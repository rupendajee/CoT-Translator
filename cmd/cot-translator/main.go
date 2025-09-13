package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	InUDPPort       int
	PSK             string // optional payload prefix/secret; empty = disabled

	// CoT
	CotType   string
	StaleSecs int
	How       string

	// Output toggles
	EnableTLSClient bool
	EnableTCPServer bool
	EnableUDPPub    bool

	// TLS client (to TAK Input)
	TlsAddr       string
	ClientCertPem string
	ClientKeyPem  string
	CACertPem     string
	TLSInsecure   bool

	// TCP server (for TAK SDF to connect; optional)
	TCPListen string

	// UDP publisher (for TAK SDF to subscribe; optional)
	OutUDPAddr string
	OutUDPPort int
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv(key))); v != "" {
		return v == "1" || v == "true" || v == "yes" || v == "on"
	}
	return def
}

func defaultStr(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func loadConfig() Config {
	return Config{
		InUDPPort: envInt("IN_UDP_PORT", 5010),
		PSK:       os.Getenv("IN_PSK"),

		CotType:   defaultStr(os.Getenv("COT_TYPE"), "a-f-G-U-C"),
		StaleSecs: envInt("STALE_SECS", 120),
		How:       defaultStr(os.Getenv("COT_HOW"), "m-g"),

		EnableTLSClient: envBool("OUT_TAK_TLS_ENABLE", false),
		EnableTCPServer: envBool("OUT_TCP_SERVER_ENABLE", true),
		EnableUDPPub:    envBool("OUT_UDP_ENABLE", false),

		TlsAddr:       os.Getenv("TAK_TLS_ADDR"),    // host:port
		ClientCertPem: os.Getenv("TAK_CLIENT_CERT"), // path
		ClientKeyPem:  os.Getenv("TAK_CLIENT_KEY"),  // path
		CACertPem:     os.Getenv("TAK_CA_CERT"),     // path
		TLSInsecure:   envBool("TAK_TLS_INSECURE", false),

		TCPListen: defaultStr(os.Getenv("TCP_LISTEN"), ":8087"),

		OutUDPAddr: defaultStr(os.Getenv("OUT_UDP_ADDR"), "239.5.0.1"),
		OutUDPPort: envInt("OUT_UDP_PORT", 6969),
	}
}

// ------------ NMEA (GPGGA) parsing & helpers ------------

type Fix struct {
	DeviceID string
	Lat      float64
	Lon      float64
	HAE      float64 // meters (HAE)
	Time     time.Time
	Valid    bool
}

func parseGPGGA(line string) (Fix, error) {
	orig := strings.TrimSpace(line)
	if !strings.HasPrefix(orig, "$GPGGA") {
		return Fix{}, fmt.Errorf("not GPGGA")
	}
	// Split checksum
	body := orig
	if i := strings.Index(orig, "*"); i > 0 {
		body = orig[:i]
		// checksum is ignored or warned elsewhere if desired
	}

	parts := strings.Split(body, ",")
	// Expected fields per NMEA GGA:
	// 0:$GPGGA 1:utc 2:lat 3:N/S 4:lon 5:E/W 6:fix 7:sats 8:hdop 9:alt 10:M 11:geoid 12:M 13:age 14:stationID(DEVICEID)
	if len(parts) < 6 {
		return Fix{}, fmt.Errorf("too few fields")
	}

	lat := parseLat(parts, 2, 3)
	lon := parseLon(parts, 4, 5)

	alt := 0.0
	if len(parts) > 9 && parts[9] != "" {
		if v, err := strconv.ParseFloat(parts[9], 64); err == nil {
			alt = v
		}
	}

	deviceID := ""
	if len(parts) >= 15 {
		deviceID = strings.TrimSpace(parts[14])
	}
	// Fallback: if last field is empty but there are 15 fields, try previous non-empty tail
	if deviceID == "" {
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.TrimSpace(parts[i]) != "" && !strings.HasPrefix(parts[i], "$GPGGA") {
				deviceID = strings.TrimSpace(parts[i])
				break
			}
		}
	}

	fixValid := false
	if len(parts) > 6 && parts[6] != "" {
		fixValid = parts[6] != "0"
	}

	return Fix{
		DeviceID: deviceID,
		Lat:      lat,
		Lon:      lon,
		HAE:      alt,
		Time:     time.Now().UTC(),
		Valid:    fixValid,
	}, nil
}

func parseLat(parts []string, iVal, iHem int) float64 {
	if len(parts) <= iVal || len(parts) <= iHem {
		return 0
	}
	s := parts[iVal]
	if s == "" {
		return 0
	}
	val, err := strconv.ParseFloat(s, 64)
	if err != nil || val == 0 {
		return 0
	}
	deg := math.Floor(val / 100)
	mins := val - (deg * 100)
	out := deg + mins/60.0
	if strings.ToUpper(parts[iHem]) == "S" {
		out = -out
	}
	return out
}

func parseLon(parts []string, iVal, iHem int) float64 {
	if len(parts) <= iVal || len(parts) <= iHem {
		return 0
	}
	s := parts[iVal]
	if s == "" {
		return 0
	}
	val, err := strconv.ParseFloat(s, 64)
	if err != nil || val == 0 {
		return 0
	}
	deg := math.Floor(val / 100)
	mins := val - (deg * 100)
	out := deg + mins/60.0
	if strings.ToUpper(parts[iHem]) == "W" {
		out = -out
	}
	return out
}

// ------------ Speed & course tracking ------------

type lastState struct {
	Lat  float64
	Lon  float64
	Time time.Time
}

type tracker struct {
	mu   sync.Mutex
	prev map[string]lastState
}

func newTracker() *tracker {
	return &tracker{prev: make(map[string]lastState)}
}

func (t *tracker) speedCourse(f Fix) (speedMS float64, courseDeg float64, have bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.prev[f.DeviceID]
	t.prev[f.DeviceID] = lastState{Lat: f.Lat, Lon: f.Lon, Time: f.Time}
	if !ok {
		return 0, 0, false
	}
	dm := haversineMeters(prev.Lat, prev.Lon, f.Lat, f.Lon)
	dt := f.Time.Sub(prev.Time).Seconds()
	if dt <= 0 {
		return 0, 0, false
	}
	speed := dm / dt
	course := bearing(prev.Lat, prev.Lon, f.Lat, f.Lon)
	return speed, course, true
}

func haversineMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000.0
	rad := math.Pi / 180.0
	dlat := (lat2 - lat1) * rad
	dlon := (lon2 - lon1) * rad
	a := math.Sin(dlat/2)*math.Sin(dlat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

func bearing(lat1, lon1, lat2, lon2 float64) float64 {
	rad := math.Pi / 180.0
	φ1 := lat1 * rad
	φ2 := lat2 * rad
	Δλ := (lon2 - lon1) * rad
	y := math.Sin(Δλ) * math.Cos(φ2)
	x := math.Cos(φ1)*math.Sin(φ2) - math.Sin(φ1)*math.Cos(φ2)*math.Cos(Δλ)
	brng := math.Atan2(y, x) * (180.0 / math.Pi)
	if brng < 0 {
		brng += 360
	}
	return brng
}

// ------------ CoT builder ------------

func buildCoT(cfg Config, f Fix, speedMS, courseDeg float64) []byte {
	now := f.Time.UTC()
	stale := now.Add(time.Duration(cfg.StaleSecs) * time.Second)
	uid := xmlEscape(nonEmpty(f.DeviceID, fmt.Sprintf("device-%d", time.Now().UnixNano())))
	callsign := uid

	var trackAttrs string
	if speedMS > 0 {
		trackAttrs += fmt.Sprintf(` speed="%.2f"`, speedMS)
	}
	if !math.IsNaN(courseDeg) && courseDeg > 0 {
		trackAttrs += fmt.Sprintf(` course="%.1f"`, courseDeg)
	}

	xml := fmt.Sprintf(
		`<event version="2.0" type="%s" uid="%s" time="%s" start="%s" stale="%s" how="%s">`+
			`<point lat="%.7f" lon="%.7f" hae="%.2f" ce="9999999.0" le="9999999.0"/>`+
			`<detail><contact callsign="%s"/><track%s/></detail>`+
			`</event>`,
		xmlEscape(cfg.CotType), uid,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), stale.Format(time.RFC3339Nano),
		xmlEscape(cfg.How),
		f.Lat, f.Lon, f.HAE,
		xmlEscape(callsign), trackAttrs,
	)
	return []byte(xml + "\n")
}

func nonEmpty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// ------------ Outputs ------------

type output interface {
	Send([]byte)
	Close() error
}

// UDP publisher (unicast or multicast)
type udpOut struct {
	addr *net.UDPAddr
	conn *net.UDPConn
	mu   sync.Mutex
}

func newUDPOut(addr string, port int) (*udpOut, error) {
	a, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, a)
	if err != nil {
		return nil, err
	}
	return &udpOut{addr: a, conn: conn}, nil
}
func (o *udpOut) Send(b []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = o.conn.Write(b)
}
func (o *udpOut) Close() error { return o.conn.Close() }

// TCP server (multiple TAK connections)
type tcpServerOut struct {
	listen string
	ln     net.Listener

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newTCPServerOut(listen string) (*tcpServerOut, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	o := &tcpServerOut{listen: listen, ln: ln, conns: make(map[net.Conn]struct{})}
	go o.acceptLoop()
	return o, nil
}
func (o *tcpServerOut) acceptLoop() {
	log.Printf("[out tcp] listening on %s", o.listen)
	for {
		c, err := o.ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			log.Printf("[out tcp] accept error: %v", err)
			return
		}
		o.mu.Lock()
		o.conns[c] = struct{}{}
		o.mu.Unlock()
		go o.serve(c)
	}
}
func (o *tcpServerOut) serve(c net.Conn) {
	defer func() {
		o.mu.Lock()
		delete(o.conns, c)
		o.mu.Unlock()
		_ = c.Close()
	}()
	reader := bufio.NewReader(c)
	for {
		// just keep connection alive; discard
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		if _, err := reader.ReadByte(); err != nil {
			if err != io.EOF {
				log.Printf("[out tcp] conn closed: %v", err)
			}
			return
		}
	}
}
func (o *tcpServerOut) Send(b []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for c := range o.conns {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(b); err != nil {
			_ = c.Close()
			delete(o.conns, c)
		}
	}
}
func (o *tcpServerOut) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for c := range o.conns {
		_ = c.Close()
	}
	if o.ln != nil {
		return o.ln.Close()
	}
	return nil
}

// TLS client → TAK Input
type tlsClientOut struct {
	addr      string
	tlsConfig *tls.Config

	mu   sync.Mutex
	conn *tls.Conn
}

func newTLSClientOut(addr, caPath, certPath, keyPath string, insecure bool) (*tlsClientOut, error) {
	cfg := &tls.Config{InsecureSkipVerify: insecure} // (set false in prod)
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		cp := x509.NewCertPool()
		cp.AppendCertsFromPEM(caPEM)
		cfg.RootCAs = cp
	}
	if certPath != "" && keyPath != "" {
		crt, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{crt}
	}
	o := &tlsClientOut{addr: addr, tlsConfig: cfg}
	go o.connectLoop()
	return o, nil
}
func (o *tlsClientOut) connectLoop() {
	for {
		conn, err := tls.Dial("tcp", o.addr, o.tlsConfig)
		if err != nil {
			log.Printf("[out tls] dial failed: %v (retrying)", err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("[out tls] connected %s", o.addr)
		o.mu.Lock()
		o.conn = conn
		o.mu.Unlock()

		// Keepalive: wait until remote closes
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		_, err = conn.Read(buf)
		log.Printf("[out tls] conn closed: %v", err)

		o.mu.Lock()
		_ = o.conn.Close()
		o.conn = nil
		o.mu.Unlock()

		time.Sleep(1 * time.Second)
	}
}
func (o *tlsClientOut) Send(b []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn == nil {
		return
	}
	_ = o.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := o.conn.Write(b); err != nil {
		log.Printf("[out tls] write error: %v", err)
		_ = o.conn.Close()
		o.conn = nil
	}
}
func (o *tlsClientOut) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn != nil {
		return o.conn.Close()
	}
	return nil
}

// ------------ Main pipeline ------------

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg := loadConfig()
	log.Printf("[boot] CoT Translator starting. UDP in :%d  TLS:%v TCP:%v UDPout:%v",
		cfg.InUDPPort, cfg.EnableTLSClient, cfg.EnableTCPServer, cfg.EnableUDPPub)

	// Build outputs
	outs := []output{}
	if cfg.EnableUDPPub {
		u, err := newUDPOut(cfg.OutUDPAddr, cfg.OutUDPPort)
		if err != nil {
			log.Fatalf("udp out: %v", err)
		}
		outs = append(outs, u)
	}
	if cfg.EnableTCPServer {
		t, err := newTCPServerOut(cfg.TCPListen)
		if err != nil {
			log.Fatalf("tcp server out: %v", err)
		}
		outs = append(outs, t)
	}
	if cfg.EnableTLSClient {
		if cfg.TlsAddr == "" {
			log.Fatalf("OUT_TAK_TLS_ENABLE=1 but TAK_TLS_ADDR unset")
		}
		tlsOut, err := newTLSClientOut(cfg.TlsAddr, cfg.CACertPem, cfg.ClientCertPem, cfg.ClientKeyPem, cfg.TLSInsecure)
		if err != nil {
			log.Fatalf("tls out: %v", err)
		}
		outs = append(outs, tlsOut)
	}

	incoming := make(chan string, 1024)
	trk := newTracker()

	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", cfg.InUDPPort))
	if err != nil {
		log.Fatalf("udp resolve: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("udp listen: %v", err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("[in udp] read error: %v", err)
				continue
			}
			line := strings.TrimSpace(string(buf[:n]))
			if cfg.PSK != "" && !strings.HasPrefix(line, cfg.PSK) {
				continue // drop non-matching
			}
			if cfg.PSK != "" {
				line = strings.TrimPrefix(line, cfg.PSK)
			}
			incoming <- line
			if (time.Now().Unix()%30) == 0 {
				log.Printf("[in udp] %d bytes from %s", n, addr)
			}
		}
	}()

	// Worker
	go func() {
		for line := range incoming {
			fix, err := parseGPGGA(line)
			if err != nil || !fix.Valid || fix.DeviceID == "" || fix.Lat == 0 || fix.Lon == 0 {
				continue
			}
			speed, course, _ := trk.speedCourse(fix)
			xml := buildCoT(cfg, fix, speed, course)
			for _, o := range outs {
				o.Send(xml)
			}
		}
	}()

	// Health log
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			log.Printf("[health] running; outs=%d", len(outs))
		}
	}()

	// Shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	for _, o := range outs {
		_ = o.Close()
	}
	log.Printf("[exit] bye")
}
