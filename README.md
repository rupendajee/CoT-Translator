# CoT Translator (GPGGA UDP ➜ CoT ➜ TAK TLS)

A tiny, production-minded service that listens for **GPGGA** sentences over **UDP**, extracts a **device ID** from the last field (right before the `*checksum`), converts each fix to **Cursor-on-Target (CoT)** XML, and forwards to **TAK Server** via a **TLS Input**.

- Written in Go (no external deps), ~10–15MB RAM, single static binary.
- Handles 100+ devices with ease; computes **speed (m/s)** and **course (deg)** from successive fixes.
- Reliability: buffered pipeline, auto-reconnect, systemd unit, minimal allocations.

## Ingest (expected GPGGA)
$GPGGA,hhmmss,lat,NS,lon,EW,fix,sats,hdop,alt,M,geoid,M,age,DEVICEID*CS

We use the **DEVICEID** (field 14) as the CoT `uid` and `contact@callsign`. If your device leaves that field empty, we try a simple fallback and take the last non-empty field.

> Tip: You may enforce an additional payload prefix filter (`IN_PSK="MYSECRET:"`), which requires devices to send `MYSECRET:$GPGGA,...`.

## CoT fields
- `type`: `a-f-G-U-C` (configurable)
- `uid`: `DEVICEID`
- `point.lat/lon/hae`: from GGA (`alt` is meters)
- `detail/contact@callsign`: `DEVICEID`
- `detail/track@speed`: meters/second (derived)
- `detail/track@course`: degrees (derived)
- `how`: `m-g` (configurable)
- `stale`: now + `STALE_SECS` (default 120)

## Quick start (Droplet, Option A: Direct to TAK TLS Input)

1. **Create Droplet + firewall**
   - Ubuntu 22.04, 1 vCPU / 1GB.
   - Cloud Firewall inbound:
     - UDP **5010** from your device IP ranges
     - TCP **22** from your admin IPs
   - Outbound allow to your **TAK_SERVER:PORT** (e.g., 8089).

2. **Build**
   ```bash
   sudo apt-get update && sudo apt-get install -y golang
   sudo mkdir -p /opt/cot && cd /opt/cot
   curl -L -o main.go https://raw.githubusercontent.com/<your>/cot-translator/main/cmd/cot-translator/main.go
   curl -L -o go.mod  https://raw.githubusercontent.com/<your>/cot-translator/main/go.mod
   CGO_ENABLED=0 go build -ldflags="-s -w" -o cot-translator ./cmd/cot-translator  # if building from repo, use path
   # or: CGO_ENABLED=0 go build -ldflags="-s -w" -o cot-translator
   sudo useradd -r -s /usr/sbin/nologin cot || true
   sudo chown cot:cot /opt/cot/cot-translator
