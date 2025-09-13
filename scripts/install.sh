#!/usr/bin/env bash
set -euo pipefail

REPO=""; VER="latest"; TAK_ADDR=""; UDP_PORT=5010; PSK=""; STALE=120; COT_TYPE="a-f-G-U-C"; HOW="m-g"
CA_FILE=""; CERT_FILE=""; KEY_FILE=""
CA_B64=""; CERT_B64=""; KEY_B64=""
SERVICE_USER="cot"
ENV_FILE="/etc/default/cot-translator"
INSTALL_DIR="/opt/cot"
BIN_PATH="${INSTALL_DIR}/cot-translator"
UNIT_FILE="/etc/systemd/system/cot-translator.service"

log(){ echo "[install] $*"; }
die(){ echo "[install] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--repo) REPO="$2"; shift 2;;
    -v|--version) VER="$2"; shift 2;;
    -tak|--tak-addr) TAK_ADDR="$2"; shift 2;;
    -udp|--udp-port) UDP_PORT="$2"; shift 2;;
    -psk|--psk) PSK="$2"; shift 2;;
    -stale|--stale-secs) STALE="$2"; shift 2;;
    -type|--cot-type) COT_TYPE="$2"; shift 2;;
    -how|--cot-how) HOW="$2"; shift 2;;
    -ca|--ca-file) CA_FILE="$2"; shift 2;;
    -cert|--cert-file) CERT_FILE="$2"; shift 2;;
    -key|--key-file) KEY_FILE="$2"; shift 2;;
    -ca-b64) CA_B64="$2"; shift 2;;
    -cert-b64) CERT_B64="$2"; shift 2;;
    -key-b64) KEY_B64="$2"; shift 2;;
    -h|--help)
      cat <<EOF
CoT Translator installer
Required:
  -r, --repo        <user/repo>   (e.g., youruser/cot-translator)
Recommended:
  -v, --version     <tag|latest>  (default: latest)
  -tak, --tak-addr  <host:port>   TAK TLS Input (e.g., tak.example.org:8089)
Optional:
  -udp, --udp-port  <port>        UDP ingest (default: 5010)
  -psk, --psk       <string>      Optional payload prefix filter
  -stale, --stale-secs <secs>     CoT stale (default: 120)
  -type, --cot-type <str>         CoT type (default: a-f-G-U-C)
  -how,  --cot-how  <str>         CoT how (default: m-g)
TLS certs:
  -ca,   --ca-file  <path>        Copy CA PEM from file
  -cert, --cert-file <path>       Copy client cert PEM
  -key,  --key-file  <path>       Copy client key PEM
  -ca-b64   <BASE64>              Write CA PEM from base64
  -cert-b64 <BASE64>              Write cert PEM from base64
  -key-b64  <BASE64>              Write key PEM from base64
EOF
      exit 0;;
    *) die "Unknown arg: $1";;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root (use sudo)."
[[ -n "$REPO" ]] || die "--repo is required (e.g., -r youruser/cot-translator)"

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ARCH="amd64";;
  aarch64|arm64) ARCH="arm64";;
  *) die "Unsupported arch: $arch (need amd64 or arm64)";;
esac

if [[ "$VER" == "latest" ]]; then
  log "Resolving latest release tag…"
  VER="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')" || true
  [[ -n "$VER" ]] || die "Could not resolve latest tag; pass -v <tag>"
fi
log "Using ${REPO}@${VER} for ${ARCH}"

log "Creating ${INSTALL_DIR} and user ${SERVICE_USER}…"
mkdir -p "$INSTALL_DIR"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$SERVICE_USER"

BIN_NAME="cot-translator_linux_${ARCH}"
DL_URL="https://github.com/${REPO}/releases/download/${VER}/${BIN_NAME}"
log "Downloading binary: $DL_URL"
curl -fsSL -o "${BIN_PATH}" "$DL_URL" || die "Download failed"
chmod +x "${BIN_PATH}"
chown "$SERVICE_USER":"$SERVICE_USER" "${BIN_PATH}"

# Write certs if provided
write_if_b64(){ [[ -z "$1" ]] && return 0; printf "%s" "$1" | base64 -d > "$2"; chmod 0400 "$2"; chown "$SERVICE_USER":"$SERVICE_USER" "$2"; }
copy_if_file(){ [[ -z "$1" ]] && return 0; cp "$1" "$2"; chmod 0400 "$2"; chown "$SERVICE_USER":"$SERVICE_USER" "$2"; }

write_if_b64 "$CA_B64"   "${INSTALL_DIR}/ca.pem"
write_if_b64 "$CERT_B64" "${INSTALL_DIR}/translator.pem"
write_if_b64 "$KEY_B64"  "${INSTALL_DIR}/translator.key"
copy_if_file  "$CA_FILE"   "${INSTALL_DIR}/ca.pem"
copy_if_file  "$CERT_FILE" "${INSTALL_DIR}/translator.pem"
copy_if_file  "$KEY_FILE"  "${INSTALL_DIR}/translator.key"

# Env file
log "Writing /etc/default/cot-translator…"
cat > "/etc/default/cot-translator" <<EOF
IN_UDP_PORT=${UDP_PORT}
IN_PSK=${PSK}
COT_TYPE=${COT_TYPE}
STALE_SECS=${STALE}
COT_HOW=${HOW}
OUT_TAK_TLS_ENABLE=true
TAK_TLS_ADDR=${TAK_ADDR}
TAK_CA_CERT=${INSTALL_DIR}/ca.pem
TAK_CLIENT_CERT=${INSTALL_DIR}/translator.pem
TAK_CLIENT_KEY=${INSTALL_DIR}/translator.key
TAK_TLS_INSECURE=false
EOF
chmod 0644 "/etc/default/cot-translator"

# systemd unit
log "Installing systemd unit…"
cat > "$UNIT_FILE" <<'EOF'
[Unit]
Description=CoT Translator (GPGGA UDP -> CoT -> TAK TLS)
After=network-online.target
Wants=network-online.target
[Service]
User=cot
Group=cot
WorkingDirectory=/opt/cot
EnvironmentFile=-/etc/default/cot-translator
ExecStart=/opt/cot/cot-translator
Restart=always
RestartSec=1
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
MemoryMax=150M
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

if [[ -n "$TAK_ADDR" ]]; then
  log "Enabling & starting service…"
  systemctl enable --now cot-translator
  systemctl --no-pager status cot-translator || true
  log "Follow logs:  journalctl -u cot-translator -f"
else
  log "Installed. Set TAK_TLS_ADDR in /etc/default/cot-translator, then: systemctl enable --now cot-translator"
fi

log "Done."
