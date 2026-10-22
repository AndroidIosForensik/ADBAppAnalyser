#!/usr/bin/env bash
# Installiert den Test-Chat-Relay als systemd-Dienst (Debian/Ubuntu, ohne Docker).
#
#   sudo ./install.sh --ip <IPv4> [--port 8443] [--ufw]
#
# Erzeugt Systembenutzer, venv, selbstsigniertes EC-Zertifikat (SAN IP:<ip>) und
# einen zufaelligen Token. Gibt am Ende serverUrl, SPKI-Pin, Token und das
# Zertifikat (PEM) aus - diese Werte kommen in die App-Konfiguration.
set -euo pipefail

PORT=8443
IP=""
OPEN_UFW=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --ufw) OPEN_UFW=1; shift;;
    *) echo "Unbekanntes Argument: $1" >&2; exit 2;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then echo "Bitte mit sudo/root ausfuehren." >&2; exit 1; fi
if ! echo "$IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "Bitte gueltige --ip <IPv4> angeben." >&2; exit 2
fi

APP_USER=testchat
APP_DIR=/opt/testchat-relay
CFG_DIR=/etc/testchat-relay
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== Voraussetzungen"
command -v python3 >/dev/null || { echo "python3 fehlt"; exit 1; }
command -v openssl >/dev/null || { echo "openssl fehlt"; exit 1; }
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
python3 - <<'PY' || { echo "Python >= 3.9 erforderlich"; exit 1; }
import sys; sys.exit(0 if sys.version_info[:2] >= (3,9) else 1)
PY
echo "   Python $PYV ok"

echo "== Systembenutzer $APP_USER"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

echo "== Verzeichnisse"
mkdir -p "$APP_DIR" "$CFG_DIR"
install -m 0644 "$SRC_DIR/relay_server.py" "$APP_DIR/relay_server.py"

echo "== Virtuelle Umgebung + websockets"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
# websockets-Version passend zur Python-Version waehlen (asyncio-Server ab 13).
if python3 - <<'PY'
import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)
PY
then WS_SPEC="websockets>=13"; else WS_SPEC="websockets>=13,<16"; fi
"$APP_DIR/venv/bin/pip" install --quiet "$WS_SPEC"

echo "== Zertifikat (selbstsigniert, SAN IP:$IP)"
if [ ! -f "$CFG_DIR/relay_key.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CFG_DIR/relay_key.pem" -out "$CFG_DIR/relay_cert.pem" \
    -days 825 -nodes -subj "/CN=testchat-relay" \
    -addext "subjectAltName=IP:$IP" >/dev/null 2>&1
fi

echo "== Token"
if [ ! -f "$CFG_DIR/token.txt" ]; then
  openssl rand -hex 24 > "$CFG_DIR/token.txt"
fi
TOKEN=$(cat "$CFG_DIR/token.txt")

chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$CFG_DIR"
chmod 600 "$CFG_DIR/relay_key.pem" "$CFG_DIR/token.txt"
chmod 644 "$CFG_DIR/relay_cert.pem"

echo "== systemd-Dienst"
cat > /etc/systemd/system/testchat-relay.service <<UNIT
[Unit]
Description=Test-Chat-Relay (WebSocket, TLS)
After=network-online.target
Wants=network-online.target

[Service]
User=$APP_USER
Group=$APP_USER
Environment=RELAY_CERT=$CFG_DIR/relay_cert.pem
Environment=RELAY_KEY=$CFG_DIR/relay_key.pem
Environment=RELAY_TOKEN_FILE=$CFG_DIR/token.txt
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/relay_server.py --host 0.0.0.0 --port $PORT
Restart=on-failure
RestartSec=2
# Haertung
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadOnlyPaths=$CFG_DIR
CapabilityBoundingSet=
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now testchat-relay.service

if [ "$OPEN_UFW" -eq 1 ] && command -v ufw >/dev/null; then
  echo "== Firewall (ufw) oeffnet Port $PORT"
  ufw allow "$PORT/tcp" || true
fi

PIN=$(openssl x509 -in "$CFG_DIR/relay_cert.pem" -pubkey -noout \
  | openssl pkey -pubin -outform der 2>/dev/null \
  | openssl dgst -sha256 -binary | openssl enc -base64)

echo
echo "======================================================================"
echo " Relay laeuft. Werte fuer die App-Konfiguration (chat.properties):"
echo "----------------------------------------------------------------------"
echo " serverUrl = wss://$IP:$PORT"
echo " pin       = sha256/$PIN"
echo " token     = $TOKEN"
echo "----------------------------------------------------------------------"
echo " Zertifikat (nach testapp/app/src/main/res/raw/relay_cert.pem kopieren):"
echo "----------------------------------------------------------------------"
cat "$CFG_DIR/relay_cert.pem"
echo "======================================================================"
if [ "$OPEN_UFW" -ne 1 ]; then
  echo "Hinweis: Firewall nicht veraendert. Port $PORT/tcp muss erreichbar sein."
fi
echo "Status:   systemctl status testchat-relay"
echo "Logs:     journalctl -u testchat-relay -f   (ohne Nachrichteninhalte)"
