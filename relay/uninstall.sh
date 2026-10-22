#!/usr/bin/env bash
# Entfernt den Test-Chat-Relay-Dienst wieder.
#   sudo ./uninstall.sh [--purge]
# --purge loescht zusaetzlich Zertifikat und Token in /etc/testchat-relay.
set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if [ "$(id -u)" -ne 0 ]; then echo "Bitte mit sudo/root ausfuehren." >&2; exit 1; fi

systemctl disable --now testchat-relay.service 2>/dev/null || true
rm -f /etc/systemd/system/testchat-relay.service
systemctl daemon-reload
rm -rf /opt/testchat-relay

if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/testchat-relay
  echo "Zertifikat und Token entfernt."
else
  echo "Zertifikat/Token in /etc/testchat-relay bleiben erhalten (--purge zum Loeschen)."
fi

if id -u testchat >/dev/null 2>&1; then
  userdel testchat 2>/dev/null || true
fi
echo "Relay entfernt."
