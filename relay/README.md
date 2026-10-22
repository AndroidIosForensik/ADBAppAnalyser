# Test-Chat-Relay

Kleiner TLS-WebSocket-Relay, damit sich zwei Android-Geräte (die getarnte
Test-App „Rechner“) über deinen Server mit fester IPv4 unterhalten können:
**Gerät → Server → Gerät**. Nur für Test-Geräte/-Server, die du selbst
kontrollierst.

## Eigenschaften

- WSS (TLS) mit selbstsigniertem EC-Zertifikat, in der App gepinnt (SPKI-SHA256).
- Zugangstoken (konstantzeitiger Vergleich), Nutzernamen `[A-Za-z0-9_-]{1,32}`.
- Grenzen: 16 KB je Nachricht, Ratenlimit, max. 100 Verbindungen.
- Offline-Empfänger: kurze Pufferung nur im RAM (TTL 24 h, max. 200).
- **Keine Speicherung auf Platte, keine Nachrichteninhalte im Log** (journald
  erhält nur Metadaten: verbunden/getrennt).

## Installation (Debian/Ubuntu, ohne Docker)

`relay/` auf den Server kopieren und dort:

```bash
sudo ./install.sh --ip <DEINE_IPV4> --port 8443
```

Das Skript legt Systembenutzer `testchat`, ein venv unter `/opt/testchat-relay`,
Zertifikat und Token unter `/etc/testchat-relay` an und richtet den
systemd-Dienst `testchat-relay` (gehärtet) ein. Am Ende gibt es **serverUrl**,
**pin**, **token** und das **Zertifikat (PEM)** aus – diese Werte kommen in die
App-Konfiguration (`testapp/app/src/main/assets/chat.properties` bzw.
`res/raw/relay_cert.pem`).

Die Firewall wird nicht verändert. Port `8443/tcp` muss erreichbar sein
(`--ufw` öffnet ihn per ufw, falls vorhanden).

Verwaltung:

```bash
systemctl status testchat-relay
journalctl -u testchat-relay -f
sudo ./uninstall.sh            # Dienst entfernen (Zertifikat bleibt)
sudo ./uninstall.sh --purge    # auch Zertifikat/Token löschen
```

## Ohne Handy testen

Den PC-Client (zwei Terminals, je ein Nutzer) verwenden:

```bash
python chat_client.py --url wss://<IP>:8443 --user alice --token <TOKEN> --cafile relay_cert.pem
python chat_client.py --url wss://<IP>:8443 --user bob   --token <TOKEN> --cafile relay_cert.pem
```

Im Terminal `alice` dann z. B. `bob Hallo` eingeben.

## Sicht des Analyse-Tools

Genau diese Merkmale soll `appanalyse` an der App erkennen: WebSocket zu einer
festen `wss://IP:Port`, gepinntes/eingebettetes Zertifikat, Foreground-Dienst
`remoteMessaging` – kombiniert mit seitlicher Installation und Tarnung.
