# ADB App Analyse

Findet auf einem Android-Gerät **versteckte oder selbst gebaute Chat-Apps**. Das
Tool liest per ADB alle installierten Apps aus, sichert und analysiert ihre APKs
statisch, gleicht sie mit Google Play, F-Droid und einer Stalkerware-Liste ab und
erstellt am Ende eine **Prüfliste**: Apps, die man auf jeden Fall gegenchecken
sollte – jeweils mit nachvollziehbaren Gründen und Belegen.

Die Datensammlung ist **rein lesend**: kein Root, keine Berechtigungsvergabe,
keine Änderung von Geräteeinstellungen.

## Bestandteile

| Ordner     | Inhalt |
|------------|--------|
| `src/appanalyse/` | Das Analyse-Tool (Python-CLI `appanalyse`). |
| `relay/`   | Kleiner TLS-WebSocket-Relay-Server + PC-Client für die Test-Umgebung. |
| `testapp/` | Getarnte Test-Chat-App „Rechner“ (Kotlin/Compose), die das Tool findet. |
| `tests/`   | Automatische Tests (Parser, APK, Bewertung, Abgleich, Relay-E2E). |

## Analyse-Tool `appanalyse`

### Installation

```bash
python -m venv .venv
.venv\Scripts\pip install -e .
```

Voraussetzungen: aktuelle Android Platform Tools (`adb` im PATH), USB-Debugging
aktiv, Gerät entsperrt und der RSA-Dialog bestätigt.

### Benutzung

```bash
appanalyse devices                 # angeschlossene Geräte auflisten
appanalyse scan -s <Seriennummer>  # Gerät scannen (rein lesend) und Bericht erzeugen
appanalyse apk pfad/zur.apk        # eine einzelne APK offline analysieren
appanalyse update-lists            # Stalkerware-IOC-Liste aktualisieren
```

Wichtige Schalter für `scan`:

- `--offline` – keinerlei Online-Abfragen (für sensible Ermittlungen).
- `--no-apk` – keine APKs sichern/analysieren (nur ADB-Metadaten).
- `--all-apks` / `--keep-all-apks` – auch System-Apps sichern bzw. alle behalten.
- `--vt-key <KEY>` – VirusTotal-Abgleich (nur Hashes, nur für Kandidaten).

### Was das Tool auswertet

- **Herkunft:** Installer, `packageSource`, Store-Abgleich (Play/F-Droid),
  Signaturzertifikat (Debug-/selbstsigniert), Paketname.
- **Chat-Funktion:** Echtzeit-/Chat-Bibliotheken (OkHttp-WS, MQTT, XMPP, Socket.IO,
  Firebase, Matrix, libsignal …), **obfuskierungsfeste Protokoll-Signaturen**
  (z. B. die WebSocket-GUID), Foreground-Dienst `remoteMessaging`, Server-Endpunkte,
  Chat-Begriffe, Zertifikats-Pinning.
- **Verschleierung:** Tarnname (Rechner, Notizen …), deaktivierter/fehlender
  Launcher, nur in Zweitprofil, `excludeFromRecents`, Packer/Obfuskierung.
- **Sonderzugriffe:** Bedienungshilfe, Benachrichtigungszugriff, Geräteadmin, Rollen.
- **Aktivität:** Datenverkehr, letzte Nutzung, Benachrichtigungen, laufende Dienste.

Jede App wird eingestuft als **Unbedingt prüfen**, **Prüfen empfohlen**,
**Bekannter Messenger** (bei Sideload mit Hinweis „Echtheit prüfen“) oder
**Unauffällig**. Bekannte modifizierte Klone (z. B. GBWhatsApp) und
IOC-Treffer sind immer „Unbedingt prüfen“.

### Ausgabe

`ausgabe/<Zeitstempel>_<Seriennr>/` enthält:

- `bericht.html` – eigenständiger Offline-Bericht (Suche, Filter, Hell/Dunkel).
- `pruefliste.csv`, `befunde.csv`, `berechtigungen.csv`, `tabellen/apps.csv`.
- `ergebnis.json` – vollständiges Ergebnis maschinenlesbar.
- `rohdaten/` + `befehle.json` – unveränderte ADB-Ausgaben und exakte Aufrufe.
- `apks/` – gesicherte APKs der Prüfliste (Beweismittel für z. B. jadx).

## Test-Umgebung

Um die Erkennung realistisch zu prüfen, gibt es eine getarnte Chat-App und einen
Relay-Server. Zwei Geräte unterhalten sich über den eigenen Server; das Tool soll
die App als „Unbedingt prüfen“ erkennen. Details:

- **Server:** siehe [`relay/README.md`](relay/README.md) – `install.sh` richtet den
  gehärteten systemd-Dienst mit selbstsigniertem Zertifikat und Token ein.
- **App:** siehe [`testapp/`](testapp/) – `build.cmd` baut Debug- und
  R8-obfuskierte Release-Variante. Die App zeigt einen echten Taschenrechner; ein
  Ziffern-Code + „=“ öffnet den versteckten Chat.

Kurzablauf:

1. `relay/` auf den Server kopieren, `sudo ./install.sh --ip <IPv4>` ausführen.
2. Die ausgegebenen Werte in `testapp/app/chat.properties` eintragen und das
   Zertifikat nach `testapp/app/src/main/res/raw/relay_cert.pem` kopieren.
3. `cd testapp && build.cmd`, die APK auf zwei Geräte installieren, chatten.
4. `appanalyse scan` auf beiden Geräten – die App erscheint unter „Unbedingt prüfen“.

## Tests

```bash
.venv\Scripts\pytest
```

## Grenzen

- Ohne Root nur Metadaten und APK lesbar, **keine App-Inhalte oder Nachrichten**.
- Play-404 kann „regional gesperrt/entfernt“ bedeuten; F-Droid kennt nur FOSS;
  „bei VirusTotal unbekannt“ heißt nur „selten“.
- Heuristiken lassen sich umgehen (Packer, Code-Nachladen). Der Bericht ist eine
  **Vorauswahl, kein Beweis**.
- Beim Online-Abgleich gehen Paketnamen an Google und F-Droid; für sensible Fälle
  `--offline` verwenden.
- Es gibt keine öffentliche „Datenbank aller Apps“; der Abgleich kombiniert
  mehrere Quellen. (AndroZoo wäre eine Erweiterung, braucht aber Forschungszugang.)
