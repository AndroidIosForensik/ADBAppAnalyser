# ADB App Analyse

Findet auf einem Android-Gerät **versteckte oder selbst gebaute Chat-Apps**. Das
Tool liest per ADB alle installierten Apps aus, sichert und analysiert ihre APKs
statisch, gleicht sie mit Google Play, F-Droid und einer Stalkerware-Liste ab und
erstellt am Ende eine **Prüfliste**: Apps, die man auf jeden Fall gegenchecken
sollte – jeweils mit nachvollziehbaren Gründen und Belegen.

Die Datensammlung ist **rein lesend**: kein Root, keine Berechtigungsvergabe,
keine Änderung von Geräteeinstellungen.

## Bestandteile

| Pfad | Inhalt |
|------|--------|
| `src/appanalyse/` | Das Analyse-Tool (Python-CLI `appanalyse`). |
| `AppAnalyse starten.cmd` / `… offline starten.cmd` | Geführter Ablauf für Windows (fragt Gerät + Online/Offline, öffnet den Bericht). |
| `packaging/` | Build der eigenständigen `appanalyse.exe` (PyInstaller) + Release-Starter. |
| `tests/` | Automatische Tests (Parser, APK, Bewertung, Abgleich). |

## Windows-Release (ohne Python)

Fertige `appanalyse.exe` unter
**[Releases](https://github.com/AndroidIosForensik/ADBAppAnalyser/releases)** —
herunterladen, entpacken, `Scan starten.cmd` ausführen. Es werden nur die
**Android Platform Tools (`adb`)** zusätzlich benötigt (nicht enthalten).

## Analyse-Tool `appanalyse` (aus dem Quellcode)

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
- `--all-apks` – auch System-Apps sichern.
- Alle gesicherten APKs bleiben erhalten. `--keep-all-apks` wird aus Kompatibilitätsgründen weiter akzeptiert.
- `--vt-key <KEY>` – VirusTotal-Abgleich (nur Hashes, nur für Kandidaten).

### Was das Tool auswertet

- **Herkunft:** Installer, `packageSource`, Store-Abgleich (Play/F-Droid),
  Signaturzertifikat (Debug-/selbstsigniert), Paketname.
- **Hinweise auf Nachrichten-/Netzwerkfunktionen:** Bibliotheken (OkHttp-WS, MQTT, XMPP, Socket.IO,
  Firebase, Matrix, libsignal …), Protokollmerkmale
  (z. B. die WebSocket-GUID), Foreground-Dienst `remoteMessaging`, Server-Endpunkte,
  Chat-Begriffe, Zertifikats-Pinning.
- **Verschleierung:** Tarnname (Rechner, Notizen …), deaktivierter/fehlender
  Launcher, nur in Zweitprofil, `excludeFromRecents`, Packer/Obfuskierung.
- **Sonderzugriffe:** Bedienungshilfe, Benachrichtigungszugriff, Geräteadmin, Rollen.
- **Aktivität:** Datenverkehr, letzte Nutzung, Benachrichtigungen, laufende Dienste.

Jede App wird eingestuft als **Unbedingt prüfen**, **Prüfen empfohlen**,
**Bekannter Messenger** (bei Sideload mit Hinweis „Echtheit prüfen“) oder
**Unauffällig**. Ohne APK-Analyse oder bei Analysefehlern lautet das Ergebnis
ohne stärkere Befunde **Nicht abschließend beurteilbar**. Vorhandene Prüfbefunde
bleiben auch bei Teilfehlern sichtbar. Bekannte modifizierte Klone (z. B. GBWhatsApp) und
IOC-Treffer sind immer „Unbedingt prüfen“.

Installer, Systemstatus und Signatur-Kurzwerte unterdrücken keine Prüfung
zusätzlicher Funktionen. Ein Rechnername zusammen mit Internetzugriff allein
ergibt keine Tarnungspunkte. Statische Treffer sind Hinweise für die Prüfung;
der tatsächliche Chat muss anhand des Aufrufpfads, Daten oder eines Tests belegt werden.

### Ausgabe

`ausgabe/<Zeitstempel>_<Seriennr>/` enthält:

- `bericht.html` – eigenständiger Offline-Bericht (Suche, Filter, Hell/Dunkel).
- `pruefliste.csv`, `befunde.csv`, `berechtigungen.csv`, `tabellen/apps.csv`.
- `ergebnis.json` – vollständiges Ergebnis maschinenlesbar.
- `rohdaten/` + `befehle.json` – unveränderte ADB-Ausgaben und exakte Aufrufe.
- `apks/` – alle gesicherten APKs, unabhängig von der Bewertung (z. B. für jadx).

## Tests

```bash
.venv\Scripts\pytest
```

## Grenzen

- Play-404 kann „regional gesperrt/entfernt“ bedeuten; F-Droid kennt nur FOSS;
  „bei VirusTotal unbekannt“ heißt nur „selten“.
- Heuristiken lassen sich umgehen (Packer, Code-Nachladen). Der Bericht ist eine
  **Vorauswahl, kein Beweis**.
- Beim Online-Abgleich gehen Paketnamen an Google und F-Droid; für sensible Fälle
  `--offline` verwenden.
- Es gibt keine öffentliche „Datenbank aller Apps“; der Abgleich kombiniert
  mehrere Quellen.
