# Schulung: Versteckte Chat-Apps per ADB finden

Diese Unterlage geht in zwei Teilen vor:

- **Teil 1 — von Hand mit ADB:** Wir bauen die Analyse Schritt für Schritt selbst
  auf und verstehen, *woran* man eine versteckte/selbst gebaute Chat-App erkennt.
  Beispiel-App: die getarnte Test-App **„Rechner"** (`de.rechenhilfe.app`).
- **Teil 2 — das Skript:** Danach zeigen wir das Werkzeug `appanalyse` und
  erklären, was es zusätzlich und automatisch macht.

> Alle Befehle sind **rein lesend**. Beispielausgaben stammen von einem Emulator
> mit installierter Test-App; Seriennummer, UID und das Suffix `.debug` können
> bei euch abweichen. Die `adb shell "... | grep ..."`-Form funktioniert in
> PowerShell **und** in der Bash.

---

## Teil 1 — Von Hand mit ADB

### Schritt 0: Verbindung herstellen

Voraussetzung: am Gerät **USB-Debugging** aktiv, Kabel dran, RSA-Dialog bestätigt.

```powershell
adb devices
```
```
List of devices attached
emulator-5554   device
```

Bei mehreren Geräten hängt man `-s <Seriennummer>` an jeden Befehl.

### Schritt 1: Das Gerät kennenlernen

```powershell
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell pm list users
```

`pm list users` zeigt, ob es **Zweitprofile** gibt (Arbeitsprofil, privater
Bereich, Klon) — beliebte Verstecke. Jedes Profil hat eine eigene Nummer; mit
`--user <N>` fragt man gezielt darin ab.

### Schritt 2: Welche Apps sind installiert?

`-3` beschränkt auf **Drittanbieter-Apps** (ohne die vorinstallierten System-Apps):

```powershell
adb shell pm list packages -3
```
```
package:de.rechenhilfe.app.debug
```

> Lernpunkt: System-Apps (`-s`) sind Hunderte — für die Suche nach Eigenbauten
> interessieren vor allem die Drittanbieter-Apps.

### Schritt 3: Woher kommen die Apps? (Installer)

`-i` zeigt pro App den **Installer** (wer sie installiert hat):

```powershell
adb shell "pm list packages -3 -i"
```
```
package:de.rechenhilfe.app.debug  installer=null
```

Alles aus dem Play Store hat `installer=com.android.vending`. Diese der
Übersicht wegbilden — was übrig bleibt, ist **nicht aus dem Play Store**:

```powershell
adb shell "pm list packages -3 -i | grep -v com.android.vending"
```

`installer=null` heißt erstmal nur: *kein Store hat installiert*.

> **Praxis-Falle (wichtig!):** Bei **Xiaomi, Oppo, Samsung** usw. tauchen hier
> **sehr viele** Apps mit `installer=null` auf — Hersteller- und Partner-Apps,
> die ab Werk als „Drittanbieter"-Apps vorinstalliert sind. `installer=null`
> allein ist also **kein** Verdacht. Man braucht bessere Unterscheidungsmerkmale:

Drei Merkmale trennen *vorinstalliert* von *nachträglich aufgespielt* (ab Android 11):

```powershell
adb shell "dumpsys package <pkg> | grep -E 'initiatingPackageName=|installReason=|signatures:'"
```

- **`initiatingPackageName`** = *wer* hat die Installation ausgelöst:
  `com.android.shell` = per adb, `…packageinstaller` = aus einer APK-Datei,
  ein Store-Paket = aus dem Store. **Leer bei Vorinstallationen** — das System
  selbst hat sie eingespielt.
- **`installReason`**: `0` = unbekannt/Systemeinrichtung, `4` = vom Nutzer.
- **Signatur** (`signatures:[…]`): Hersteller-Apps sind mit **demselben
  Zertifikat wie die System-Apps** signiert. Das kann ein Dritter nicht fälschen.
  Vergleich: `adb shell "dumpsys package android | grep -m1 signatures:"` — stimmt
  der Kurzwert einer verdächtigen App damit überein, ist sie vom Hersteller.

**Faustregel:** `installer=null` **und** `initiatingPackageName=null` **und**
gleiche Signatur wie System-Apps → Hersteller-Vorinstallation (harmlos). Dagegen
`initiatingPackageName=com.android.shell` → wirklich per adb aufgespielt.

> Hinweis: Bei **älteren Geräten (vor Android 11)** fehlt `initiatingPackageName`.
> Dann lässt sich Vorinstallation und Sideload per Installer nicht sicher trennen —
> hier hilft nur die Signatur und der APK-Pfad (`/data/app/…` = nachträglich).

### Schritt 4: Eine App genauer ansehen

```powershell
adb shell "dumpsys package de.rechenhilfe.app.debug | grep -E 'versionName=|firstInstallTime=|installerPackageName=|initiatingPackageName=|packageSource=|flags=\['"
```
```
    versionName=1.0
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
    installerPackageName=null
    initiatingPackageName=com.android.shell
    packageSource=1
      firstInstallTime=2026-10-19 07:28:44
```

Darauf achten:
- `initiatingPackageName=com.android.shell` → **per `adb install` vom PC** aufgespielt.
- `flags=[ DEBUGGABLE ... ]` → ein **Entwickler-Build** (untypisch für Store-Apps).
- `firstInstallTime` → **wann** kam die App aufs Gerät? Passt das zu etwas?

### Schritt 5: Welche Rechte hat die App?

```powershell
adb shell "dumpsys package de.rechenhilfe.app.debug | grep 'granted=true'"
```
```
      android.permission.INTERNET: granted=true
      android.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING: granted=true
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
      ...
```

`INTERNET` + `FOREGROUND_SERVICE_REMOTE_MESSAGING` + `RECEIVE_BOOT_COMPLETED` ist
ein klassisches Chat-Profil: Dauerverbindung ins Netz, Neustart-fest.

### Schritt 6: Sieht man die App überhaupt? (Launcher)

Hat die App ein Symbol im App-Menü?

```powershell
adb shell "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER | grep de.rechenhilfe.app.debug"
```

Die Tarn-App **hat** hier einen Launcher (den Taschenrechner). Spannender ist die
Umkehrung — **welche Drittanbieter-App hat *keinen* Launcher** (taucht nirgends auf)?
Dieser Einzeiler vergleicht alle Drittanbieter-Apps mit der Launcher-Liste:

```powershell
adb shell 'L=$(cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER); for p in $(pm list packages -3 | cut -d: -f2); do echo "$L" | grep -q "$p/" && echo "sichtbar: $p" || echo "KEIN LAUNCHER: $p"; done'
```

Eine App mit Netzzugriff, aber **ohne Launcher**, ist hochverdächtig.

### Schritt 7: Versteckte Dienste und Autostart

```powershell
adb shell "dumpsys package de.rechenhilfe.app.debug | grep -E 'de.rechenhilfe.*(Service|Receiver)'"
```

Hier sieht man den `BootReceiver` (startet nach Neustart) und den `ChatService`.
Ob ein solcher Dienst **gerade läuft** (als Foreground-Dienst):

```powershell
adb shell "dumpsys activity services de.rechenhilfe.app.debug | grep -E 'ServiceRecord|isForeground|foregroundServiceType'"
```
```
  * ServiceRecord{... de.rechenhilfe.app.debug/de.rechenhilfe.app.ChatService}
    isForeground=true  types=0x00000200   <- 0x200 = remoteMessaging
```

`foregroundServiceType` **remoteMessaging** = eine dauerhafte Nachrichten-
verbindung. Genau das, was eine Chat-App braucht.

### Schritt 8: Sonderzugriffe (sehr aussagekräftig)

```powershell
adb shell settings get secure enabled_accessibility_services
adb shell settings get secure enabled_notification_listeners
adb shell "dumpsys device_policy | grep -i 'admin='"
```

Eine unbekannte App mit **Bedienungshilfe**, **Benachrichtigungszugriff** oder
**Geräteadmin** kann mitlesen/fernsteuern — immer prüfen. (Der Launcher taucht
beim Benachrichtigungszugriff normal auf, das ist kein Alarm.)

### Schritt 9: Ist die App aktiv?

```powershell
# Zuletzt benutzt (zeigt u.a. lastTimeUsed=... und appLaunchCount=...):
adb shell "dumpsys usagestats | grep 'package=de.rechenhilfe.app.debug'"

# Datenverkehr je App-UID (hier UID 10216 aus Schritt 4, appId):
adb shell "dumpsys netstats | grep -E '^ +10216 '"
```
```
    package=de.rechenhilfe.app.debug ... lastTimeUsed="2026-10-19 07:29:26" ...
    10216 4014 45 2847 36      (uid  rxBytes rxPackets txBytes txPackets)
```

> Tipp fürs Quoting unter Windows: Den Teil nach `adb shell` immer in **doppelte
> Anführungszeichen** setzen und innen nur **einfache** benutzen — dann muss man
> nichts escapen. Das gilt für alle Befehle hier.

Verkehr + kürzliche Nutzung zeigen: die App tut wirklich etwas.

### Schritt 10: Die APK holen und in den Code schauen

Pfad der APK ermitteln und auf den PC ziehen:

```powershell
adb shell pm path de.rechenhilfe.app.debug
adb pull /data/app/~~.../base.apk rechner.apk
```

**a) Signaturzertifikat** (wer hat signiert?) — mit `apksigner` aus den
Android-SDK-Build-Tools (`%LOCALAPPDATA%\Android\Sdk\build-tools\<version>\`):

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
& "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.1.0\apksigner.bat" verify --print-certs rechner.apk
```
```
Signer #1 certificate DN: C=US, O=Android, CN=Android Debug
```
→ **Android-Debug-Zertifikat**: ein selbst gebauter Entwickler-Build, keine
offizielle App.

**b) Name und Rechte aus dem Manifest** — mit `aapt2`:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.1.0\aapt2.exe" dump badging rechner.apk | Select-String "application-label:|uses-permission"
& "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.1.0\aapt2.exe" dump xmltree rechner.apk --file AndroidManifest.xml | Select-String "foregroundServiceType|excludeFromRecents|debuggable|allowBackup"
```
```
application-label:'Rechner'
...:debuggable=true   ...:allowBackup=false
...:excludeFromRecents=true   ...:foregroundServiceType=0x200
```
→ heißt **„Rechner"**, blendet sich aber aus der App-Übersicht aus
(`excludeFromRecents`) und hat einen remoteMessaging-Dienst.

**c) In den Code schauen.** Die APK ist ein ZIP; der Code liegt in
`classes*.dex`. Entpacken und nach verräterischen Strings suchen:

```powershell
tar -xf rechner.apk
findstr /m /c:"okhttp3/internal/ws" classes*.dex
findstr /m /c:"258EAFA5-E914-47DA-95CA-C5AB0DC85B11" classes*.dex
```
```
classes4.dex        <- enthaelt die OkHttp-WebSocket-Klassen
classes4.dex        <- enthaelt die WebSocket-GUID (Handshake-Konstante)
```

Die **Server-Adresse** herausziehen:

```powershell
(Select-String -Path classes*.dex -Pattern 'wss://[0-9A-Za-z.:/_-]+' -AllMatches).Matches.Value | Select-Object -Unique
```
```
wss://203.0.113.7:8444
```

→ Die „Rechner"-App spricht per WebSocket mit einem festen Server. Spätestens
jetzt ist klar: Das ist **keine Rechner-App**.

### Schritt 11: Zwischenfazit „Rechner"

Von Hand zusammengetragen:

| Beobachtung | Befehl | Bedeutung |
|---|---|---|
| per `adb install`, kein Store | `dumpsys package`, `pm list -i` | Herkunft unklar |
| Debug-Zertifikat | `apksigner` | Eigenbau |
| OkHttp-WebSocket + GUID + `wss://…` | `findstr`/`Select-String` in `classes*.dex` | Chat/Netz-Funktion |
| `foregroundServiceType=remoteMessaging` | `dumpsys activity services` | Dauer-Chatverbindung |
| `excludeFromRecents`, Name „Rechner" | `aapt2` | Tarnung |

Das reicht, um die App sicher auf die **Prüfliste** zu setzen.

---

## Teil 2 — Das Skript `appanalyse`

Die Handarbeit aus Teil 1 ist genau das, was das Werkzeug automatisiert — für
**alle Apps auf einmal** und mit zusätzlicher Bewertung.

### Start

```powershell
.venv\Scripts\appanalyse scan -s emulator-5554
```
oder doppelklickbar und geführt: **`AppAnalyse starten.cmd`** (fragt Online/
Offline) bzw. **`AppAnalyse offline starten.cmd`** (fest offline).

### Was das Skript 1:1 wie die Handarbeit macht

| Teil-1-Schritt | im Skript |
|---|---|
| `pm list packages -3 -i`, `dumpsys package` | `parsers/pm.py`, `parsers/dumpsys_package.py` |
| Launcher-Vergleich (Schritt 6) | `parsers/activity.py` |
| Sonderzugriffe (Schritt 8) | `parsers/special_access.py` |
| Nutzung/Verkehr/Dienste (Schritt 9) | `parsers/usagestats.py`, `netstats.py`, `activity.py` |
| APK ziehen + Zertifikat + Manifest (Schritt 10) | `apk/analyzer.py` (androguard) |
| Code-Strings (GUID, `wss://`, OkHttp) | `apk/dex_strings.py` + `apk/indicators.py` |

### Was das Skript **zusätzlich** macht

1. **Alle Apps gleichzeitig** statt eine nach der anderen — inklusive aller
   Profile und der „deinstalliert, aber Daten behalten"-Fälle.
2. **Hersteller-Apps automatisch aussortieren:** Das Skript vergleicht die
   Signatur jeder Drittanbieter-App mit den System-Signaturen des Geräts und
   wertet `initiatingPackageName`/`installReason` aus. So fallen bei Xiaomi,
   Oppo, Samsung nicht hunderte harmlose `installer=null`-Apps in die Prüfliste
   (siehe Praxis-Falle in Schritt 3). Auf Custom-ROMs/Emulatoren mit
   `test-keys`/`dev-keys` wird der Plattformsignatur bewusst **nicht** vertraut.
3. **Online-Abgleich** (nur im Online-Modus): Gibt es den Paketnamen bei
   **Google Play** / **F-Droid**? Ist der APK-Hash bei **VirusTotal** bekannt?
   Abgleich mit einer **Stalkerware-Liste** (Paketnamen + Zertifikats-Hashes).
   „Nirgends im Store" ist ein starkes Eigenbau-Indiz.
4. **Bewertung & Priorität** — die Einzelbeobachtungen werden zu Punkten
   **H / Chat / V** verrechnet und ergeben die Einstufung *Unbedingt prüfen →
   Prüfen empfohlen → Bekannter Messenger → Unauffällig*. Jeder Punkt nennt
   seinen **Beleg**.
5. **Obfuskierungsfest:** ein eigener, schneller DEX-String-Leser findet die
   Merkmale auch dann, wenn ein **Release-Build** die Klassennamen verschleiert
   (die Protokoll-GUID und die Server-Adresse überleben das).
6. **Beweiskette:** jeder ADB-Aufruf wird mit Roh-Ausgabe, Zeitstempel und
   SHA-256 protokolliert (`rohdaten/`, `befehle.json`, `sha256.csv`).
7. **Bericht:** ein eigenständiger **HTML-Bericht** (Suche, Filter, Belege) plus
   CSV/JSON — und je Verdachts-App gleich der passende **Datensicherungs-Befehl**
   (`run-as` ohne Root bei Debug-Builds, sonst Root/physikalisch).

### Dasselbe Ergebnis, automatisch

Im Scan landet „Rechner" mit genau den Belegen aus Teil 1 unter **Unbedingt
prüfen** (H/Chat/V, z. B. 80/70/40) — nur eben in Sekunden und neben allen
anderen Apps, statt jede von Hand durchzugehen.

---

## Anhang — Befehls-Spickzettel

```powershell
adb devices                                           # Geräte
adb shell pm list users                               # Profile
adb shell "pm list packages -3 -i"                    # Drittanbieter + Installer
adb shell "pm list packages -3 -i | grep -v com.android.vending"   # nicht aus Play
adb shell "dumpsys package <pkg> | grep -E 'installerPackageName=|initiatingPackageName=|installReason=|packageSource=|signatures:|flags=\['"
adb shell "dumpsys package android | grep -m1 signatures:"   # System-Signatur zum Vergleich
adb shell "dumpsys package <pkg> | grep granted=true" # gewährte Rechte
adb shell "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER"   # Launcher
adb shell settings get secure enabled_accessibility_services
adb shell settings get secure enabled_notification_listeners
adb shell "dumpsys activity services <pkg> | grep -E 'isForeground|foregroundServiceType'"
adb shell "dumpsys usagestats | grep 'package=<pkg>'"
adb shell "dumpsys netstats | grep -E '^ +<uid> '"    # Verkehr je UID
adb shell pm path <pkg>                               # APK-Pfad
adb pull <pfad> app.apk                               # APK sichern
tar -xf app.apk                                       # APK (=ZIP) entpacken
findstr /m /c:"okhttp3/internal/ws" classes*.dex      # Code-Merkmale
.venv\Scripts\appanalyse scan -s <serial>             # alles automatisch
```
