@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title ADB App Analyse - gefuehrter Scan
color 0F

echo(
echo ==========================================================================
echo                    ADB APP ANALYSE - gefuehrter Scan
echo ==========================================================================
echo(
echo Dieses Werkzeug liest ueber ADB alle installierten Apps eines Android-
echo Geraets aus und erstellt eine PRUEFLISTE mit Apps, die man auf versteckte
echo oder selbst gebaute Chat-Apps hin gegenchecken sollte.
echo(
echo Die Sammlung ist REIN LESEND: kein Root, keine Rechtevergabe, keine
echo Aenderung am Geraet.
echo(

REM ---------------------------------------------------------------------------
REM 1) Python finden
REM ---------------------------------------------------------------------------
set "PY="
where py  >nul 2>&1 && set "PY=py -3"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo [FEHLER] Python wurde nicht gefunden. Bitte Python 3.10+ installieren
  echo          und "AppAnalyse starten.cmd" erneut ausfuehren.
  echo(
  pause
  exit /b 1
)

REM ---------------------------------------------------------------------------
REM 2) Beim ersten Start die virtuelle Umgebung (.venv) einrichten
REM ---------------------------------------------------------------------------
if not exist ".venv\Scripts\appanalyse.exe" (
  echo [Erststart] Richte einmalig die Arbeitsumgebung ein ^(dauert 1-2 Minuten,
  echo             braucht Internet^)...
  echo(
  %PY% -m venv .venv
  if errorlevel 1 ( echo [FEHLER] Konnte .venv nicht anlegen. & pause & exit /b 1 )
  ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
  ".venv\Scripts\python.exe" -m pip install -e .
  if errorlevel 1 ( echo [FEHLER] Installation fehlgeschlagen. & pause & exit /b 1 )
  echo(
  echo [OK] Umgebung eingerichtet.
  echo(
)
set "APP=.venv\Scripts\appanalyse.exe"

REM ---------------------------------------------------------------------------
REM 3) Geraete anzeigen und auswaehlen
REM ---------------------------------------------------------------------------
echo --------------------------------------------------------------------------
echo  Angeschlossene Geraete
echo --------------------------------------------------------------------------
echo Voraussetzung: USB-Debugging am Geraet aktiv und der Anschluss am PC
echo bestaetigt ^(RSA-Dialog^). Bei mehreren Geraeten die Seriennummer eingeben.
echo(
"%APP%" devices
echo(
set "SERIAL="
set /p "SERIAL=Seriennummer (leer lassen = einziges Geraet automatisch nehmen): "

REM ---------------------------------------------------------------------------
REM 4) Betriebsart waehlen: Online oder Offline
REM ---------------------------------------------------------------------------
REM Aufruf mit Parameter "offline" (z. B. aus "AppAnalyse offline starten.cmd"):
REM keine Auswahl anbieten, fest offline.
if /I "%~1"=="offline" goto :fest_offline

echo(
echo --------------------------------------------------------------------------
echo  Betriebsart waehlen
echo --------------------------------------------------------------------------
echo(
echo  [1] ONLINE  (empfohlen)
echo      Zusaetzlich zum lokalen Check werden die PAKETNAMEN der installierten
echo      Apps online abgeglichen:
echo        - Google Play  : gibt es diese App im Play Store?  (ja / nein)
echo        - F-Droid       : gibt es diese quelloffene App bei F-Droid?
echo        - VirusTotal    : nur wenn ein API-Key gesetzt ist und nur fuer
echo                          Verdachtsfaelle - es wird NUR der Datei-Hash
echo                          geschickt, niemals die App selbst.
echo      Nutzen: Eine App, die es NIRGENDS im Store gibt, ist ein starkes
echo      Indiz fuer einen Eigenbau. Ergebnisse werden lokal zwischengespeichert.
echo      Datenschutz: dabei gehen Paketnamen (z.B. com.whatsapp) an Google
echo      und F-Droid.
echo(
echo  [2] OFFLINE
echo      Schickt NICHTS ins Internet. Es zaehlt nur die lokale Analyse:
echo      APK-Code, Zertifikate, Manifest, Berechtigungen, Sichtbarkeit sowie
echo      der Abgleich mit der lokal gespeicherten Stalkerware-Liste ^(falls
echo      vorher einmal geladen^).
echo      Sicherer fuer sensible Ermittlungen, liefert aber weniger Kontext.
echo(
set "MODE="
set /p "MODE=Auswahl [1]: "
if "!MODE!"=="" set "MODE=1"

set "MODEFLAG="
set "MODETEXT=ONLINE"
if "!MODE!"=="2" ( set "MODEFLAG=--offline" & set "MODETEXT=OFFLINE" )
goto :modus_fertig

:fest_offline
title ADB App Analyse - OFFLINE
echo(
echo --------------------------------------------------------------------------
echo  Betriebsart: OFFLINE  (fest eingestellt)
echo --------------------------------------------------------------------------
echo  Es werden KEINE Daten ins Internet geschickt - keine Paketnamen an
echo  Google oder F-Droid, keine Hashes an VirusTotal.
echo(
echo  Ausgewertet wird nur lokal:
echo    - APK-Code ^(Chat-Bibliotheken, Protokoll-Signaturen, Server-Adressen^)
echo    - Signaturzertifikat ^(Debug-/Eigenbau-Zertifikat^)
echo    - Manifest ^(versteckte Dienste, Tarnname, Teilen-Ziel^)
echo    - Berechtigungen, Sichtbarkeit, Sonderzugriffe, Aktivitaet
echo    - Stalkerware-Liste, sofern sie vorher einmal geladen wurde
echo(
echo  Was dadurch fehlt: der Hinweis "nicht im Play Store / nicht bei F-Droid".
echo  Seitlich installierte Apps erhalten dadurch etwas weniger Herkunftspunkte
echo  ^(bis zu 25^); die uebrigen Belege bleiben voll erhalten.
echo(
if exist "%LOCALAPPDATA%\appanalyse\stalkerware_ioc.yaml" (
  echo  [OK] Stalkerware-Liste ist lokal vorhanden.
) else (
  echo  [Hinweis] Keine lokale Stalkerware-Liste gefunden. Einmalig online laden:
  echo            .venv\Scripts\appanalyse update-lists
)
echo(
set "MODEFLAG=--offline"
set "MODETEXT=OFFLINE"

:modus_fertig

REM ---------------------------------------------------------------------------
REM 5) Scan starten
REM ---------------------------------------------------------------------------
set "SERIALFLAG="
if not "!SERIAL!"=="" set "SERIALFLAG=-s !SERIAL!"

echo(
echo --------------------------------------------------------------------------
echo  Starte Scan  (Betriebsart: !MODETEXT!)
echo --------------------------------------------------------------------------
echo Das dauert je nach Anzahl der Apps ein paar Minuten. Bitte warten...
echo(
"%APP%" scan !SERIALFLAG! !MODEFLAG!
set "RC=!ERRORLEVEL!"

REM ---------------------------------------------------------------------------
REM 6) Bedeutung der Punktwerte erklaeren
REM ---------------------------------------------------------------------------
echo(
echo --------------------------------------------------------------------------
echo  Was bedeuten die Spalten "Punkte H/Chat/V"?
echo --------------------------------------------------------------------------
echo   H     = HERKUNFT       woher die App stammt: aus einem Store oder
echo                          seitlich geladen, Art des Signaturzertifikats.
echo   Chat  = CHAT-FUNKTION  Hinweise auf Chat/Netzwerk: WebSocket, feste
echo                          Server-Adresse, Push, Verschluesselung.
echo   V     = VERSCHLEIERUNG Tarnung: harmlos wirkender Name, kein/verstecktes
echo                          Symbol, nur im Zweitprofil, obfuskierter Code.
echo   Hoehere Werte = verdaechtiger. Die Einstufung ergibt sich aus der
echo   Kombination - Details mit Belegen stehen im HTML-Bericht.
echo(
echo   Einstufungen: "Unbedingt pruefen" ^> "Pruefen empfohlen" ^>
echo   "Bekannter Messenger" ^> "Unauffaellig".
echo(

REM ---------------------------------------------------------------------------
REM 7) Neuesten Bericht suchen und oeffnen
REM ---------------------------------------------------------------------------
REM Ordnernamen sind Zeitstempel (yyyyMMdd_HHmmss...) - nach Name absteigend
REM sortieren und den ersten Ordner mit einem Bericht nehmen (neuester zuerst).
set "REPORT="
for /f "delims=" %%D in ('dir /b /ad /o-n "ausgabe" 2^>nul') do (
  if not defined REPORT if exist "ausgabe\%%D\bericht.html" set "REPORT=ausgabe\%%D\bericht.html"
)
if defined REPORT (
  echo Oeffne Bericht: !REPORT!
  start "" "!REPORT!"
) else (
  echo [Hinweis] Kein HTML-Bericht gefunden. Rohdaten liegen unter "ausgabe\".
)

echo(
if not "!RC!"=="0" (
  echo [Hinweis] Der Scan meldete Einschraenkungen/Teilfehler ^(Code !RC!^).
  echo           Ein Teilbericht wurde trotzdem erstellt; Einzelheiten in
  echo           ausgabe\...\tabellen\status.csv.
  echo(
)
echo Fertig. Fenster kann geschlossen werden.
pause
endlocal
