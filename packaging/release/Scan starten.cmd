@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title ADB App Analyse
color 0F

if not exist "appanalyse.exe" (
  echo [FEHLER] appanalyse.exe nicht gefunden. Bitte im entpackten Release-Ordner starten.
  pause & exit /b 1
)

echo(
echo ==========================================================================
echo                         ADB APP ANALYSE
echo ==========================================================================
echo Liest ueber ADB alle installierten Apps aus und erstellt eine Pruefliste
echo mit Apps, die man auf versteckte/selbst gebaute Chat-Apps pruefen sollte.
echo REIN LESEND: kein Root, keine Rechtevergabe, keine Aenderung am Geraet.
echo(
echo Voraussetzung: Android Platform Tools (adb) installiert, USB-Debugging am
echo Geraet aktiv und der Anschluss bestaetigt.
echo(

echo --------------------------------------------------------------------------
echo  Angeschlossene Geraete
echo --------------------------------------------------------------------------
appanalyse.exe devices
echo(
set "SERIAL="
set /p "SERIAL=Seriennummer (leer = einziges Geraet automatisch): "

echo(
echo --------------------------------------------------------------------------
echo  Betriebsart
echo --------------------------------------------------------------------------
echo  [1] ONLINE  (empfohlen): gleicht Paketnamen mit Google Play / F-Droid ab
echo      (dabei gehen Paketnamen an Google und F-Droid). "Nirgends im Store"
echo      ist ein starkes Indiz fuer einen Eigenbau.
echo  [2] OFFLINE: schickt nichts ins Internet, nur lokale Analyse.
echo(
set "MODE=" & set /p "MODE=Auswahl [1]: "
set "MODEFLAG=" & set "MODETEXT=ONLINE"
if "!MODE!"=="2" ( set "MODEFLAG=--offline" & set "MODETEXT=OFFLINE" )

set "SERIALFLAG="
if not "!SERIAL!"=="" set "SERIALFLAG=-s !SERIAL!"

echo(
echo Starte Scan (!MODETEXT!) - dauert ein paar Minuten...
echo(
appanalyse.exe scan !SERIALFLAG! !MODEFLAG!

echo(
echo --------------------------------------------------------------------------
echo  Punkte H/Chat/V:  H=Herkunft (Store/seitlich/Zertifikat)   Chat=Chat-/
echo  Netzfunktion (WebSocket, Server, Push)   V=Verschleierung/Tarnung.
echo  Hoehere Werte = verdaechtiger. Details mit Belegen im HTML-Bericht.
echo --------------------------------------------------------------------------
set "REPORT="
for /f "delims=" %%D in ('dir /b /ad /o-n "ausgabe" 2^>nul') do (
  if not defined REPORT if exist "ausgabe\%%D\bericht.html" set "REPORT=ausgabe\%%D\bericht.html"
)
if defined REPORT ( echo Oeffne Bericht: !REPORT! & start "" "!REPORT!" ) else echo [Hinweis] Kein Bericht gefunden - siehe Ordner "ausgabe".
echo(
echo Fertig.
pause
endlocal
