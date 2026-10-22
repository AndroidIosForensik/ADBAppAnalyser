@echo off
REM Startet den gefuehrten Scan fest im OFFLINE-Modus:
REM keine Paketnamen an Google/F-Droid, keine Hashes an VirusTotal.
REM Die Ablaufschritte und Erklaerungen stehen in "AppAnalyse starten.cmd".
title ADB App Analyse - OFFLINE
call "%~dp0AppAnalyse starten.cmd" offline
