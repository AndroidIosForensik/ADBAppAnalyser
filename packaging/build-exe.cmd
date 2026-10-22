@echo off
REM Baut die eigenstaendige appanalyse.exe mit PyInstaller.
REM Voraussetzung: .venv mit installiertem Projekt (pip install -e .) und pyinstaller.
setlocal
cd /d "%~dp0\.."
if not exist ".venv\Scripts\python.exe" ( echo [FEHLER] .venv fehlt - erst "pip install -e ." ausfuehren. & exit /b 1 )
".venv\Scripts\python.exe" -m pip install -q pyinstaller
rmdir /s /q build dist 2>nul
del /q appanalyse.spec 2>nul
".venv\Scripts\python.exe" -m PyInstaller --onefile --name appanalyse --console --paths src ^
  --collect-data androguard --collect-binaries androguard ^
  --collect-submodules appanalyse ^
  --exclude-module androguard.pentest --exclude-module matplotlib --exclude-module tkinter ^
  --exclude-module PyQt5 --exclude-module PySide2 --exclude-module PySide6 --exclude-module PyQt6 ^
  --hidden-import androguard.core.apk --hidden-import androguard.core.axml ^
  --add-data "src\appanalyse\data;appanalyse\data" ^
  --add-data "src\appanalyse\report\templates;appanalyse\report\templates" ^
  --noconfirm packaging\appanalyse_entry.py
echo.
if exist "dist\appanalyse.exe" ( echo Fertig: dist\appanalyse.exe ) else ( echo [FEHLER] Build fehlgeschlagen. )
endlocal
