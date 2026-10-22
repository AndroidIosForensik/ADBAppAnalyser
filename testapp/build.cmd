@echo off
REM Baut die Test-App "Rechner". Nutzung: build.cmd [debug^|release^|both]
REM Setzt JAVA_HOME auf die Android-Studio-JBR und schreibt local.properties.
setlocal

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=both"

REM --- JDK aus Android Studio ---
if "%JAVA_HOME%"=="" set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
if not exist "%JAVA_HOME%\bin\java.exe" (
  echo [Fehler] JBR nicht gefunden unter "%JAVA_HOME%".
  echo Bitte JAVA_HOME auf ein JDK 17+ setzen.
  exit /b 1
)
echo JAVA_HOME=%JAVA_HOME%

REM --- Android SDK ---
if "%ANDROID_HOME%"=="" set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
if not exist "%ANDROID_HOME%\platform-tools" (
  echo [Fehler] Android SDK nicht gefunden unter "%ANDROID_HOME%".
  exit /b 1
)

REM local.properties (Gradle erwartet Vorwaertsschraegstriche)
set "SDK_FWD=%ANDROID_HOME:\=/%"
> "%~dp0local.properties" echo sdk.dir=%SDK_FWD%

if not exist "%~dp0app\chat.properties" (
  echo [Hinweis] app\chat.properties fehlt - baue mit Standardwerten aus chat.properties.example.
  echo           Fuer echte Tests die Werte aus relay\install.sh eintragen.
)

REM --- Release-Keystore bei Bedarf erzeugen ---
if /I "%TARGET%"=="release"  call :ensure_keystore
if /I "%TARGET%"=="both"     call :ensure_keystore

pushd "%~dp0"
if /I "%TARGET%"=="debug"    ( call gradlew.bat :app:assembleDebug   ) else ^
if /I "%TARGET%"=="release"  ( call gradlew.bat :app:assembleRelease ) else ^
                              ( call gradlew.bat :app:assembleDebug :app:assembleRelease )
set "RC=%ERRORLEVEL%"
popd

if "%RC%"=="0" (
  echo.
  echo Fertige APKs:
  if exist "%~dp0app\build\outputs\apk\debug\app-debug.apk"     echo   app\build\outputs\apk\debug\app-debug.apk
  if exist "%~dp0app\build\outputs\apk\release\app-release.apk" echo   app\build\outputs\apk\release\app-release.apk
)
exit /b %RC%

:ensure_keystore
if exist "%~dp0keystore.properties" goto :eof
echo Erzeuge Release-Keystore ...
set "KSPW=rechner-test-%RANDOM%%RANDOM%"
"%JAVA_HOME%\bin\keytool.exe" -genkeypair -v -keystore "%~dp0release.keystore" ^
  -alias rechner -keyalg RSA -keysize 2048 -validity 3650 ^
  -storepass "%KSPW%" -keypass "%KSPW%" -dname "CN=Rechner"
> "%~dp0keystore.properties" (
  echo storeFile=release.keystore
  echo storePassword=%KSPW%
  echo keyAlias=rechner
  echo keyPassword=%KSPW%
)
echo keystore.properties geschrieben.
goto :eof
