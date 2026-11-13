@echo off
setlocal
cd /d "%~dp0"

where dotnet >nul 2>nul
if errorlevel 1 (
  echo dotnet SDK 8.0 not found. Install it from https://dot.net
  exit /b 1
)

if exist "dist\ProxyForWin" rmdir /s /q "dist\ProxyForWin"

dotnet publish src\ProxyTray\ProxyTray.csproj ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:DebugType=None ^
  -p:DebugSymbols=false ^
  -o dist\ProxyForWin

if errorlevel 1 exit /b 1

copy /y README.md dist\ProxyForWin\README.md >nul
copy /y native\WinDivert\WinDivert.dll dist\ProxyForWin\ >nul
copy /y native\WinDivert\WinDivert64.sys dist\ProxyForWin\ >nul
copy /y native\WinDivert\LICENSE.txt dist\ProxyForWin\WinDivert-LICENSE.txt >nul

echo.
echo Ready: dist\ProxyForWin\ProxyForWin.exe
dir dist\ProxyForWin
endlocal
