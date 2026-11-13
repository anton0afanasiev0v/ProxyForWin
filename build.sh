#!/usr/bin/env bash
# Builds a self-contained win-x64 single-file executable on Linux or Windows.
set -euo pipefail

cd "$(dirname "$0")"

if [ -x "$HOME/.dotnet/dotnet" ]; then
  export PATH="$HOME/.dotnet:$PATH"
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet SDK 8.0 not found. Install it: https://dot.net" >&2
  exit 1
fi

rm -rf dist/ProxyForWin

dotnet publish src/ProxyTray/ProxyTray.csproj \
  -c Release \
  -r win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -o dist/ProxyForWin

cp README.md dist/ProxyForWin/README.md
cp native/WinDivert/WinDivert.dll native/WinDivert/WinDivert64.sys dist/ProxyForWin/
cp native/WinDivert/LICENSE.txt dist/ProxyForWin/WinDivert-LICENSE.txt

echo
echo "Упаковка..."
cd dist
rm -f ProxyForWin-win-x64.zip
zip -q -r ProxyForWin-win-x64.zip ProxyForWin
cd ..

echo
echo "Готово: dist/ProxyForWin/ProxyForWin.exe"
echo "Архив:  dist/ProxyForWin-win-x64.zip"
ls -la dist/ProxyForWin
