#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -x "$HOME/.dotnet/dotnet" ]; then export PATH="$HOME/.dotnet:$PATH"; fi
dotnet run --project tests/ProxyCore.Tests/ProxyCore.Tests.csproj -c Release
