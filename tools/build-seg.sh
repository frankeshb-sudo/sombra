#!/usr/bin/env bash
# Compila la rama de niveles de seguridad aparte (no choca con otras compilaciones).
set -u
cd "$(dirname "$0")/../src-tauri"
export CARGO_TARGET_DIR="$HOME/sombra-target-seg"
"$HOME/.cargo/bin/cargo" build --color never > /tmp/sombra-seg-build.log 2>&1
code=$?
grep -E '^(error|warning: unused)|^\s+-->|^\s+[0-9]* \||^\s*= (note|help)' /tmp/sombra-seg-build.log | head -150
tail -3 /tmp/sombra-seg-build.log
echo "EXIT=$code"
