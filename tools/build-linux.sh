#!/usr/bin/env bash
# Compila Sombra para Linux (también sirve dentro de WSL en Windows).
# Uso: bash tools/build-linux.sh [--release]
set -u
cd "$(dirname "$0")/../src-tauri"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/sombra-target}"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
"$CARGO" build --color never "$@" > /tmp/sombra-build.log 2>&1
code=$?
grep -E '^(error|warning: unused)|^\s+-->|^\s+[0-9]* \||^\s*= (note|help)' /tmp/sombra-build.log | head -250
tail -3 /tmp/sombra-build.log
echo "EXIT=$code"
exit $code
