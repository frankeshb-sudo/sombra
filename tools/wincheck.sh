#!/usr/bin/env bash
# Comprueba (sin compilar ni ejecutar nada en Windows) que el cÃ³digo de Windows compila.
set -u
cd "$(dirname "$0")/../src-tauri"
"$HOME/.cargo/bin/rustup" target add x86_64-pc-windows-gnu >/dev/null 2>&1
export CARGO_TARGET_DIR="$HOME/sombra-target-wincheck"
"$HOME/.cargo/bin/cargo" check --target x86_64-pc-windows-gnu --color never > /tmp/sombra-wincheck.log 2>&1
code=$?
grep -E '^error|^\s+-->|^\s+[0-9]* \||^\s*= (note|help)' /tmp/sombra-wincheck.log | head -120
tail -3 /tmp/sombra-wincheck.log
echo "EXIT=$code"
