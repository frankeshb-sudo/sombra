#!/usr/bin/env bash
# Pruebas automáticas de la bóveda de contraseñas (cifrado, desbloqueo, recuperación).
cd "$(dirname "$0")/../src-tauri"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/sombra-target}"
"${CARGO:-$HOME/.cargo/bin/cargo}" test --color never vault > /tmp/sombra-test.log 2>&1
code=$?
grep -E '^error|-->|^test |test result|panicked|assert' /tmp/sombra-test.log | head -40
echo "EXIT=$code"
exit $code
