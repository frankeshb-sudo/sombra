#!/usr/bin/env bash
# Pruebas unitarias del motor en Linux (WSL). Uso: tools/unittest.sh [filtro]
cd "$(dirname "$0")/../src-tauri"
export CARGO_TARGET_DIR="$HOME/sombra-target-seg"
"$HOME/.cargo/bin/cargo" test --color never "$@" 2>&1 | grep -E '^test |test result|panicked|left:|right:|^error'
