#!/usr/bin/env bash
# Abre Sombra (versión Linux). En WSL la ventana aparece en el escritorio de Windows.
# Uso: bash tools/run-linux.sh [--release]
BIN_DIR="${CARGO_TARGET_DIR:-$HOME/sombra-target}/debug"
[ "${1:-}" = "--release" ] && BIN_DIR="${CARGO_TARGET_DIR:-$HOME/sombra-target}/release"
# Evita ventanas en blanco con algunos drivers gráficos (WSL, NVIDIA).
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export RUST_LOG="${RUST_LOG:-warn}"
exec "$BIN_DIR/sombra" > /tmp/sombra-run.log 2>&1
