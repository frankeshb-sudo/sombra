#!/usr/bin/env bash
# Abre la versión de esta rama con sus propios datos (no choca con otra copia de Sombra abierta).
export XDG_DATA_HOME=/tmp/sombra-seg-data
mkdir -p "$XDG_DATA_HOME"
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export RUST_LOG="${RUST_LOG:-warn}"
exec "$HOME/sombra-target-seg/debug/sombra" > /tmp/sombra-seg-run.log 2>&1
