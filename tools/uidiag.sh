#!/usr/bin/env bash
# Diagnóstico de la interfaz (solo versión de pruebas): abre Sombra y anota errores de JavaScript.
BIN="${CARGO_TARGET_DIR:-$HOME/sombra-target}/debug/sombra"
export WEBKIT_DISABLE_DMABUF_RENDERER=1 RUST_LOG=warn SOMBRA_UIDIAG=1
timeout 40 "$BIN" > /tmp/sombra-uidiag.log 2>&1 &
for i in $(seq 1 35); do grep -q UIDIAG /tmp/sombra-uidiag.log && break; sleep 1; done
grep UIDIAG /tmp/sombra-uidiag.log || echo "sin resultado"
pkill -f "sombra-target/debug/sombra" ; true
