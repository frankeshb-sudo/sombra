#!/usr/bin/env bash
# Prueba real del aviso "¿Guardar la contraseña?" (solo versión de pruebas).
# Abre Sombra, entra con datos falsos en una web de práctica y mira si el aviso llega.
BIN="${CARGO_TARGET_DIR:-$HOME/sombra-target}/debug/sombra"
export WEBKIT_DISABLE_DMABUF_RENDERER=1 RUST_LOG=warn SOMBRA_SELFTEST=1
timeout 150 "$BIN" > /tmp/sombra-selftest.log 2>&1 &
for i in $(seq 1 140); do
  grep -q "SELFTEST diag" /tmp/sombra-selftest.log && break
  sleep 1
done
grep "SELFTEST" /tmp/sombra-selftest.log || echo "Sin resultado (ver /tmp/sombra-selftest.log)"
pkill -f sombra-target/debug/sombra
