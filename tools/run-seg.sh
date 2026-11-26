#!/usr/bin/env bash
# Abre la versión de esta rama con sus propios datos y su propio nombre de programa
# (no choca con otra copia de Sombra abierta ni con quien limpie /tmp).
# Uso: bash tools/run-seg.sh [gdb]
D="$HOME/sombra-seg"
mkdir -p "$D/data" "$D/bin"
cp -f "$HOME/sombra-target-seg/debug/sombra" "$D/bin/sombra-seg"
export XDG_DATA_HOME="$D/data"
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export RUST_LOG="${RUST_LOG:-warn}"
if [ "${1:-}" = "gdb" ]; then
  exec gdb -q -batch -ex 'set pagination off' -ex 'handle SIGPIPE nostop noprint' -ex run -ex 'thread apply all bt 12' "$D/bin/sombra-seg" > "$D/run.log" 2>&1
fi
exec "$D/bin/sombra-seg" > "$D/run.log" 2>&1
