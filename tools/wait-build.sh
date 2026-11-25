#!/usr/bin/env bash
# Espera a que termine una compilación en curso y muestra el final del registro.
for i in $(seq 1 115); do
  pgrep -x cargo >/dev/null || break
  sleep 5
done
grep -E '^error|^\s+-->' /tmp/sombra-build.log | head -40
tail -3 /tmp/sombra-build.log
