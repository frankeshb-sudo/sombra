#!/usr/bin/env bash
# Lanza la prueba de seguridad de esta rama, espera el resultado y cierra Sombra.
# Uso: bash tools/sectest.sh [yt|all] [segundos]
pkill -f 'bin/sombra-se[g]'
sleep 1
rm -f "$HOME/sombra-seg/run.log"
SOMBRA_SECTEST="${1:-all}" bash "$(dirname "$0")/run-seg.sh" &
sleep 5
end=$((SECONDS + ${2:-420}))
until grep -aqE 'youtube anuncios|SECTEST https fin' "$HOME/sombra-seg/run.log" 2>/dev/null || [ $SECONDS -ge $end ] || ! pgrep -f 'bin/sombra-se[g]' >/dev/null; do sleep 5; done
grep -a 'SECTEST' "$HOME/sombra-seg/run.log"
pgrep -f 'bin/sombra-se[g]' >/dev/null || echo "Sombra se ha cerrado"
pkill -f 'bin/sombra-se[g]'
