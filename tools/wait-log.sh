#!/usr/bin/env bash
# Espera (máx. $3 s) a que aparezca $2 en el registro $1 y muestra las líneas de prueba.
# Uso: bash tools/wait-log.sh /tmp/sombra-seg-run.log "youtube anuncios" 420 SECTEST
end=$((SECONDS + ${3:-300}))
until grep -aq "$2" "$1" 2>/dev/null || [ $SECONDS -ge $end ]; do sleep 5; done
grep -a "${4:-SECTEST}" "$1"
