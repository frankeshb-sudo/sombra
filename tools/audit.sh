#!/usr/bin/env bash
# Auditoría de seguridad de esta rama (Linux/WSL): lanza Sombra con SOMBRA_AUDIT, vigila si sale
# alguna consulta DNS fuera de Tor (tcpdump, puerto 53) y muestra los resultados.
# Uso: bash tools/audit.sh [segundos]
D="$HOME/sombra-seg"
pkill -f 'bin/sombra-se[g]'
sleep 1
rm -f "$D/run.log" "$D/dns.log"
mkdir -p "$D"
if command -v tcpdump >/dev/null; then
  tcpdump -i any -n -l 'udp port 53 or tcp port 53 or udp port 5353' > "$D/dns.log" 2>/dev/null &
  TCPD=$!
fi
SOMBRA_AUDIT=1 bash "$(dirname "$0")/run-seg.sh" &
sleep 5
end=$((SECONDS + ${1:-600}))
until grep -aq 'AUDIT fin' "$D/run.log" 2>/dev/null || [ $SECONDS -ge $end ] || ! pgrep -f 'bin/sombra-se[g]' >/dev/null; do sleep 5; done
grep -a 'AUDIT' "$D/run.log"
pgrep -f 'bin/sombra-se[g]' >/dev/null || echo "Sombra se ha cerrado"
pkill -f 'bin/sombra-se[g]'
[ -n "${TCPD:-}" ] && kill "$TCPD" 2>/dev/null
echo "--- consultas DNS vistas durante la prueba ---"
cat "$D/dns.log" 2>/dev/null | head -40
