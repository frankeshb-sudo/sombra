#!/usr/bin/env bash
# Prueba el proxy de Sombra mientras está abierto: Tor, país, bloqueo de anuncios y red local.
PORT=$(ss -ltnp 2>/dev/null | grep '"sombra"' | grep -v 4782 | grep -oE '127\.0\.0\.1:[0-9]+' | head -1 | cut -d: -f2)
echo "Puerto del proxy: ${PORT:-NO ENCONTRADO}"
[ -z "$PORT" ] && exit 1
P="--socks5-hostname 127.0.0.1:$PORT --max-time 60 -s"
echo "== Esperando a Tor =="
for i in $(seq 1 40); do
  R=$(curl $P https://check.torproject.org/api/ip 2>/dev/null) && [ -n "$R" ] && break
  sleep 3
done
echo "Respuesta de check.torproject.org: $R"
echo "== ¿La IP visible es distinta de la real? =="
REAL=$(curl -s --max-time 15 https://api.ipify.org)
case "$R" in *"$REAL"*) echo "NO: se ve tu IP real (FALLO)";; *) echo "Sí: tu IP real está oculta";; esac
echo "== Anuncio (doubleclick.net) =="
curl $P -o /dev/null -w '%{http_code}\n' https://securepubads.g.doubleclick.net/ 2>&1 || echo "BLOQUEADO (correcto)"
echo "== Rastreador (google-analytics.com) =="
curl $P -o /dev/null -w '%{http_code}\n' https://www.google-analytics.com/analytics.js 2>&1 || echo "BLOQUEADO (correcto)"
echo "== Red local (192.168.1.1) =="
curl $P -o /dev/null -w '%{http_code}\n' http://192.168.1.1/ 2>&1 || echo "BLOQUEADO (correcto)"
echo "== Web normal (duckduckgo.com) =="
curl $P -o /dev/null -w '%{http_code}\n' https://duckduckgo.com/
echo "== Buscador DuckDuckGo por .onion (dentro de Tor) =="
ONION=https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
curl $P --max-time 120 -o /tmp/ddg.html -w 'HTTP %{http_code} en %{time_total}s\n' "$ONION/html/?q=privacidad" || echo "FALLO al conectar con el .onion"
grep -c 'result__a' /tmp/ddg.html 2>/dev/null | sed 's/^/Resultados encontrados: /'
