#!/usr/bin/env bash
# Prueba varias veces la conexión al DuckDuckGo .onion a través del proxy de Sombra.
PORT=$(ss -ltnp 2>/dev/null | grep '"sombra"' | grep -v 4782 | grep -oE '127\.0\.0\.1:[0-9]+' | head -1 | cut -d: -f2)
ONION=https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/
for i in 1 2 3; do
  R=$(curl --socks5-hostname 127.0.0.1:$PORT --max-time 90 -s -o /dev/null -w '%{http_code} %{time_total}s' "$ONION" 2>&1)
  echo "Intento $i: HTTP $R"
  sleep 2
done
