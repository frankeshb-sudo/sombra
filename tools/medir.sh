#!/usr/bin/env bash
# Mide cuánto gasta Sombra en reposo (Linux/WSL): memoria real (PSS) de todos sus procesos
# (Sombra y los del motor WebKit) y procesador durante 30 s, con una web normal abierta.
# Uso: bash tools/medir.sh [etiqueta] [segundos de espera antes de medir]
D="$(dirname "$0")"
pkill -f 'bin/sombra-se[g]'; sleep 1
rm -f "$HOME/sombra-seg/run.log"
SOMBRA_SECTEST=medir bash "$D/run-seg.sh" &
until grep -aq 'SECTEST medir cargada' "$HOME/sombra-seg/run.log" 2>/dev/null; do sleep 1; done
sleep "${2:-25}"
main=$(pgrep -f 'bin/sombra-se[g]' | head -1)
pids() { { echo "$main"; pgrep -P "$main"; for c in $(pgrep -P "$main"); do pgrep -P "$c"; done; } | sort -u; }
P=$(pids)
pss() { awk '/^Pss:/{print int($2/1024)}' /proc/$1/smaps_rollup 2>/dev/null || echo 0; }
tk() { awk '{print $14+$15}' /proc/$1/stat 2>/dev/null || echo 0; }
declare -A T1
for p in $P; do T1[$p]=$(tk $p); done
sleep 30
hz=$(getconf CLK_TCK)
tm=0; tc=0
for p in $P; do
  m=$(pss $p); c=$(( $(tk $p) - ${T1[$p]} )); tm=$((tm + m)); tc=$((tc + c))
  printf '  %-16s %5s MB  %5s %%\n' "$(cat /proc/$p/comm 2>/dev/null)" "$m" "$(awk -v c=$c -v hz=$hz 'BEGIN{printf "%.1f", c/hz/30*100}')"
done
echo "${1:-medida}: memoria ${tm} MB, procesador en reposo $(awk -v c=$tc -v hz=$hz 'BEGIN{printf "%.1f", c/hz/30*100}') % de un núcleo"
grep -a 'SECTEST medir' "$HOME/sombra-seg/run.log" | tail -1 | sed 's/.*SECTEST/SECTEST/'
pkill -f 'bin/sombra-se[g]'
