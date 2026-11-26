#!/usr/bin/env bash
# Como set-setting.sh, para los datos de prueba de esta rama. Uso: set-setting-seg.sh security_level 2
mkdir -p "$HOME/sombra-seg/data/Sombra"
python3 - "$1" "$2" <<'EOF'
import json, os, sys
p = os.path.expanduser('~/sombra-seg/data/Sombra/settings.json')
d = json.load(open(p)) if os.path.exists(p) else {}
d[sys.argv[1]] = json.loads(sys.argv[2])
json.dump(d, open(p, 'w'), indent=2)
print(sys.argv[1], '=', d[sys.argv[1]])
EOF
