#!/usr/bin/env bash
# Cambia un ajuste de Sombra (Linux) con Sombra cerrado. Uso: tools/set-setting.sh fp_strict false
python3 - "$1" "$2" <<'EOF'
import json, os, sys
p = os.path.expanduser('~/.local/share/Sombra/settings.json')
d = json.load(open(p))
d[sys.argv[1]] = json.loads(sys.argv[2])
json.dump(d, open(p, 'w'), indent=2)
print(sys.argv[1], '=', d[sys.argv[1]])
EOF
