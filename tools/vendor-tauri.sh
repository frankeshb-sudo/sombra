#!/usr/bin/env bash
# Copia Tauri y su capa wry a src-tauri/vendor para aplicarles el parche de Sombra
# (pestañas sin rastros de Tauri). Ver src-tauri/vendor/PARCHE.md.
# Uso: tools/vendor-tauri.sh <versión tauri> <versión tauri-runtime-wry>
set -e
TV="${1:-2.12.7}"; RV="${2:-2.12.5}"
R=$(ls -d "$HOME"/.cargo/registry/src/index.crates.io-*/ | head -1)
D="$(dirname "$0")/../src-tauri/vendor"
mkdir -p "$D"
rm -rf "$D/tauri" "$D/tauri-runtime-wry"
cp -r "$R/tauri-$TV" "$D/tauri"
cp -r "$R/tauri-runtime-wry-$RV" "$D/tauri-runtime-wry"
echo "copiado tauri $TV y tauri-runtime-wry $RV (falta aplicar el parche)"
