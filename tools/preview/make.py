"""Genera tools/preview/index.html: la interfaz real con Tauri simulado, para revisarla en un navegador.

Uso: python tools/preview/make.py  y luego servir la carpeta del proyecto:
     python -m http.server 18791 --bind 127.0.0.1  ->  http://127.0.0.1:18791/tools/preview/index.html?lang=es&theme=dark
"""
import pathlib
import re
import time

root = pathlib.Path(__file__).resolve().parents[2]
html = (root / "ui" / "index.html").read_text(encoding="utf-8")
# "?v=..." obliga al navegador a cargar siempre la última versión.
v = str(time.time_ns())
html = re.sub(r'(src|href)="(?!http)([^"]+\.(?:js|css))"', r'\1="/ui/\2?v=' + v + '"', html)
html = html.replace('<script src="/ui/i18n.js', '<script src="/tools/preview/mock-tauri.js?v=' + v + '"></script>\n  <script src="/ui/i18n.js', 1)
(root / "tools" / "preview" / "index.html").write_text(html, encoding="utf-8")
print("ok")
