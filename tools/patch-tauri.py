"""Aplica el parche de Sombra a la copia de Tauri en src-tauri/vendor.

Las pestañas (vistas cuyo nombre empieza por "tab-") se crean "desnudas": sin los
scripts de Tauri (window.__TAURI_INTERNALS__, window.isTauri...), sin sus protocolos
internos (ipc://, tauri://) y sin el canal de mensajes de wry (window.ipc). Así una web
no puede saber que está dentro de una app Tauri ni hablar con Sombra.
La interfaz de Sombra (vista "ui") no cambia.

Uso, tras tools/vendor-tauri.sh:  python tools/patch-tauri.py
Falla con un error claro si el código de Tauri ha cambiado y el parche ya no encaja.
"""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1] / "src-tauri" / "vendor"
MARK = "SOMBRA:"


def patch(rel, pairs):
    p = root / rel
    s = p.read_text(encoding="utf-8")
    if MARK in s:
        print(f"{rel}: ya parcheado")
        return
    for old, new in pairs:
        if s.count(old) != 1:
            sys.exit(f"ERROR: en {rel} no se encuentra (o se repite) el fragmento:\n{old}")
        s = s.replace(old, new)
    p.write_text(s, encoding="utf-8", newline="")
    print(f"{rel}: parcheado")


patch("tauri/src/manager/webview.rs", [
    (
        "    let mut webview_attributes = pending.webview_attributes;\n",
        "    let mut webview_attributes = pending.webview_attributes;\n"
        "\n"
        "    // SOMBRA: las pestañas (\"tab-*\") no llevan nada de Tauri: ni scripts, ni protocolos.\n"
        "    let sombra_bare = label.starts_with(\"tab-\");\n",
    ),
    (
        "    // Prepend `all_initialization_scripts` to `webview_attributes.initialization_scripts`\n",
        "    // SOMBRA: en las pestañas solo quedan los scripts propios de la app.\n"
        "    if sombra_bare {\n"
        "      all_initialization_scripts.clear();\n"
        "    }\n"
        "    // Prepend `all_initialization_scripts` to `webview_attributes.initialization_scripts`\n",
    ),
    (
        "    for (uri_scheme, protocol) in &*self.uri_scheme_protocols.lock().unwrap() {\n",
        "    for (uri_scheme, protocol) in self\n"
        "      .uri_scheme_protocols\n"
        "      .lock()\n"
        "      .unwrap()\n"
        "      .iter()\n"
        "      .filter(|_| !sombra_bare)\n"
        "    {\n",
    ),
    (
        "    if !registered_scheme_protocols.contains(&\"tauri\".into()) {\n",
        "    if !sombra_bare && !registered_scheme_protocols.contains(&\"tauri\".into()) {\n",
    ),
    (
        "    if !registered_scheme_protocols.contains(&\"ipc\".into()) {\n",
        "    if !sombra_bare && !registered_scheme_protocols.contains(&\"ipc\".into()) {\n",
    ),
    (
        "    pending.ipc_handler = Some(crate::ipc::protocol::message_handler(\n"
        "      manager.manager_owned(),\n"
        "    ));\n",
        "    // SOMBRA: las pestañas no tienen canal de mensajes con la app.\n"
        "    if !label.starts_with(\"tab-\") {\n"
        "      pending.ipc_handler = Some(crate::ipc::protocol::message_handler(\n"
        "        manager.manager_owned(),\n"
        "      ));\n"
        "    }\n",
    ),
])

patch("tauri-runtime-wry/src/lib.rs", [
    (
        "  webview_builder = webview_builder.with_ipc_handler(create_ipc_handler(\n"
        "    window_id_for_ipc,\n"
        "    id,\n"
        "    context.clone(),\n"
        "    label.clone(),\n"
        "    ipc_handler,\n"
        "  ));\n",
        "  // SOMBRA: sin canal de mensajes, wry no crea window.ipc ni su manejador.\n"
        "  if ipc_handler.is_some() {\n"
        "    webview_builder = webview_builder.with_ipc_handler(create_ipc_handler(\n"
        "      window_id_for_ipc,\n"
        "      id,\n"
        "      context.clone(),\n"
        "      label.clone(),\n"
        "      ipc_handler,\n"
        "    ));\n"
        "  }\n",
    ),
])
