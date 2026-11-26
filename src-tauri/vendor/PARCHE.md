# Tauri parcheado para Sombra

Aquí hay una copia de **tauri 2.12.7** y **tauri-runtime-wry 2.12.5** (MIT/Apache-2.0,
sus licencias van dentro de cada carpeta) con un parche pequeño. `Cargo.toml` las usa
en lugar de las originales (`[patch.crates-io]`).

## Qué cambia

Las vistas cuyo nombre empieza por `tab-` (las pestañas con webs) se crean **desnudas**:

- sin los scripts de Tauri (`window.isTauri`, `window.__TAURI_INTERNALS__`…);
- sin sus protocolos internos (`ipc://`, `tauri://`);
- sin el canal de mensajes (`window.ipc` en Windows, `webkit.messageHandlers.ipc` en Linux).

Así una web no puede saber que está dentro de una app Tauri ni enviar nada a Sombra.
La interfaz de Sombra (vista `ui`) funciona igual que con Tauri normal.

Lo que Sombra necesita de las pestañas (aviso de contraseña enviada, contador de huella
digital) lo **recoge Sombra** ejecutando código en la página; la página nunca inicia nada.

Todos los cambios llevan el comentario `SOMBRA:`.

## Cómo actualizar Tauri

1. Sube la versión de `tauri` en `Cargo.toml` y ejecuta `cargo update -p tauri` sin el
   bloque `[patch.crates-io]` (coméntalo) para que se descargue.
2. `bash tools/vendor-tauri.sh <versión tauri> <versión tauri-runtime-wry>`
   (las versiones exactas salen en `Cargo.lock`).
3. `python tools/patch-tauri.py`. Si dice que un fragmento no encaja, Tauri ha cambiado
   ese código: hay que adaptar el parche a mano.
4. Vuelve a activar `[patch.crates-io]`, compila y pasa `tools/selftest-cred.sh`: la línea
   `SELFTEST rastros` debe salir toda en `false` y con la lista `g` vacía o solo
   `UserMessageHandlersNamespace` (normal en cualquier WebKit).
