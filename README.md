# Sombra

Navegador **ligero y privado**: sin publicidad, con **Tor integrado**, elección de país y una puerta de control para que **cualquier IA** (Claude, ChatGPT, una IA local...) navegue por ti.

> Versión 0.1 (primera prueba). Licencia **GPL-3.0-or-later**: libre y gratis. Quien lo modifique y lo comparta tiene que publicar su código.

## Qué hace

| Función | Cómo |
|---|---|
| Dos modos | **Modo normal** (botón +, `Ctrl+T`): conexión directa y rápida para el día a día; sesiones, cookies e historial se guardan (perfil propio del motor), con bloqueo de anuncios y rastreadores y solo HTTPS. **Modo Sombra** (botón de la máscara, `Ctrl+Mayús+N`): todo por Tor, anti-huella, niveles de seguridad y nada se guarda. La pestaña y la barra se tiñen de morado en modo Sombra. Los dos modos nunca comparten cookies, caché ni sesiones. Un .onion abierto desde el modo normal se abre en una pestaña Sombra. En Ajustes se puede elegir que Sombra arranque en modo Sombra. |
| Certificado digital y AutoFirma | Para las webs de la administración (Hacienda, Seguridad Social, DGT...) en una **pestaña normal**: Windows te deja elegir tu certificado y Sombra abre AutoFirma cuando la web lo pide (solo esa app externa; durante 10 minutos la web puede hablar con AutoFirma en tu PC, y solo por los puertos que indica el propio enlace de AutoFirma). Ajustes → *Mis certificados* abre el gestor de Windows para importar tu .p12/.pfx (la contraseña la escribes tú en la ventana de Windows). En **modo Sombra** el certificado nunca se envía y no se abre ninguna app externa, porque dirían quién eres: Sombra ofrece abrir la web en una pestaña normal. |
| IP oculta (modo Sombra) | Todo el tráfico de las pestañas Sombra sale por Tor (Arti, integrado). Si Tor no funciona, **no hay conexión** (nunca usa la directa). |
| País de salida | Selector en la barra: Alemania, Francia, EE. UU., etc. |
| Sin publicidad | EasyList, EasyPrivacy, EasyList España y lista de avisos de cookies (motor adblock-rust). Bloqueo por red y ocultación de huecos. En YouTube se quita la lista de anuncios de los datos del vídeo (y si aun así sale uno, se salta). |
| Niveles de seguridad | Como Tor Browser: *Normal*, *Más seguro* (sin JavaScript en webs http, JavaScript sin JIT ni WebAssembly, sin WebGL ni vídeos que se reproducen solos) y *El más seguro* (sin JavaScript en ninguna web). En el panel (☰) se puede permitir JavaScript en una web concreta. |
| Solo HTTPS | Como Tor Browser: las webs se abren siempre cifradas (https), también al pulsar un enlace. Antes de abrir una web http, Sombra comprueba por Tor que su https funciona de verdad (certificado válido); si no, muestra un aviso con *Volver* o *Continuar sin cifrar* (solo para esa web y hasta cerrar Sombra). Nada sale sin cifrar por el puerto 80 salvo lo que tú aceptes. Se puede quitar en Ajustes. |
| Sin fugas | WebRTC desactivado, sin QUIC/UDP, DNS por Tor, red local inaccesible desde las webs. |
| Nada se guarda (modo Sombra) | Historial, cookies y caché solo en memoria; se borran al cerrar. |
| Anti-huella digital | Detecta y engaña intentos de identificar tu equipo (canvas, WebGL, audio, fuentes). |
| Control para IAs | API local con token, aviso de cada IA nueva, permiso antes de enviar formularios, botón "Cortar IA" y registro de intrusos. |
| Favoritos | Barra de favoritos y accesos rápidos en la pestaña nueva (clic derecho para quitar). |
| 13 idiomas | Español, English, Français, Deutsch, Italiano, Português, Català, Nederlands, Polski, Русский, 中文, 日本語, العربية (de derecha a izquierda). Automático según el sistema. |
| Buscador privado | Por defecto **DuckDuckGo .onion**: la búsqueda no sale de la red Tor, así que ni el buscador ni ningún nodo sabe quién busca. Cada búsqueda va por un circuito nuevo y no se guarda en el historial. Se puede cambiar por DuckDuckGo, Startpage, Brave, Mojeek, Qwant, Ecosia, Google, Bing o uno propio; Sombra avisa del nivel de privacidad de cada uno. |
| Aislamiento por web | Cada dominio usa sus propios circuitos de Tor: dos webs no pueden relacionarte por compartir circuito. |
| Ajustes | Idioma, tema (oscuro/claro/sistema), color, tamaño de letra, modo compacto, barra de favoritos y buscador. |
| Historial | Tú eliges: no guardar nada, solo mientras Sombra está abierto (por defecto) o guardar en el equipo. Con buscador y borrado al cerrar. `Ctrl+H`. |
| Contraseñas | Bóveda cifrada en tu equipo (XChaCha20-Poly1305 + Argon2id), nunca en la nube. Al entrar o registrarte en una web pregunta *Guardar / Ahora no / Nunca en esta web*; la llave de la barra la rellena solo cuando tú pulsas. Generador, bloqueo automático y recuperación con frase de 12 palabras. Las IAs nunca ven las contraseñas. |
| Limpiador | Borra historial, caché y cookies, identidad de Tor, registro, contadores o pestañas con un botón. `Ctrl+Mayús+Supr`. |

**Añadir un idioma:** copia `ui/locales/en.js`, tradúcelo, añádelo en `ui/index.html` y en `LANG_NAMES` (`ui/i18n.js`), y comprueba con `node tools/check-locales.mjs`.

## Usarlo con una IA (MCP)

1. Abre Sombra → panel (☰) → activa **Permitir que una IA use Sombra**.
2. Añade el servidor MCP a tu IA. Ejemplo para Claude Code / Claude Desktop:

```json
{
  "mcpServers": {
    "sombra": {
      "command": "node",
      "args": ["D:/Escritorio/Sombra/mcp/sombra-mcp.mjs"],
      "env": { "SOMBRA_CLIENT": "Claude" }
    }
  }
}
```

3. Dile a la IA: *"Entra en tal web a través de Sombra y..."*. La primera vez Sombra te pedirá permiso.

**Otras IAs o programas propios:** API HTTP en `http://127.0.0.1:<puerto>/v1/<acción>` (POST JSON) con la cabecera `Authorization: Bearer <token>`. Puerto y token están en `%LOCALAPPDATA%\Sombra\control.json` (Linux: `~/.local/share/Sombra/control.json`). Acciones: `status, open, read, click, type, select, scroll, back, forward, reload, tabs, switch_tab, close_tab, country, new_identity`.

Reglas de seguridad (para todas las IAs): las **contraseñas** y los **CAPTCHA** los pone el usuario; **enviar formularios** necesita su permiso.

## Compilar

Requisitos: Rust y, en Windows, Visual Studio Build Tools (C++).

```
cd src-tauri
cargo build --release
```

Instalador (opcional): `cargo install tauri-cli --version "^2"` y luego `cargo tauri build`.

## Limitaciones conocidas (0.1)

- Por Tor algunas webs van más lentas y muestran más CAPTCHAs.
- Las webs pueden notar que el motor es WebView2/Chromium. Contra la huella digital, el Tor Browser oficial sigue siendo más fuerte.
- Huella reforzada (Ajustes, activada por defecto): idioma inglés, hora UTC, tamaño de página redondeado, sin listas de voces ni dispositivos, ruido en canvas/WebGL/audio distinto en cada web y sesión, y en Linux las webs ven Safari en Mac. Limitaciones: el tamaño real del monitor se puede leer con reglas CSS, los tipos de letra delatan el sistema, los Workers ven los núcleos reales y, en Windows, también la zona horaria real. Detalles y comparación con otros navegadores en `AUDITORIA.md`.
- Anuncios de YouTube: funcionan quitando los anuncios de los datos del vídeo; si YouTube cambia su forma de mandarlos, puede dejar de funcionar hasta actualizar Sombra.
- Niveles de seguridad: cuando una web necesita JavaScript al revés que la anterior, la pestaña se abre de nuevo (se pierde el botón Atrás de esa pestaña). Permitir JavaScript en una web también lo permite en los recuadros que esa web incluya.
- Modo normal en Linux: la hora que ven las webs es UTC si la huella reforzada está activada (el motor solo admite una zona para todo el programa), y WebRTC depende de que WebKitGTK lo traiga compilado. En Windows no pasa.
- Certificado digital en Linux: todavía no (el motor WebKit necesita que Sombra le entregue el certificado). AutoFirma sí se abre si está instalada.
- Linux: la ventana lleva su propia barra (− □ ×) en lugar de la del sistema.
- Las pestañas no tienen ninguna conexión con Sombra ni rastros de Tauri (Tauri va parcheado, ver `src-tauri/vendor/PARCHE.md`). Aun así, una web siempre puede notar que el motor es una vista web de sistema y no un navegador conocido.
- Contraseñas: si olvidas la contraseña maestra **y** pierdes las 12 palabras, no hay forma de recuperarlas (así nadie más puede).
- Previsto: favoritos e historial dentro de la bóveda, recuperación con llave USB / otro dispositivo / personas de confianza, versión Android.

## Créditos

Tor/Arti (The Tor Project, MIT/Apache-2.0), adblock-rust (Brave, MPL-2.0), listas EasyList (GPL-3.0/CC BY-SA 3.0), Tauri (MIT/Apache-2.0; copia con un pequeño parche en `src-tauri/vendor`).
