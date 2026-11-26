// Sombra - pestañas: cada web se abre en su propia vista, aislada y sin acceso a Sombra.
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use crate::state::{Shared, TabInfo};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::webview::{PageLoadEvent, PermissionResponse, WebviewBuilder};
use tauri::{AppHandle, LogicalPosition, LogicalSize, Manager, WebviewUrl};

pub struct Engine {
    pub args: String,
    pub proxy_port: u16,
    pub data_dir: PathBuf,
    /// Nombre aleatorio (por sesión) del contador anti-huella dentro de cada página.
    pub fp_key: String,
}

pub static ENGINE: OnceLock<Engine> = OnceLock::new();

/// Argumentos del motor (WebView2/Chromium): proxy obligatorio, sin WebRTC por fuera de Tor,
/// sin QUIC (UDP), sin precargas ni conexiones de fondo de Microsoft.
pub fn browser_args(proxy_port: u16) -> String {
    [
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,NetworkPrediction,InterestFeedContentSuggestions,OptimizationHints,MediaRouter,WebRtcHideLocalIpsWithMdns,AutofillServerCommunication,msEdgeEnhanceSecurityMode,msImplicitSignin,msDiagnosticDataForwarding",
        &format!("--proxy-server=socks5://127.0.0.1:{proxy_port}"),
        "--proxy-bypass-list=<-loopback>",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic",
        "--dns-prefetch-disable",
        "--no-pings",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-sync",
        "--disable-breakpad",
        "--no-first-run",
    ]
    .join(" ")
}

/// Configuración común del motor para la interfaz y todas las pestañas.
/// Windows (WebView2): argumentos de Chromium con el proxy. Linux/Android (WebKit): proxy nativo.
pub fn engine_setup(b: WebviewBuilder<tauri::Wry>) -> WebviewBuilder<tauri::Wry> {
    let eng = ENGINE.get().expect("motor no iniciado");
    let b = b.incognito(true).data_directory(eng.data_dir.clone());
    #[cfg(windows)]
    {
        b.additional_browser_args(&eng.args)
    }
    #[cfg(not(windows))]
    {
        let u = url::Url::parse(&format!("socks5://127.0.0.1:{}", eng.proxy_port)).expect("url proxy");
        b.proxy_url(u)
    }
}

pub fn label(id: u32) -> String {
    format!("tab-{id}")
}

/// Script que se ejecuta en cada página (y en cada iframe) antes que el código de la web.
fn privacy_script(fp_key: &str) -> String {
    r#"(() => {
  try {
    const hide = (o, k) => { try { delete o[k]; } catch (e) {} try { Object.defineProperty(o, k, { value: undefined, configurable: true }); } catch (e) {} };
    // Las pestañas no tienen ninguna conexión con Sombra (Tauri parcheado, ver
    // vendor/PARCHE.md). En Windows, WebView2 añade window.chrome.webview: se quita.
    try { if (window.chrome && window.chrome.webview) delete window.chrome.webview; } catch (e) {}
    const J = JSON.stringify;
    // Contador de intentos de huella digital (lo lee Sombra con page_privacy).
    const st = { fp: 0, kinds: {} };
    // Contraseñas enviadas, esperando a que Sombra las recoja.
    const pend = [];
    const api = Object.freeze({
      read: () => J(st),
      take: () => { const out = []; for (const it of pend) { out.push({ user: it.user, pass: it.pass }); it.done(); } pend.length = 0; return J({ host: location.hostname, items: out }); },
    });
    try { Object.defineProperty(window, '__FPKEY__', { value: api }); } catch (e) {}
    // Contraseñas: al enviar un formulario con contraseña, Sombra pregunta si se guarda.
    // La página no avisa a nadie: Sombra pasa a recoger el aviso cada poco (take). La web
    // se identifica en Sombra por la dirección real de la pestaña, no por lo que diga la página.
    if (window.top === window) {
      const fsubmit = HTMLFormElement.prototype.submit;
      const sent = new Map();
      const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
      const userOf = (root, pw) => {
        const ins = [...root.querySelectorAll('input')].filter(e => vis(e) && /^(text|email|tel)$/.test(e.type) && e.value && (e.compareDocumentPosition(pw) & 4)).reverse();
        const u = ins.find(e => /user|mail|login|name|usuario|correo/i.test((e.name || '') + (e.id || '') + (e.autocomplete || ''))) || ins[0];
        return u ? u.value.slice(0, 200) : '';
      };
      // Devuelve una promesa que se cumple cuando Sombra ha recogido el aviso (o null).
      const grab = (t) => {
        try {
          const root = (t && t.closest && t.closest('form')) || document;
          const pws = [...root.querySelectorAll('input[type=password]')].filter(e => e.value && vis(e));
          if (!pws.length) return null;
          const pass = pws[pws.length - 1].value;
          if (pass.length > 512) return null;
          const user = userOf(root, pws[0]);
          const k = user + '\n' + pass;
          if (!sent.has(k)) sent.set(k, new Promise(done => pend.push({ user, pass, done })));
          return sent.get(k);
        } catch (e) { return null; }
      };
      // Si el formulario va a cambiar de página, se espera un momento (máx. 1,5 s) a que el
      // aviso llegue a Sombra y luego se envía igual que lo habría enviado la web.
      addEventListener('submit', e => {
        const form = e.target;
        const p = grab(form);
        if (!p || e.defaultPrevented || !(form instanceof HTMLFormElement)) return;
        e.preventDefault();
        const sub = e.submitter;
        Promise.race([p, new Promise(r => setTimeout(r, 1500))]).then(() => {
          if (sub && sub.name) { const h = document.createElement('input'); h.type = 'hidden'; h.name = sub.name; h.value = sub.value; form.appendChild(h); }
          fsubmit.call(form);
        });
      });
      const LOGIN = /log|sign|entr|acced|inici|regist|contin|next|siguiente|submit|enviar|crear|create|join/i;
      addEventListener('click', e => {
        const b = e.target && e.target.closest && e.target.closest('button,input[type=submit],[role=button]');
        if (b && (b.type === 'submit' || LOGIN.test((b.textContent || '') + (b.value || '') + (b.getAttribute('aria-label') || '')))) grab(b);
      }, true);
      addEventListener('keydown', e => { if (e.key === 'Enter' && e.target && e.target.type === 'password') grab(e.target); }, true);
    }
    // WebRTC fuera: es la fuga de IP más típica.
    ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription','RTCIceCandidate','RTCRtpReceiver','RTCRtpSender'].forEach(k => hide(window, k));
    // Ruido en canvas y aviso de intentos de huella digital.
    const note = (k) => { st.fp++; st.kinds[k] = (st.kinds[k] || 0) + 1; };
    const noise = (data) => { for (let i = 0; i < data.length; i += 97) { data[i] = data[i] ^ 1; } };
    const C2D = window.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
    if (C2D && C2D.getImageData) {
      const orig = C2D.getImageData;
      C2D.getImageData = function () { note('canvas'); const r = orig.apply(this, arguments); try { noise(r.data); } catch (e) {} return r; };
    }
    const HC = window.HTMLCanvasElement && HTMLCanvasElement.prototype;
    if (HC) {
      for (const m of ['toDataURL', 'toBlob']) {
        const orig = HC[m];
        if (!orig) continue;
        HC[m] = function () {
          note('canvas');
          try {
            const ctx = this.getContext && this.getContext('2d');
            if (ctx && this.width && this.height) {
              const d = C2D.getImageData.call(ctx, 0, 0, Math.min(this.width, 64), Math.min(this.height, 64));
              ctx.putImageData(d, 0, 0);
            }
          } catch (e) {}
          return orig.apply(this, arguments);
        };
      }
    }
    for (const G of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
      if (!G) continue;
      const orig = G.prototype.getParameter;
      G.prototype.getParameter = function (p) {
        if (p === 37445) { note('webgl'); return 'Google Inc.'; }
        if (p === 37446) { note('webgl'); return 'ANGLE (Generic GPU)'; }
        return orig.apply(this, arguments);
      };
    }
    const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (AC) {
      const orig = AC.prototype.startRendering;
      AC.prototype.startRendering = function () { note('audio'); return orig.apply(this, arguments); };
    }
    if (document.fonts && document.fonts.check) {
      const orig = document.fonts.check.bind(document.fonts);
      let n = 0;
      document.fonts.check = function () { if (++n === 20) note('fuentes'); return orig.apply(null, arguments); };
    }
    if (navigator.getBattery) hide(Navigator.prototype, 'getBattery');
    try { Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get: () => 4 }); } catch (e) {}
    try { Object.defineProperty(Navigator.prototype, 'deviceMemory', { get: () => 8 }); } catch (e) {}
  } catch (e) {}
})();"#
        .replace("__FPKEY__", fp_key)
}

/// Convierte lo escrito en la barra en una URL (o búsqueda).
pub fn normalize_input(input: &str, search: &str) -> String {
    let t = input.trim();
    if t.is_empty() {
        return String::new();
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower == "about:blank" {
        return t.to_string();
    }
    if !t.contains(' ') && (t.contains('.') || lower.starts_with("localhost")) && !t.starts_with('.') {
        return format!("https://{t}");
    }
    let q: String = url::form_urlencoded::byte_serialize(t.as_bytes()).collect();
    if search.contains("%s") {
        search.replace("%s", &q)
    } else {
        format!("{search}{q}")
    }
}

fn allowed_scheme(u: &url::Url) -> bool {
    matches!(u.scheme(), "http" | "https" | "about" | "blob" | "data")
}

pub fn emit_tabs(sh: &Shared) {
    let t = sh.tabs.lock();
    sh.emit("tabs", serde_json::json!({ "list": t.list, "active": t.active }));
}

/// Cambia una pestaña y avisa a la interfaz solo si algo ha cambiado de verdad
/// (algunas webs cambian el título o recargan sin parar: así no parpadea).
fn update_tab(sh: &Shared, id: u32, f: impl FnOnce(&mut TabInfo)) {
    let changed = {
        let mut t = sh.tabs.lock();
        match t.list.iter_mut().find(|x| x.id == id) {
            Some(tab) => {
                let before = tab.clone();
                f(tab);
                *tab != before
            }
            None => false,
        }
    };
    if changed {
        sh.refresh_top_hosts();
        emit_tabs(sh);
    }
}

/// Crea una pestaña (vacía o con una URL) y la activa.
pub async fn new_tab(app: &AppHandle, sh: &Arc<Shared>, url: Option<String>) -> anyhow::Result<u32> {
    let id = {
        let mut t = sh.tabs.lock();
        let id = t.next;
        t.next += 1;
        t.list.push(TabInfo { id, url: String::new(), title: "Nueva pestaña".into(), loading: false, has_view: false });
        t.active = Some(id);
        id
    };
    if let Some(u) = url.filter(|u| !u.is_empty()) {
        navigate(app, sh, id, &u).await?;
    }
    layout(app, sh);
    emit_tabs(sh);
    Ok(id)
}

/// Navega una pestaña a una URL. Crea la vista web si todavía no existe.
pub async fn navigate(app: &AppHandle, sh: &Arc<Shared>, id: u32, raw: &str) -> anyhow::Result<()> {
    let search = sh.settings.lock().search.clone();
    let target = normalize_input(raw, &search);
    let parsed = url::Url::parse(&target).map_err(|e| anyhow::anyhow!("Dirección no válida: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("Solo se permiten direcciones http y https");
    }
    // Cada búsqueda sale por un circuito de Tor nuevo: el buscador no puede
    // relacionar una búsqueda con la anterior.
    let prefix = search.split("%s").next().unwrap_or(&search);
    if prefix.len() > 8 && target.starts_with(prefix) {
        if let Some(h) = parsed.host_str() {
            sh.tor.rotate_host(h);
        }
    }
    // Se marca la web como "abierta por ti" ANTES de pedirla, para que el bloqueador no la corte.
    update_tab(sh, id, |t| {
        t.url = parsed.to_string();
        t.loading = true;
    });
    if let Some(wv) = app.get_webview(&label(id)) {
        wv.navigate(parsed)?;
        return Ok(());
    }
    create_view(app, sh, id, parsed)?;
    update_tab(sh, id, |t| t.has_view = true);
    layout(app, sh);
    Ok(())
}

fn create_view(app: &AppHandle, sh: &Arc<Shared>, id: u32, url: url::Url) -> anyhow::Result<()> {
    let eng = ENGINE.get().ok_or_else(|| anyhow::anyhow!("motor no iniciado"))?;
    let window = app.get_window("main").ok_or_else(|| anyhow::anyhow!("sin ventana"))?;

    let sh_nav = sh.clone();
    let sh_load = sh.clone();
    let sh_title = sh.clone();
    let sh_new = sh.clone();
    let app_new = app.clone();
    let app_load = app.clone();

    let builder = engine_setup(WebviewBuilder::new(label(id), WebviewUrl::External(url)))
        .initialization_script_for_all_frames(privacy_script(&eng.fp_key))
        .on_permission_request(|_, _| PermissionResponse::Deny)
        .on_navigation(move |u| {
            if !allowed_scheme(u) {
                return false;
            }
            // La dirección de la pestaña NO se cambia aquí: este aviso llega también de los
            // recuadros de dentro de la página (anuncios, CAPTCHAs...), y la barra mostraba
            // su dirección. La dirección real llega en on_page_load, que es solo de la página.
            let _ = &sh_nav;
            true
        })
        .on_page_load(move |wv, payload| {
            let url = payload.url().to_string();
            match payload.event() {
                PageLoadEvent::Started => {
                    if sh_load.tabs.lock().active == Some(id) {
                        sh_load.stats.page_blocked.store(0, Ordering::Relaxed);
                    }
                    update_tab(&sh_load, id, |t| {
                        t.loading = true;
                        t.url = url;
                    });
                }
                PageLoadEvent::Finished => {
                    let mut title = String::new();
                    update_tab(&sh_load, id, |t| {
                        t.loading = false;
                        t.url = url.clone();
                        title = t.title.clone();
                    });
                    sh_load.add_history(&url, &title);
                    let sh2 = sh_load.clone();
                    let app2 = app_load.clone();
                    let label = wv.label().to_string();
                    tauri::async_runtime::spawn(async move {
                        apply_cosmetics(&app2, &sh2, &label, &url).await;
                        tokio::time::sleep(Duration::from_millis(2500)).await;
                        apply_cosmetics(&app2, &sh2, &label, &url).await;
                    });
                }
            }
        })
        .on_document_title_changed(move |_, title| {
            let mut url = String::new();
            update_tab(&sh_title, id, |t| {
                url = t.url.clone();
                t.title = if title.trim().is_empty() { t.url.clone() } else { title.clone() };
            });
            sh_title.set_history_title(&url, &title);
        })
        .on_new_window(move |u, _| {
            // Las ventanas emergentes se abren como pestañas normales (o se descartan).
            if matches!(u.scheme(), "http" | "https") {
                let app = app_new.clone();
                let sh = sh_new.clone();
                let s = u.to_string();
                tauri::async_runtime::spawn(async move {
                    let _ = new_tab(&app, &sh, Some(s)).await;
                });
            }
            tauri::webview::NewWindowResponse::Deny
        });

    let (x, y, w, h) = sh.tabs.lock().rect;
    window.add_child(builder, LogicalPosition::new(x, y), LogicalSize::new(w.max(1.0), h.max(1.0)))?;
    Ok(())
}

/// Oculta anuncios incrustados que no se pueden bloquear por red.
async fn apply_cosmetics(app: &AppHandle, sh: &Arc<Shared>, label: &str, url: &str) {
    if !sh.blocking_enabled.load(Ordering::Relaxed) {
        return;
    }
    let Some(b) = sh.blocker() else { return };
    let (mut css, generichide, exceptions) = b.cosmetic_css(url);
    if !generichide {
        let js = r#"(() => { const c = new Set(), i = new Set();
          for (const e of document.querySelectorAll('[class],[id]')) { if (e.id) i.add(e.id); for (const k of e.classList) c.add(k); if (c.size > 6000) break; }
          return JSON.stringify({ c: [...c], i: [...i] }); })()"#;
        if let Ok(v) = eval_label(app, label, js.to_string()).await {
            let classes: Vec<String> = serde_json::from_value(v["c"].clone()).unwrap_or_default();
            let ids: Vec<String> = serde_json::from_value(v["i"].clone()).unwrap_or_default();
            let g = b.generic_css(&classes, &ids, &exceptions);
            if !g.is_empty() {
                css.push('\n');
                css.push_str(&g);
            }
        }
    }
    if css.is_empty() {
        return;
    }
    let js = format!(
        r#"(() => {{ const css = {}; let s = document.getElementById('sombra-cosmetic');
          if (!s) {{ s = document.createElement('style'); s.id = 'sombra-cosmetic'; (document.head || document.documentElement).appendChild(s); }}
          s.textContent = css; return 'ok'; }})()"#,
        serde_json::to_string(&css).unwrap_or_else(|_| "''".into())
    );
    let _ = eval_label(app, label, js).await;
}

/// Ejecuta JavaScript en una pestaña y devuelve el resultado como JSON.
pub async fn eval_label(app: &AppHandle, label: &str, js: String) -> anyhow::Result<serde_json::Value> {
    let wv = app.get_webview(label).ok_or_else(|| anyhow::anyhow!("La pestaña no tiene ninguna web abierta"))?;
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let tx = Mutex::new(Some(tx));
    wv.eval_with_callback(js, move |res| {
        if let Some(t) = tx.lock().take() {
            let _ = t.send(res);
        }
    })?;
    let raw = tokio::time::timeout(Duration::from_secs(15), rx).await??;
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or(serde_json::Value::String(raw));
    if let serde_json::Value::String(inner) = &v {
        if let Ok(x) = serde_json::from_str::<serde_json::Value>(inner) {
            return Ok(x);
        }
    }
    Ok(v)
}

pub async fn eval_tab(app: &AppHandle, id: u32, js: String) -> anyhow::Result<serde_json::Value> {
    eval_label(app, &label(id), js).await
}

/// Coloca la pestaña activa en la zona de contenido y oculta las demás (pestañas dormidas).
pub fn layout(app: &AppHandle, sh: &Shared) {
    let (rect, active, ids) = {
        let t = sh.tabs.lock();
        (t.rect, t.active, t.list.iter().map(|x| x.id).collect::<Vec<_>>())
    };
    let (x, y, w, h) = rect;
    for id in ids {
        if let Some(wv) = app.get_webview(&label(id)) {
            if Some(id) == active && w > 1.0 && h > 1.0 {
                let _ = wv.set_position(LogicalPosition::new(x, y));
                let _ = wv.set_size(LogicalSize::new(w, h));
                let _ = wv.show();
            } else {
                let _ = wv.hide();
            }
        }
    }
}

pub fn activate(app: &AppHandle, sh: &Shared, id: u32) {
    {
        let mut t = sh.tabs.lock();
        if t.list.iter().any(|x| x.id == id) {
            t.active = Some(id);
        }
    }
    sh.stats.page_blocked.store(0, Ordering::Relaxed);
    layout(app, sh);
    emit_tabs(sh);
}

pub async fn close(app: &AppHandle, sh: &Arc<Shared>, id: u32) -> anyhow::Result<()> {
    if let Some(wv) = app.get_webview(&label(id)) {
        let _ = wv.close();
    }
    let empty = {
        let mut t = sh.tabs.lock();
        let pos = t.list.iter().position(|x| x.id == id);
        if let Some(p) = pos {
            t.list.remove(p);
            if t.active == Some(id) {
                let n = t.list.len();
                t.active = if n == 0 { None } else { Some(t.list[p.min(n - 1)].id) };
            }
        }
        t.list.is_empty()
    };
    sh.refresh_top_hosts();
    if empty {
        new_tab(app, sh, None).await?;
    } else {
        layout(app, sh);
        emit_tabs(sh);
    }
    Ok(())
}

/// Inicio: la pestaña vuelve a la pantalla de inicio. Se cierra su vista web,
/// así la web deja de ejecutarse y no queda nada suyo en memoria.
/// La pestaña recibe un número nuevo (en el mismo sitio de la barra): así la vista
/// vieja, que se cierra en segundo plano, no choca con la nueva ni puede cambiar
/// la pestaña con eventos que lleguen tarde.
pub fn go_home(app: &AppHandle, sh: &Shared, id: u32) {
    if let Some(wv) = app.get_webview(&label(id)) {
        let _ = wv.close();
    }
    {
        let mut t = sh.tabs.lock();
        let new_id = t.next;
        let Some(tab) = t.list.iter_mut().find(|x| x.id == id) else { return };
        *tab = TabInfo { id: new_id, url: String::new(), title: "Nueva pestaña".into(), loading: false, has_view: false };
        t.next += 1;
        if t.active == Some(id) {
            t.active = Some(new_id);
        }
    }
    sh.refresh_top_hosts();
    sh.stats.page_blocked.store(0, Ordering::Relaxed);
    emit_tabs(sh);
}

pub fn active_id(sh: &Shared) -> Option<u32> {
    sh.tabs.lock().active
}

/// Espera a que la pestaña termine de cargar (máximo `secs` segundos).
pub async fn wait_loaded(sh: &Shared, id: u32, secs: u64) {
    tokio::time::sleep(Duration::from_millis(400)).await;
    for _ in 0..(secs * 4) {
        let loading = sh.tabs.lock().list.iter().find(|t| t.id == id).map(|t| t.loading).unwrap_or(false);
        if !loading {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
