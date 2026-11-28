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
    /// Modo normal: su propio perfil del motor (carpeta que se conserva: sesiones y cookies),
    /// sus argumentos y su puerto del proxy (salida directa, sin Tor).
    pub normal_args: String,
    pub normal_port: u16,
    pub normal_dir: PathBuf,
    /// Nombre aleatorio (por sesión) del contador anti-huella dentro de cada página.
    pub fp_key: String,
    /// Semilla aleatoria (por sesión) del ruido de canvas, WebGL y audio. Nunca se expone.
    pub fp_seed: u32,
}

/// Linux con huella reforzada: las webs ven Safari en Mac. Es el mismo motor (WebKit), así que
/// casi todo encaja, y Safari en Mac tiene muchísimos usuarios (WebKitGTK en Ubuntu, muy pocos).
pub const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15";

pub static ENGINE: OnceLock<Engine> = OnceLock::new();

/// Argumentos del motor (WebView2/Chromium): proxy obligatorio, sin WebRTC por fuera de Tor,
/// sin QUIC (UDP), sin precargas ni conexiones de fondo de Microsoft.
pub fn browser_args(proxy_port: u16, strict: bool, level: u8) -> String {
    let proxy = format!("--proxy-server=socks5://127.0.0.1:{proxy_port}");
    let mut a: Vec<&str> = vec![
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,NetworkPrediction,InterestFeedContentSuggestions,OptimizationHints,MediaRouter,WebRtcHideLocalIpsWithMdns,AutofillServerCommunication,msEdgeEnhanceSecurityMode,msImplicitSignin,msDiagnosticDataForwarding",
        &proxy,
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
    ];
    // Huella reforzada: las webs se piden en inglés (cabecera Accept-Language).
    if strict {
        a.push("--accept-lang=en-US,en");
    }
    // Niveles "más seguro" y "el más seguro": JavaScript sin compilador JIT (ni WebAssembly),
    // sin WebGL y sin vídeos ni audios que se reproducen solos. Se aplica al abrir Sombra.
    if level >= 1 {
        a.extend(["--js-flags=--jitless", "--disable-3d-apis", "--autoplay-policy=user-gesture-required"]);
    }
    a.join(" ")
}

/// Argumentos del motor en modo normal: proxy de Sombra (bloqueador, solo HTTPS) con salida
/// directa. Sin QUIC (iría por UDP, sin pasar por el bloqueador). WebRTC sí funciona
/// (videollamadas), sin revelar las direcciones de la red local.
pub fn browser_args_normal(proxy_port: u16) -> String {
    let proxy = format!("--proxy-server=socks5://127.0.0.1:{proxy_port}");
    [
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,NetworkPrediction,InterestFeedContentSuggestions,OptimizationHints,MediaRouter,AutofillServerCommunication,msImplicitSignin,msDiagnosticDataForwarding",
        &proxy,
        "--proxy-bypass-list=<-loopback>",
        "--force-webrtc-ip-handling-policy=default_public_interface_only",
        "--webrtc-ip-handling-policy=default_public_interface_only",
        "--disable-quic",
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

/// ¿Es de modo Sombra esta pestaña?
pub fn tab_private(sh: &Shared, id: u32) -> bool {
    sh.tabs.lock().list.iter().find(|t| t.id == id).map(|t| t.private).unwrap_or(true)
}

/* ---------- niveles de seguridad: JavaScript por web ---------- */

/// ¿Puede esta dirección usar JavaScript? Normal: siempre. Más seguro: solo en webs cifradas
/// (https o .onion), como Tor Browser. El más seguro: nunca. En todos los niveles, salvo las
/// webs que el usuario haya permitido (y sus subdominios).
pub fn js_allowed(sh: &Shared, u: &url::Url, private: bool) -> bool {
    let s = sh.settings.lock();
    // Los niveles de seguridad son del modo Sombra; en modo normal las webs funcionan enteras.
    if s.security_level == 0 || !private {
        return true;
    }
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    if s.js_allow.iter().any(|a| host == *a || host.ends_with(&format!(".{a}"))) {
        return true;
    }
    s.security_level == 1 && (u.scheme() == "https" || host.ends_with(".onion"))
}

/* ---------- modo solo HTTPS ---------- */

/// ¿Hay que pasar esta dirección a https? Solo webs http normales: los .onion ya van cifrados
/// dentro de Tor y la red local está bloqueada de todas formas.
pub fn needs_upgrade(sh: &Shared, u: &url::Url) -> bool {
    if u.scheme() != "http" || !sh.settings.lock().https_only {
        return false;
    }
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    !host.is_empty() && !host.ends_with(".onion") && !crate::proxy::is_local(&host) && !sh.http_allowed(&host)
}

/// Versión https de una dirección http, si la web la tiene. Se comprueba de verdad: conexión
/// al puerto 443 por Tor (por el mismo circuito que usará la web) y saludo TLS con un
/// certificado válido para esa web. Si falla (puerto cerrado, sin cifrado, certificado caducado
/// o de otra web) o la dirección usa otro puerto, devuelve `None` y Sombra muestra el aviso.
async fn https_version(sh: &Shared, u: &url::Url, private: bool) -> Option<url::Url> {
    if u.port().is_some() {
        return None;
    }
    let host = u.host_str()?.to_ascii_lowercase();
    if !sh.https_known.lock().contains(&host) {
        if !tls_ok(sh, &host, private).await {
            return None;
        }
        sh.https_known.lock().insert(host);
    }
    let mut h = u.clone();
    h.set_scheme("https").ok()?;
    Some(h)
}

/// ¿Responde la web por https con un certificado válido? (raíces de Mozilla, webpki-roots).
async fn tls_ok(sh: &Shared, host: &str, private: bool) -> bool {
    static CFG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    let cfg = CFG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .ok()
            .map(|b| Arc::new(b.with_root_certificates(roots).with_no_client_auth()))
    });
    let (Some(cfg), Ok(name)) = (cfg.clone(), rustls::pki_types::ServerName::try_from(host.to_string())) else {
        return false;
    };
    let tls = tokio_rustls::TlsConnector::from(cfg);
    let check = async {
        if private {
            let (stream, _) = sh.tor.connect(host, 443).await.ok()?;
            tls.connect(name, stream).await.ok().map(|_| ())
        } else {
            // Modo normal: directo, sin llegar nunca a la red local.
            let stream = crate::proxy::connect_direct(host, 443, false).await?;
            tls.connect(name, stream).await.ok().map(|_| ())
        }
    };
    matches!(tokio::time::timeout(Duration::from_secs(if private { 25 } else { 15 }), check).await, Ok(Some(_)))
}

/// Evita pasar a https dos veces la misma carga (llega el aviso de inicio y el de fin).
static UPGRADING: OnceLock<Mutex<std::collections::HashMap<u32, (String, std::time::Instant)>>> = OnceLock::new();

fn first_upgrade(id: u32, url: &str) -> bool {
    let mut m = UPGRADING.get_or_init(Default::default).lock();
    m.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(5));
    if let Some((u, t)) = m.get(&id) {
        if u == url && t.elapsed() < Duration::from_secs(5) {
            return false;
        }
    }
    m.insert(id, (url.to_string(), std::time::Instant::now()));
    true
}

/// La web no tiene https: la pestaña se queda sin vista y la interfaz muestra el aviso
/// ("Continuar sin cifrar" / "Volver").
fn show_https_warn(app: &AppHandle, sh: &Shared, id: u32, u: &url::Url) {
    let id = if app.get_webview(&label(id)).is_some() { go_home(app, sh, id) } else { Some(id) };
    if let Some(id) = id {
        update_tab(sh, id, |t| {
            t.url = u.to_string();
            t.title = u.host_str().unwrap_or("").to_string();
            t.loading = false;
            t.https_warn = true;
        });
    }
}

/// JavaScript activado o no en cada vista abierta (no se puede cambiar en una vista ya creada:
/// si una web necesita lo contrario, la pestaña se vuelve a abrir con otra vista).
static VIEW_JS: OnceLock<Mutex<std::collections::HashMap<u32, bool>>> = OnceLock::new();

fn view_js() -> &'static Mutex<std::collections::HashMap<u32, bool>> {
    VIEW_JS.get_or_init(Default::default)
}

/// ¿Tiene JavaScript la vista de esta pestaña? (None si no tiene vista).
pub fn tab_js(id: u32) -> Option<bool> {
    view_js().lock().get(&id).copied()
}

/// Configuración común del motor para la interfaz y todas las pestañas.
/// Windows (WebView2): argumentos de Chromium con el proxy. Linux/Android (WebKit): proxy nativo.
/// `private`: modo Sombra (perfil temporal, salida por Tor). Si no, modo normal (perfil propio
/// que se conserva, salida directa). Cada modo usa su carpeta: no comparten cookies ni caché.
pub fn engine_setup(b: WebviewBuilder<tauri::Wry>, private: bool) -> WebviewBuilder<tauri::Wry> {
    let eng = ENGINE.get().expect("motor no iniciado");
    let (dir, args, port) = if private { (&eng.data_dir, &eng.args, eng.proxy_port) } else { (&eng.normal_dir, &eng.normal_args, eng.normal_port) };
    let b = b.incognito(private).data_directory(dir.clone());
    #[cfg(windows)]
    {
        let _ = port;
        b.additional_browser_args(args)
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        let u = url::Url::parse(&format!("socks5://127.0.0.1:{port}")).expect("url proxy");
        b.proxy_url(u)
    }
}

pub fn label(id: u32) -> String {
    format!("tab-{id}")
}

/// Script que se ejecuta en cada página (y en cada iframe) antes que el código de la web.
fn privacy_script(fp_key: &str, seed: u32, strict: bool, yt: bool, private: bool) -> String {
    // Linux con huella reforzada: las webs ven Safari en Mac (ver SAFARI_UA).
    let platform = if cfg!(target_os = "linux") && strict { "MacIntel" } else { "" };
    r#"(() => {
  try {
    const hide = (o, k) => { try { delete o[k]; } catch (e) {} try { Object.defineProperty(o, k, { value: undefined, configurable: true }); } catch (e) {} };
    // Las pestañas no tienen ninguna conexión con Sombra (Tauri parcheado, ver
    // vendor/PARCHE.md). En Windows, WebView2 añade window.chrome.webview: se quita.
    try { if (window.chrome && window.chrome.webview) delete window.chrome.webview; } catch (e) {}
    const J = JSON.stringify;
    // Lo que Sombra cambia debe parecer igual que el original: mismo nombre, mismo número
    // de argumentos, sin "prototype" y con toString() = "[native code]".
    const NAT = new WeakMap();
    const FTS = Function.prototype.toString;
    const mask = (fn, orig) => { try { NAT.set(fn, orig); } catch (e) {} return fn; };
    try {
      const ts = { toString() { return FTS.call(NAT.get(this) || this); } }.toString;
      mask(ts, FTS);
      Object.defineProperty(Function.prototype, 'toString', { value: ts, writable: true, configurable: true });
    } catch (e) {}
    const wrap = (o, k, impl) => {
      try {
        const orig = o[k];
        if (typeof orig !== 'function') return;
        const f = impl(orig);
        const fn = { m(...a) { return f.apply(this, a); } }.m;
        Object.defineProperty(fn, 'name', { value: orig.name });
        Object.defineProperty(fn, 'length', { value: orig.length });
        const d = Object.getOwnPropertyDescriptor(o, k) || { writable: true, enumerable: false, configurable: true };
        Object.defineProperty(o, k, { value: mask(fn, orig), writable: d.writable !== false, enumerable: !!d.enumerable, configurable: true });
      } catch (e) {}
    };
    const getter = (o, k, get) => {
      try {
        const d = Object.getOwnPropertyDescriptor(o, k);
        if (!d || !d.get) return;
        const g = Object.getOwnPropertyDescriptor({ get [k]() { return get.call(this); } }, k).get;
        Object.defineProperty(o, k, { get: mask(g, d.get), set: d.set, enumerable: d.enumerable, configurable: true });
      } catch (e) {}
    };
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
    // WebRTC fuera en modo Sombra: es la fuga de IP más típica. En modo normal se deja
    // (videollamadas); el motor no revela las direcciones de la red local.
    if (__PRIVATE__) ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription','RTCIceCandidate','RTCRtpReceiver','RTCRtpSender'].forEach(k => hide(window, k));
    // Huella de canvas, WebGL y audio: ruido mínimo que cambia en cada web y en cada sesión
    // (como Brave). Dentro de una misma web y sesión el resultado es siempre el mismo, pero dos
    // webs, o la misma web otro día, ven huellas distintas: no se te puede seguir con ellas.
    const note = (k) => { st.fp++; st.kinds[k] = (st.kinds[k] || 0) + 1; };
    const site = (() => { try { return window.top.location.hostname; } catch (e) { return location.hostname; } })();
    const SEED = (() => { let h = 2166136261 ^ __SEED__; for (const ch of site) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; })();
    const rng = (s) => () => { s = (s + 0x6D2B79F5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
    const noise = (data) => { const r = rng(SEED ^ data.length); for (let i = Math.floor(r() * 40); i < data.length; i += 16 + Math.floor(r() * 48)) { if ((i & 3) !== 3) data[i] ^= 1; } };
    const C2D = window.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
    const GID = C2D && C2D.getImageData, GCX = window.HTMLCanvasElement && HTMLCanvasElement.prototype.getContext;
    if (C2D) wrap(C2D, 'getImageData', orig => function () { note('canvas'); const r = orig.apply(this, arguments); try { noise(r.data); } catch (e) {} return r; });
    if (window.OffscreenCanvasRenderingContext2D) wrap(OffscreenCanvasRenderingContext2D.prototype, 'getImageData', orig => function () { note('canvas'); const r = orig.apply(this, arguments); try { noise(r.data); } catch (e) {} return r; });
    const HC = window.HTMLCanvasElement && HTMLCanvasElement.prototype;
    if (HC && C2D) {
      // Se exporta una copia con ruido: el canvas de la web no se toca (antes se modificaba).
      for (const m of ['toDataURL', 'toBlob']) {
        wrap(HC, m, orig => function () {
          note('canvas');
          try {
            if (this.width && this.height && this.width * this.height <= 4000000) {
              const c = document.createElement('canvas');
              c.width = this.width; c.height = this.height;
              const x = GCX.call(c, '2d');
              x.drawImage(this, 0, 0);
              const d = GID.call(x, 0, 0, c.width, c.height);
              noise(d.data);
              x.putImageData(d, 0, 0);
              return orig.apply(c, arguments);
            }
          } catch (e) {}
          return orig.apply(this, arguments);
        });
      }
    }
    for (const G of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
      if (!G) continue;
      wrap(G.prototype, 'getParameter', orig => function (p) {
        if (p === 37445) { note('webgl'); return 'Google Inc.'; }
        if (p === 37446) { note('webgl'); return 'ANGLE (Generic GPU)'; }
        return orig.apply(this, arguments);
      });
      wrap(G.prototype, 'readPixels', orig => function () {
        const r = orig.apply(this, arguments);
        try { const px = [...arguments].find(a => ArrayBuffer.isView(a)); if (px && px.length) { note('webgl'); noise(px); } } catch (e) {}
        return r;
      });
    }
    const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (AC) wrap(AC.prototype, 'startRendering', orig => function () { note('audio'); return orig.apply(this, arguments); });
    // Audio: variación inaudible (una millonésima) en algunas muestras, igual en cada lectura.
    const anoise = (a) => { const r = rng(SEED ^ a.length ^ 0x5bd1e995); for (let i = Math.floor(r() * 100); i < a.length; i += 50 + Math.floor(r() * 150)) a[i] += (r() - 0.5) * 2e-7; };
    if (window.AudioBuffer) {
      const seen = new WeakSet();
      wrap(AudioBuffer.prototype, 'getChannelData', orig => function () {
        const a = orig.apply(this, arguments);
        try { if (!seen.has(a)) { seen.add(a); anoise(a); } } catch (e) {}
        return a;
      });
      wrap(AudioBuffer.prototype, 'copyFromChannel', orig => function (dest) { const r = orig.apply(this, arguments); try { anoise(dest); } catch (e) {} return r; });
    }
    if (window.AnalyserNode) {
      wrap(AnalyserNode.prototype, 'getFloatFrequencyData', orig => function (a) { const r = orig.apply(this, arguments); try { note('audio'); anoise(a); } catch (e) {} return r; });
    }
    if (window.FontFaceSet) {
      let n = 0;
      wrap(FontFaceSet.prototype, 'check', orig => function () { if (++n === 20) note('fuentes'); return orig.apply(this, arguments); });
    }
    if (navigator.getBattery) hide(Navigator.prototype, 'getBattery');
    getter(Navigator.prototype, 'hardwareConcurrency', () => 4);
    getter(Navigator.prototype, 'deviceMemory', () => 8);

    // Protección reforzada (ajuste "fp_strict", activado por defecto), como Tor Browser:
    // idioma inglés, hora UTC, pantalla = tamaño de la página (que Sombra redondea), sin
    // lista de voces ni de dispositivos. Así muchos usuarios de Sombra parecen el mismo.
    if (__STRICT__) {
      const LOC = 'en-US', TZ = 'UTC';
      const LANGS = Object.freeze([LOC, 'en']);
      getter(Navigator.prototype, 'language', () => LOC);
      getter(Navigator.prototype, 'languages', () => LANGS);
      // Linux: Sombra se presenta como Safari en Mac (mismo motor, muchísimos más usuarios).
      if ('__PLATFORM__') getter(Navigator.prototype, 'platform', () => '__PLATFORM__');
      // Windows: WebView2 se delata en la lista de marcas ("Microsoft Edge WebView2"); se quita.
      if (window.NavigatorUAData) {
        const P = NavigatorUAData.prototype, d = Object.getOwnPropertyDescriptor(P, 'brands');
        const clean = (l) => Array.isArray(l) ? l.filter(b => !/webview/i.test(b && b.brand)) : l;
        if (d && d.get) { const og = d.get; getter(P, 'brands', function () { return clean(og.call(this)); }); }
        wrap(P, 'getHighEntropyValues', orig => function () {
          return orig.apply(this, arguments).then(v => { if (v) { if (v.brands) v.brands = clean(v.brands); if (v.fullVersionList) v.fullVersionList = clean(v.fullVersionList); } return v; });
        });
      }
      // Intl: idioma y zona horaria por defecto.
      const opts = (o, tz) => {
        if (!tz) return o;
        if (o === undefined) return { timeZone: TZ };
        if (o && typeof o === 'object' && o.timeZone === undefined) return Object.assign({}, o, { timeZone: TZ });
        return o;
      };
      for (const name of ['DateTimeFormat', 'NumberFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat', 'ListFormat', 'DisplayNames', 'Segmenter', 'DurationFormat']) {
        const C = Intl[name];
        if (typeof C !== 'function') continue;
        const tz = name === 'DateTimeFormat';
        const args = a => [a[0] === undefined ? LOC : a[0], opts(a[1], tz)].concat([].slice.call(a, 2));
        const P = new Proxy(C, {
          construct: (t, a, nt) => Reflect.construct(t, args(a), nt),
          apply: (t, self, a) => Reflect.apply(t, self, args(a)),
        });
        mask(P, C);
        try { Object.defineProperty(C.prototype, 'constructor', { value: P, writable: true, configurable: true }); } catch (e) {}
        try { Object.defineProperty(Intl, name, { value: P, writable: true, configurable: true }); } catch (e) {}
      }
      // Fechas: todo en UTC, como si el equipo estuviera en Greenwich.
      const OD = Date, DP = OD.prototype, gt = DP.getTime, realTZO = DP.getTimezoneOffset;
      const U = { FullYear: 1, Month: 1, Date: 1, Day: 1, Hours: 1, Minutes: 1, Seconds: 1, Milliseconds: 1 };
      for (const k in U) {
        const g = DP['getUTC' + k];
        wrap(DP, 'get' + k, () => function () { return g.call(this); });
        const s = DP['setUTC' + k];
        if (s) wrap(DP, 'set' + k, () => function () { return s.apply(this, arguments); });
      }
      wrap(DP, 'getTimezoneOffset', () => function () { return isNaN(gt.call(this)) ? NaN : 0; });
      wrap(DP, 'getYear', () => function () { const y = DP.getUTCFullYear.call(this); return isNaN(y) ? NaN : y - 1900; });
      const DN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const MN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const p2 = n => String(n).padStart(2, '0');
      const yr = y => (y < 0 ? '-' + String(-y).padStart(6, '0') : String(y).padStart(4, '0'));
      const dStr = d => DN[d.getUTCDay()] + ' ' + MN[d.getUTCMonth()] + ' ' + p2(d.getUTCDate()) + ' ' + yr(d.getUTCFullYear());
      const tStr = d => p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds()) + ' GMT+0000 (Coordinated Universal Time)';
      const bad = d => isNaN(gt.call(d));
      wrap(DP, 'toString', () => function () { return bad(this) ? 'Invalid Date' : dStr(this) + ' ' + tStr(this); });
      wrap(DP, 'toDateString', () => function () { return bad(this) ? 'Invalid Date' : dStr(this); });
      wrap(DP, 'toTimeString', () => function () { return bad(this) ? 'Invalid Date' : tStr(this); });
      for (const k of ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString']) {
        wrap(DP, k, orig => function (l, o) { return orig.call(this, l === undefined ? LOC : l, opts(o, true)); });
      }
      wrap(Number.prototype, 'toLocaleString', orig => function (l, o) { return orig.call(this, l === undefined ? LOC : l, o); });
      wrap(String.prototype, 'localeCompare', orig => function (s, l, o) { return orig.call(this, s, l === undefined ? LOC : l, o); });
      // Textos de fecha sin zona: el motor los toma como hora local; se pasan a UTC.
      const realOff = t => { try { return realTZO.call(new OD(t)); } catch (e) { return 0; } };
      const ZONED = /(?:Z|[+-]\d\d:?\d\d|GMT|UTC|\b[ECMP][SD]T)\s*(?:\([^)]*\))?\s*$/i;
      const DATE_ONLY = /^\s*[+-]?\d{4,6}(?:-\d\d(?:-\d\d)?)?\s*$/;
      wrap(OD, 'parse', orig => function (s) {
        const str = String(s);
        const t = orig.call(this, str);
        if (isNaN(t) || ZONED.test(str) || DATE_ONLY.test(str)) return t;
        return t - realOff(t) * 60000;
      });
      const PD = new Proxy(OD, {
        construct: (t, a, nt) => {
          if (a.length >= 2) return Reflect.construct(t, [OD.UTC.apply(null, a)], nt);
          if (a.length === 1 && typeof a[0] === 'string') return Reflect.construct(t, [OD.parse(a[0])], nt);
          return Reflect.construct(t, a, nt);
        },
        apply: () => DP.toString.call(new OD()),
      });
      mask(PD, OD);
      try { Object.defineProperty(DP, 'constructor', { value: PD, writable: true, configurable: true }); } catch (e) {}
      try { Object.defineProperty(window, 'Date', { value: PD, writable: true, configurable: true }); } catch (e) {}
      // Temporal (API nueva de fechas): zona UTC por defecto.
      const TN = window.Temporal && Temporal.Now;
      if (TN) {
        wrap(TN, 'timeZoneId', () => function () { return TZ; });
        for (const k of ['zonedDateTimeISO', 'plainDateTimeISO', 'plainDateISO', 'plainTimeISO']) {
          wrap(TN, k, orig => function (tz) { return orig.call(this, tz === undefined ? TZ : tz); });
        }
      }
      // Pantalla y ventana: lo mismo que mide la página (Sombra redondea ese tamaño).
      const top = (() => { try { return window.top.innerWidth >= 0 ? window.top : window; } catch (e) { return window; } })();
      const W = () => top.innerWidth, H = () => top.innerHeight, Z = () => 0;
      for (const [k, f] of [['width', W], ['height', H], ['availWidth', W], ['availHeight', H], ['availLeft', Z], ['availTop', Z], ['colorDepth', () => 24], ['pixelDepth', () => 24]]) getter(Screen.prototype, k, f);
      for (const [k, f] of [['outerWidth', W], ['outerHeight', H], ['screenX', Z], ['screenY', Z], ['screenLeft', Z], ['screenTop', Z]]) getter(window, k, f);      // Voces de lectura en voz alta y dispositivos (cámaras, micros): listas vacías.
      if (window.speechSynthesis && window.SpeechSynthesis) wrap(SpeechSynthesis.prototype, 'getVoices', () => function () { return []; });
      if (window.MediaDevices) wrap(MediaDevices.prototype, 'enumerateDevices', () => function () { return Promise.resolve([]); });
    }

    // Anuncios de YouTube (con el bloqueador activado). YouTube manda la lista de anuncios
    // dentro de los datos del vídeo: se quita antes de que el reproductor la lea. Si aun así
    // sale alguno, se salta al final y se pulsa "Saltar".
    if (__YT__ && /(^|\.)youtube(-nocookie)?\.com$/.test(location.hostname)) {
      const ADK = ['adPlacements', 'adSlots', 'playerAds', 'adBreakHeartbeatParams'];
      const strip = (o, d) => {
        if (!o || typeof o !== 'object' || d > 4) return o;
        for (const k of ADK) if (k in o) { try { delete o[k]; } catch (e) {} }
        for (const k of ['playerResponse', 'response']) if (o[k] && typeof o[k] === 'object') strip(o[k], d + 1);
        if (Array.isArray(o)) for (const x of o) strip(x, d + 1);
        return o;
      };
      wrap(JSON, 'parse', orig => function () { return strip(orig.apply(this, arguments), 0); });
      if (window.Response) wrap(Response.prototype, 'json', orig => function () { return orig.apply(this, arguments).then(v => strip(v, 0)); });
      for (const g of ['ytInitialPlayerResponse', 'ytInitialData']) {
        let v;
        try {
          Object.defineProperty(window, g, { get() { return v; }, set(x) { v = strip(x, 0); }, configurable: true, enumerable: true });
        } catch (e) {}
      }
      const skip = () => {
        try {
          const p = document.querySelector('.html5-video-player.ad-showing, .html5-video-player.ad-interrupting');
          if (!p) return;
          const vd = p.querySelector('video');
          if (vd && isFinite(vd.duration) && vd.duration > 0) { vd.muted = true; vd.currentTime = vd.duration; }
          const b = p.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button');
          if (b) b.click();
        } catch (e) {}
      };
      setInterval(skip, 500);
    }
  } catch (e) {}
})();"#
        .replace("__FPKEY__", fp_key)
        .replace("__SEED__", &seed.to_string())
        .replace("__PLATFORM__", platform)
        .replace("__STRICT__", if strict { "true" } else { "false" })
        .replace("__YT__", if yt { "true" } else { "false" })
        .replace("__PRIVATE__", if private { "true" } else { "false" })
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

/// Aviso a la interfaz, como mucho uno cada 5 s (algunas webs lo intentan varias veces).
/// `url`: la web, para ofrecer abrirla en una pestaña normal.
fn notice_once(sh: &Shared, code: &str, url: String) {
    static LAST: Mutex<Vec<(String, std::time::Instant)>> = Mutex::new(Vec::new());
    {
        let mut l = LAST.lock();
        l.retain(|(_, t)| t.elapsed() < Duration::from_secs(5));
        if l.iter().any(|(c, _)| c == code) {
            return;
        }
        l.push((code.to_string(), std::time::Instant::now()));
    }
    sh.emit("notice", serde_json::json!({ "code": code, "message": code, "url": url }));
}

fn tab_url(sh: &Shared, id: u32) -> String {
    sh.tabs.lock().list.iter().find(|t| t.id == id).map(|t| t.url.clone()).unwrap_or_default()
}

/// AutoFirma (firmar con el certificado digital en webs de la administración). Solo en
/// pestañas normales: en modo Sombra diría quién eres. Devuelve si el motor sigue adelante.
fn open_afirma(sh: &Shared, id: u32, private: bool, u: &url::Url) -> bool {
    if private {
        notice_once(sh, "afirmaSombra", tab_url(sh, id));
        return false;
    }
    sh.start_afirma(u.as_str());
    sh.sec("afirma", serde_json::json!({}), "AutoFirma: la web puede hablar con ella en este PC durante 10 minutos".into());
    // Windows: el motor pregunta y abre AutoFirma. Linux: lo abre el sistema.
    #[cfg(windows)]
    {
        let _ = u;
        true
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(u.as_str()).spawn();
        false
    }
}

/// Windows (WebView2): certificado digital y apps externas.
/// - Modo Sombra: nunca se envía el certificado ni se abre ninguna app (dirían quién eres).
/// - Modo normal: el motor te deja elegir el certificado (ventana de Windows); de las apps
///   externas solo AutoFirma, también desde los recuadros de la página.
#[cfg(windows)]
fn windows_hooks(pw: tauri::webview::PlatformWebview, sh: Arc<Shared>, id: u32, private: bool) {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        ICoreWebView2_18, ICoreWebView2_5, COREWEBVIEW2_KEY_EVENT_KIND, COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN,
        COREWEBVIEW2_KEY_EVENT_KIND_SYSTEM_KEY_DOWN, COREWEBVIEW2_PHYSICAL_KEY_STATUS,
    };
    use webview2_com::{
        AcceleratorKeyPressedEventHandler, ClientCertificateRequestedEventHandler, ContainsFullScreenElementChangedEventHandler,
        LaunchingExternalUriSchemeEventHandler,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CONTROL, VK_SHIFT};
    use windows_core::{Interface, BOOL, PWSTR};
    unsafe {
        let controller = pw.controller();
        let Ok(core) = controller.CoreWebView2() else { return };
        let mut token = 0i64;
        // Atajos de Sombra con el foco dentro de la página.
        {
            let sh2 = sh.clone();
            let _ = controller.add_AcceleratorKeyPressed(
                &AcceleratorKeyPressedEventHandler::create(Box::new(move |_, args| {
                    let Some(a) = args else { return Ok(()) };
                    let mut kind = COREWEBVIEW2_KEY_EVENT_KIND::default();
                    a.KeyEventKind(&mut kind)?;
                    if kind != COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN && kind != COREWEBVIEW2_KEY_EVENT_KIND_SYSTEM_KEY_DOWN {
                        return Ok(());
                    }
                    let mut st = COREWEBVIEW2_PHYSICAL_KEY_STATUS::default();
                    a.PhysicalKeyStatus(&mut st)?;
                    // Mantener la tecla pulsada no repite el atajo (no abre veinte pestañas).
                    if st.WasKeyDown.as_bool() {
                        return Ok(());
                    }
                    let mut vk = 0u32;
                    a.VirtualKey(&mut vk)?;
                    let key = match vk {
                        0x41..=0x5A => Key::Ch((vk as u8 + 32) as char),
                        0x70..=0x7B => Key::F((vk - 0x6F) as u8),
                        0x09 => Key::Tab,
                        0x24 => Key::Home,
                        0x2E => Key::Delete,
                        _ => Key::Other,
                    };
                    let ctrl = GetKeyState(VK_CONTROL.0 as i32) < 0;
                    let shift = GetKeyState(VK_SHIFT.0 as i32) < 0;
                    if let Some(name) = shortcut(key, ctrl, shift, st.IsMenuKeyDown.as_bool()) {
                        a.SetHandled(true)?;
                        run_shortcut(&sh2, name);
                    }
                    Ok(())
                })),
                &mut token,
            );
        }
        // Pantalla completa de verdad (vídeos).
        if let Some(app) = sh.app.get().cloned() {
            let sh2 = sh.clone();
            let _ = core.add_ContainsFullScreenElementChanged(
                &ContainsFullScreenElementChangedEventHandler::create(Box::new(move |sender, _| {
                    if let Some(s) = sender {
                        let mut on = BOOL::default();
                        s.ContainsFullScreenElement(&mut on)?;
                        set_fullscreen(&app, &sh2, id, on.as_bool());
                    }
                    Ok(())
                })),
                &mut token,
            );
        }
        if private {
            if let Ok(w5) = core.cast::<ICoreWebView2_5>() {
                let sh2 = sh.clone();
                let _ = w5.add_ClientCertificateRequested(
                    &ClientCertificateRequestedEventHandler::create(Box::new(move |_, args| {
                        if let Some(a) = args {
                            a.SetCancel(true)?;
                            notice_once(&sh2, "certSombra", tab_url(&sh2, id));
                        }
                        Ok(())
                    })),
                    &mut token,
                );
            }
        }
        if let Ok(w18) = core.cast::<ICoreWebView2_18>() {
            let _ = w18.add_LaunchingExternalUriScheme(
                &LaunchingExternalUriSchemeEventHandler::create(Box::new(move |_, args| {
                    let Some(a) = args else { return Ok(()) };
                    let mut p = PWSTR::null();
                    a.Uri(&mut p)?;
                    let uri = webview2_com::take_pwstr(p);
                    let afirma = uri.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("afirma:"));
                    if afirma && !private {
                        sh.start_afirma(&uri);
                    } else {
                        a.SetCancel(true)?;
                        if afirma {
                            notice_once(&sh, "afirmaSombra", tab_url(&sh, id));
                        }
                    }
                    Ok(())
                })),
                &mut token,
            );
        }
    }
}

/// Tecla pulsada dentro de una página (Windows y Linux la traducen a esto).
#[derive(Clone, Copy, PartialEq)]
pub enum Key {
    Ch(char),
    F(u8),
    Tab,
    Home,
    Delete,
    Other,
}

/// Atajos de Sombra que funcionan también con el foco dentro de la página (como en Chrome).
/// La página no los recibe. Los nombres son los que entiende la interfaz (runShortcut).
pub fn shortcut(k: Key, ctrl: bool, shift: bool, alt: bool) -> Option<&'static str> {
    use Key::*;
    Some(match (k, ctrl, shift, alt) {
        (Ch('t'), true, false, false) => "newtab",
        (Ch('t'), true, true, false) => "reopen",
        (Ch('n'), true, true, false) => "newtab-private",
        (Ch('w'), true, false, false) | (F(4), true, false, false) => "close",
        (Ch('l'), true, false, false) | (Ch('d'), false, false, true) | (F(6), false, false, false) => "addr",
        (F(5), false, false, false) | (Ch('r'), true, false, false) => "reload",
        (Ch('h'), true, false, false) => "history",
        (Home, false, false, true) => "home",
        (Tab, true, false, false) => "next-tab",
        (Tab, true, true, false) => "prev-tab",
        (Delete, true, true, false) => "clean",
        _ => return None,
    })
}

/// Lleva el atajo a la interfaz. Para escribir una dirección (también en una pestaña nueva),
/// el foco pasa a la barra de Sombra.
pub fn run_shortcut(sh: &Shared, name: &str) {
    if matches!(name, "addr" | "newtab" | "newtab-private") {
        if let Some(ui) = sh.app.get().and_then(|a| a.get_webview("ui")) {
            let _ = ui.set_focus();
        }
    }
    sh.emit("shortcut", name);
}

/// Pantalla completa de una página (un vídeo): la ventana pasa a pantalla completa y la
/// pestaña la ocupa entera. Al salir, todo vuelve a su sitio.
pub fn set_fullscreen(app: &AppHandle, sh: &Arc<Shared>, id: u32, on: bool) {
    {
        let mut t = sh.tabs.lock();
        if on {
            t.fullscreen = Some(id);
        } else if t.fullscreen == Some(id) {
            t.fullscreen = None;
        } else {
            return;
        }
    }
    if let Some(w) = app.get_window("main") {
        let _ = w.set_fullscreen(on);
    }
    // La interfaz se vuelve negra detrás de la página (sin barra ni bordes a la vista).
    sh.emit("fullscreen", on);
    layout(app, sh);
    // La ventana tarda un momento en cambiar de tamaño.
    let (app2, sh2) = (app.clone(), sh.clone());
    tauri::async_runtime::spawn(async move {
        for ms in [150, 450] {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            layout(&app2, &sh2);
        }
    });
}

/// Sale de la pantalla completa si la tenía otra pestaña (al cambiar o cerrar pestañas).
fn leave_fullscreen_unless(app: &AppHandle, sh: &Arc<Shared>, keep: Option<u32>) {
    let fs = sh.tabs.lock().fullscreen;
    if let Some(f) = fs.filter(|f| Some(*f) != keep) {
        set_fullscreen(app, sh, f, false);
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

/// Crea una pestaña (vacía o con una URL) en el modo por defecto y la activa.
pub async fn new_tab(app: &AppHandle, sh: &Arc<Shared>, url: Option<String>) -> anyhow::Result<u32> {
    let private = sh.settings.lock().default_private;
    new_tab_mode(app, sh, url, private).await
}

/// Crea una pestaña en modo Sombra (`private`) o normal, y la activa.
pub async fn new_tab_mode(app: &AppHandle, sh: &Arc<Shared>, url: Option<String>, private: bool) -> anyhow::Result<u32> {
    let id = {
        let mut t = sh.tabs.lock();
        let id = t.next;
        t.next += 1;
        t.list.push(TabInfo { id, url: String::new(), title: "Nueva pestaña".into(), loading: false, has_view: false, https_warn: false, private });
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
    // Un aviso tardío de una vista ya cerrada (pestaña cerrada o reabierta con otro número)
    // no debe crear una vista nueva para una pestaña que ya no existe.
    if !sh.tabs.lock().list.iter().any(|t| t.id == id) {
        return Ok(());
    }
    let private = tab_private(sh, id);
    let search = sh.settings.lock().search_for(private);
    let target = normalize_input(raw, &search);
    let mut parsed = url::Url::parse(&target).map_err(|e| anyhow::anyhow!("Dirección no válida: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("Solo se permiten direcciones http y https");
    }
    // Los .onion solo existen dentro de Tor: desde una pestaña normal se abren en una pestaña
    // Sombra (nueva, para no mezclar nada de los dos modos).
    if !private && parsed.host_str().is_some_and(|h| h.trim_end_matches('.').ends_with(".onion")) {
        let s = parsed.to_string();
        Box::pin(new_tab_mode(app, sh, Some(s), true)).await?;
        return Ok(());
    }
    // Modo solo HTTPS: se abre la versión cifrada; si no existe, se avisa en lugar de abrirla.
    // Una web escrita sin "https://" (ejemplo.com) pasa por la misma comprobación, para poder
    // ofrecer el aviso si su https no funciona (en vez de quedarse en un error de certificado).
    let typed_bare = target.strip_prefix("https://") == Some(raw.trim());
    if typed_bare && parsed.port().is_none() && !sh.https_known.lock().contains(&parsed.host_str().unwrap_or("").to_ascii_lowercase()) {
        let mut h = parsed.clone();
        if h.set_scheme("http").is_ok() && needs_upgrade(sh, &h) {
            parsed = h;
        }
    }
    if needs_upgrade(sh, &parsed) {
        update_tab(sh, id, |t| {
            t.loading = true;
            t.https_warn = false;
        });
        match https_version(sh, &parsed, private).await {
            Some(u) => parsed = u,
            None => {
                show_https_warn(app, sh, id, &parsed);
                return Ok(());
            }
        }
    }
    // Cada búsqueda sale por un circuito de Tor nuevo: el buscador no puede
    // relacionar una búsqueda con la anterior.
    let prefix = search.split("%s").next().unwrap_or(&search);
    if private && prefix.len() > 8 && target.starts_with(prefix) {
        if let Some(h) = parsed.host_str() {
            sh.tor.rotate_host(h);
        }
    }
    // Si la vista abierta tiene JavaScript al revés de lo que toca a la nueva web (nivel de
    // seguridad), se cierra y la pestaña se abre con una vista nueva (con otro número).
    // La comprobación de https tarda: la pestaña pudo cerrarse mientras tanto.
    if !sh.tabs.lock().list.iter().any(|t| t.id == id) {
        return Ok(());
    }
    let mut id = id;
    let js = js_allowed(sh, &parsed, private);
    let existing = app.get_webview(&label(id));
    if existing.is_some() && tab_js(id) != Some(js) {
        match go_home(app, sh, id) {
            Some(n) => id = n,
            None => return Ok(()),
        }
    }
    // Se marca la web como "abierta por ti" ANTES de pedirla, para que el bloqueador no la corte.
    update_tab(sh, id, |t| {
        t.url = parsed.to_string();
        t.loading = true;
        t.https_warn = false;
    });
    if let Some(wv) = existing.filter(|_| tab_js(id) == Some(js)) {
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
    #[cfg(windows)]
    let sh_win = sh.clone();
    let sh_load = sh.clone();
    let sh_title = sh.clone();
    let sh_new = sh.clone();
    let app_new = app.clone();
    let app_load = app.clone();

    let private = tab_private(sh, id);
    let js = js_allowed(sh, &url, private);
    // Huella reforzada y niveles de seguridad: solo en modo Sombra.
    let (strict, level, yt) = {
        let s = sh.settings.lock();
        (s.fp_strict && private, if private { s.security_level } else { 0 }, s.blocking_enabled)
    };
    let mut builder = engine_setup(WebviewBuilder::new(label(id), WebviewUrl::External(url)), private);
    if !js {
        builder = builder.disable_javascript();
    }
    if cfg!(target_os = "linux") && strict {
        builder = builder.user_agent(SAFARI_UA);
    }
    let builder = builder
        .initialization_script_for_all_frames(privacy_script(&eng.fp_key, eng.fp_seed, strict, yt, private))
        .on_permission_request(|_, _| PermissionResponse::Deny)
        .on_navigation(move |u| {
            if u.scheme() == "afirma" {
                return open_afirma(&sh_nav, id, private, u);
            }
            // La dirección de la pestaña NO se cambia aquí: este aviso llega también de los
            // recuadros de dentro de la página (anuncios, CAPTCHAs...), y la barra mostraba
            // su dirección. La dirección real llega en on_page_load, que es solo de la página.
            allowed_scheme(u)
        })
        .on_page_load(move |wv, payload| {
            let url = payload.url().to_string();
            // Modo solo HTTPS: un enlace o una redirección a http (el proxy ya ha cortado la
            // conexión sin cifrar) se abre por https, o se muestra el aviso.
            if needs_upgrade(&sh_load, payload.url()) {
                if first_upgrade(id, &url) {
                    let (app2, sh2) = (app_load.clone(), sh_load.clone());
                    tauri::async_runtime::spawn(async move {
                        let _ = navigate(&app2, &sh2, id, &url).await;
                        layout(&app2, &sh2);
                    });
                }
                return;
            }
            // Nivel de seguridad: si la página (un enlace, una redirección) necesita JavaScript
            // al revés que esta vista, la pestaña se vuelve a abrir con una vista adecuada.
            if matches!(payload.url().scheme(), "http" | "https") && tab_js(id).is_some_and(|j| j != js_allowed(&sh_load, payload.url(), private)) {
                let _ = wv.hide();
                let (app2, sh2) = (app_load.clone(), sh_load.clone());
                tauri::async_runtime::spawn(async move {
                    let _ = navigate(&app2, &sh2, id, &url).await;
                    layout(&app2, &sh2);
                });
                return;
            }
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
                    // Modo Sombra: nada se guarda, tampoco en el historial.
                    if !private {
                        sh_load.add_history(&url, &title);
                    }
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
            if !private {
                sh_title.set_history_title(&url, &title);
            }
        })
        .on_new_window(move |u, _| {
            // Las ventanas emergentes se abren como pestañas (del mismo modo) o se descartan.
            if matches!(u.scheme(), "http" | "https") {
                let app = app_new.clone();
                let sh = sh_new.clone();
                let s = u.to_string();
                tauri::async_runtime::spawn(async move {
                    let _ = new_tab_mode(&app, &sh, Some(s), private).await;
                });
            }
            tauri::webview::NewWindowResponse::Deny
        });

    // Zoom con Ctrl +/- y Ctrl + rueda. Windows: lo hace el motor. Linux: Sombra (más abajo),
    // porque Tauri lo haría metiendo un script en la página.
    #[cfg(windows)]
    let builder = builder.zoom_hotkeys_enabled(true);
    let (x, y, w, h) = sh.tabs.lock().rect;
    let view = window.add_child(builder, LogicalPosition::new(x, y), LogicalSize::new(w.max(1.0), h.max(1.0)))?;
    view_js().lock().insert(id, js);
    #[cfg(windows)]
    let _ = view.with_webview(move |pw| windows_hooks(pw, sh_win, id, private));
    // Linux (WebKit): sin WebGL ni reproducción automática en los niveles altos. En Windows
    // lo hacen los argumentos del motor (browser_args).
    #[cfg(target_os = "linux")]
    if level >= 1 {
        let _ = view.with_webview(|pw| {
            use webkit2gtk::{SettingsExt, WebViewExt};
            if let Some(s) = pw.inner().settings() {
                s.set_enable_webgl(false);
                s.set_media_playback_requires_user_gesture(true);
            }
        });
    }
    // Linux (WebKit): WebRTC viene apagado; en modo normal se enciende (videollamadas).
    #[cfg(target_os = "linux")]
    if !private {
        let _ = view.with_webview(|pw| {
            use webkit2gtk::{SettingsExt, WebViewExt};
            if let Some(s) = pw.inner().settings() {
                s.set_enable_webrtc(true);
            }
        });
    }
    // Linux (WebKit): atajos con el foco en la página, zoom y pantalla completa.
    #[cfg(target_os = "linux")]
    {
        let (sh_k, app_f) = (sh.clone(), app.clone());
        let _ = view.with_webview(move |pw| linux_hooks(pw.inner(), sh_k, app_f, id));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (&view, level);
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_hooks(wv: webkit2gtk::WebView, sh: Arc<Shared>, app: AppHandle, id: u32) {
    use gtk::gdk::keys::constants as K;
    use gtk::gdk::{ModifierType, ScrollDirection};
    use gtk::glib::Propagation;
    use gtk::prelude::*;
    use webkit2gtk::WebViewExt;
    fn zoom(w: &webkit2gtk::WebView, z: Option<f64>) {
        let n = z.map_or(1.0, |d| (w.zoom_level() + d).clamp(0.3, 3.0));
        w.set_zoom_level((n * 10.0).round() / 10.0);
    }
    let sh_k = sh.clone();
    wv.connect_key_press_event(move |w, ev| {
        let st = ev.state();
        let (ctrl, shift, alt) = (st.contains(ModifierType::CONTROL_MASK), st.contains(ModifierType::SHIFT_MASK), st.contains(ModifierType::MOD1_MASK));
        let kv = ev.keyval();
        if ctrl && !alt {
            if kv == K::plus || kv == K::equal || kv == K::KP_Add {
                zoom(w, Some(0.1));
                return Propagation::Stop;
            }
            if kv == K::minus || kv == K::KP_Subtract {
                zoom(w, Some(-0.1));
                return Propagation::Stop;
            }
            if kv == K::_0 || kv == K::KP_0 {
                zoom(w, None);
                return Propagation::Stop;
            }
        }
        let key = if kv == K::Tab || kv == K::ISO_Left_Tab {
            Key::Tab
        } else if kv == K::Home {
            Key::Home
        } else if kv == K::Delete {
            Key::Delete
        } else if kv == K::F4 {
            Key::F(4)
        } else if kv == K::F5 {
            Key::F(5)
        } else if kv == K::F6 {
            Key::F(6)
        } else {
            kv.to_lower().to_unicode().map_or(Key::Other, Key::Ch)
        };
        match shortcut(key, ctrl, shift, alt) {
            Some(n) => {
                run_shortcut(&sh_k, n);
                Propagation::Stop
            }
            None => Propagation::Proceed,
        }
    });
    wv.connect_scroll_event(|w, ev| {
        if !ev.state().contains(ModifierType::CONTROL_MASK) {
            return Propagation::Proceed;
        }
        let d = match ev.direction() {
            ScrollDirection::Up => 0.1,
            ScrollDirection::Down => -0.1,
            ScrollDirection::Smooth => ev.delta().1.signum() * -0.1,
            _ => 0.0,
        };
        if d != 0.0 {
            zoom(w, Some(d));
        }
        Propagation::Stop
    });
    let (app2, sh2) = (app.clone(), sh.clone());
    wv.connect_enter_fullscreen(move |_| {
        set_fullscreen(&app2, &sh2, id, true);
        false
    });
    wv.connect_leave_fullscreen(move |_| {
        set_fullscreen(&app, &sh, id, false);
        false
    });
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
    let (rect, active, ids, fs, private) = {
        let t = sh.tabs.lock();
        let private = t.active.and_then(|a| t.list.iter().find(|x| x.id == a)).is_some_and(|x| x.private);
        (t.rect, t.active, t.list.iter().map(|x| x.id).collect::<Vec<_>>(), t.fullscreen, private)
    };
    let (mut x, mut y, mut w, mut h) = rect;
    // Pantalla completa: la pestaña ocupa toda la ventana (que ya está a pantalla completa).
    if fs.is_some() && fs == active {
        if let Some(win) = app.get_window("main") {
            if let (Ok(sz), Ok(sf)) = (win.inner_size(), win.scale_factor()) {
                (x, y, w, h) = (0.0, 0.0, sz.width as f64 / sf, sz.height as f64 / sf);
            }
        }
    }
    // Huella reforzada (solo modo Sombra, como el resto de esa protección): la página mide un
    // múltiplo de 100 px (centrada), como el "letterboxing" de Tor Browser. Así el tamaño de la
    // ventana no identifica a nadie. En pantalla completa los bordes se ven negros (interfaz).
    if private && sh.settings.lock().fp_strict && w >= 200.0 && h >= 200.0 {
        let (w2, h2) = ((w / 100.0).floor() * 100.0, (h / 100.0).floor() * 100.0);
        x += ((w - w2) / 2.0).floor();
        y += ((h - h2) / 2.0).floor();
        w = w2;
        h = h2;
    }
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

pub fn activate(app: &AppHandle, sh: &Arc<Shared>, id: u32) {
    leave_fullscreen_unless(app, sh, Some(id));
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
    if sh.tabs.lock().fullscreen == Some(id) {
        set_fullscreen(app, sh, id, false);
    }
    if let Some(wv) = app.get_webview(&label(id)) {
        let _ = wv.close();
    }
    view_js().lock().remove(&id);
    let empty = {
        let mut t = sh.tabs.lock();
        let pos = t.list.iter().position(|x| x.id == id);
        if let Some(p) = pos {
            let old = t.list.remove(p);
            // Solo las que tenían una web abierta (no las de inicio ni los avisos).
            if old.has_view && (old.url.starts_with("https://") || old.url.starts_with("http://")) {
                t.closed.push(crate::state::ClosedTab { url: old.url, title: old.title, private: old.private, pos: p });
                let n = t.closed.len();
                if n > crate::state::MAX_CLOSED {
                    t.closed.drain(0..n - crate::state::MAX_CLOSED);
                }
            }
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

/// Reabre una pestaña cerrada (`index` en la lista de cerradas; sin él, la última), en su modo
/// (normal o Sombra) y en su sitio. Si la pestaña activa está vacía y es del mismo modo (la que
/// se abre sola al cerrar la última), se usa esa en lugar de abrir otra.
pub async fn reopen(app: &AppHandle, sh: &Arc<Shared>, index: Option<usize>) -> anyhow::Result<Option<u32>> {
    let (c, reuse) = {
        let mut t = sh.tabs.lock();
        let i = match index {
            Some(i) if i < t.closed.len() => i,
            Some(_) => return Ok(None),
            None if t.closed.is_empty() => return Ok(None),
            None => t.closed.len() - 1,
        };
        let c = t.closed.remove(i);
        let reuse = t
            .active
            .and_then(|a| t.list.iter().find(|x| x.id == a))
            .filter(|x| !x.has_view && !x.https_warn && x.url.is_empty() && x.private == c.private)
            .map(|x| x.id);
        (c, reuse)
    };
    let id = match reuse {
        Some(id) => id,
        None => {
            let id = new_tab_mode(app, sh, None, c.private).await?;
            let mut t = sh.tabs.lock();
            if let Some(p) = t.list.iter().position(|x| x.id == id) {
                let tab = t.list.remove(p);
                let at = c.pos.min(t.list.len());
                t.list.insert(at, tab);
            }
            id
        }
    };
    navigate(app, sh, id, &c.url).await?;
    layout(app, sh);
    emit_tabs(sh);
    Ok(Some(id))
}

/// Inicio: la pestaña vuelve a la pantalla de inicio. Se cierra su vista web,
/// así la web deja de ejecutarse y no queda nada suyo en memoria.
/// La pestaña recibe un número nuevo (en el mismo sitio de la barra): así la vista
/// vieja, que se cierra en segundo plano, no choca con la nueva ni puede cambiar
/// la pestaña con eventos que lleguen tarde.
pub fn go_home(app: &AppHandle, sh: &Shared, id: u32) -> Option<u32> {
    // Si estaba a pantalla completa (Alt+Inicio desde un vídeo), primero se sale.
    let was_fullscreen = sh.tabs.lock().fullscreen == Some(id);
    if was_fullscreen {
        let sh_arc = app.state::<Arc<Shared>>().inner().clone();
        set_fullscreen(app, &sh_arc, id, false);
    }
    if let Some(wv) = app.get_webview(&label(id)) {
        let _ = wv.close();
    }
    view_js().lock().remove(&id);
    let new_id;
    {
        let mut t = sh.tabs.lock();
        new_id = t.next;
        let tab = t.list.iter_mut().find(|x| x.id == id)?;
        *tab = TabInfo { id: new_id, url: String::new(), title: "Nueva pestaña".into(), loading: false, has_view: false, https_warn: false, private: tab.private };
        t.next += 1;
        if t.active == Some(id) {
            t.active = Some(new_id);
        }
    }
    sh.refresh_top_hosts();
    sh.stats.page_blocked.store(0, Ordering::Relaxed);
    emit_tabs(sh);
    Some(new_id)
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
