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

/* ---------- niveles de seguridad: JavaScript por web ---------- */

/// ¿Puede esta dirección usar JavaScript? Normal: siempre. Más seguro: solo en webs cifradas
/// (https o .onion), como Tor Browser. El más seguro: nunca. En todos los niveles, salvo las
/// webs que el usuario haya permitido (y sus subdominios).
pub fn js_allowed(sh: &Shared, u: &url::Url) -> bool {
    let s = sh.settings.lock();
    if s.security_level == 0 {
        return true;
    }
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    if s.js_allow.iter().any(|a| host == *a || host.ends_with(&format!(".{a}"))) {
        return true;
    }
    s.security_level == 1 && (u.scheme() == "https" || host.ends_with(".onion"))
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
fn privacy_script(fp_key: &str, seed: u32, strict: bool, yt: bool) -> String {
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
    // WebRTC fuera: es la fuga de IP más típica.
    ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription','RTCIceCandidate','RTCRtpReceiver','RTCRtpSender'].forEach(k => hide(window, k));
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
    // Si la vista abierta tiene JavaScript al revés de lo que toca a la nueva web (nivel de
    // seguridad), se cierra y la pestaña se abre con una vista nueva (con otro número).
    let mut id = id;
    let js = js_allowed(sh, &parsed);
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
    let sh_load = sh.clone();
    let sh_title = sh.clone();
    let sh_new = sh.clone();
    let app_new = app.clone();
    let app_load = app.clone();

    let js = js_allowed(sh, &url);
    let (strict, level, yt) = {
        let s = sh.settings.lock();
        (s.fp_strict, s.security_level, s.blocking_enabled)
    };
    let mut builder = engine_setup(WebviewBuilder::new(label(id), WebviewUrl::External(url)));
    if !js {
        builder = builder.disable_javascript();
    }
    if cfg!(target_os = "linux") && strict {
        builder = builder.user_agent(SAFARI_UA);
    }
    let builder = builder
        .initialization_script_for_all_frames(privacy_script(&eng.fp_key, eng.fp_seed, strict, yt))
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
            // Nivel de seguridad: si la página (un enlace, una redirección) necesita JavaScript
            // al revés que esta vista, la pestaña se vuelve a abrir con una vista adecuada.
            if matches!(payload.url().scheme(), "http" | "https") && tab_js(id).is_some_and(|j| j != js_allowed(&sh_load, payload.url())) {
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
    let view = window.add_child(builder, LogicalPosition::new(x, y), LogicalSize::new(w.max(1.0), h.max(1.0)))?;
    view_js().lock().insert(id, js);
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
    #[cfg(not(target_os = "linux"))]
    let _ = (&view, level);
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
    let (mut x, mut y, mut w, mut h) = rect;
    // Huella reforzada: la página mide un múltiplo de 100 px (centrada), como el
    // "letterboxing" de Tor Browser. Así el tamaño de la ventana no identifica a nadie.
    if sh.settings.lock().fp_strict && w >= 200.0 && h >= 200.0 {
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
    view_js().lock().remove(&id);
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
pub fn go_home(app: &AppHandle, sh: &Shared, id: u32) -> Option<u32> {
    if let Some(wv) = app.get_webview(&label(id)) {
        let _ = wv.close();
    }
    view_js().lock().remove(&id);
    let new_id;
    {
        let mut t = sh.tabs.lock();
        new_id = t.next;
        let tab = t.list.iter_mut().find(|x| x.id == id)?;
        *tab = TabInfo { id: new_id, url: String::new(), title: "Nueva pestaña".into(), loading: false, has_view: false };
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
