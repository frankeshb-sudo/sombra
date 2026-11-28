// Sombra - estado compartido: pestañas, estadísticas, registros, favoritos y ajustes.
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use crate::blocker::Blocker;
use crate::tor::Tor;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, EventTarget};
use tokio::sync::oneshot;

#[derive(Default)]
pub struct Stats {
    pub ads: AtomicU64,
    pub trackers: AtomicU64,
    pub leaks_blocked: AtomicU64,
    pub page_blocked: AtomicU64,
    pub connections: AtomicU64,
}

#[derive(Clone, Serialize, PartialEq)]
pub struct TabInfo {
    pub id: u32,
    pub url: String,
    pub title: String,
    pub loading: bool,
    pub has_view: bool,
    /// Modo solo HTTPS: la web no tiene versión cifrada y se muestra el aviso en lugar de abrirla.
    pub https_warn: bool,
    /// Pestaña en modo Sombra (Tor, anti-huella, nada se guarda). Si no, modo normal: conexión
    /// directa, sesiones y cookies guardadas, para el día a día. Nunca comparten datos.
    pub private: bool,
}

#[derive(Default)]
pub struct Tabs {
    pub list: Vec<TabInfo>,
    pub active: Option<u32>,
    pub next: u32,
    /// Zona donde se dibuja la web (x, y, ancho, alto) en píxeles lógicos.
    pub rect: (f64, f64, f64, f64),
    /// Pestaña con un vídeo (o algo) a pantalla completa: ocupa toda la pantalla.
    pub fullscreen: Option<u32>,
    /// Pestañas cerradas, la última al final, para reabrirlas (Ctrl+Mayús+T). Solo en memoria:
    /// se pierden al cerrar Sombra y se borran con el limpiador.
    pub closed: Vec<ClosedTab>,
}

#[derive(Clone, Serialize)]
pub struct ClosedTab {
    pub url: String,
    pub title: String,
    pub private: bool,
    /// Sitio que tenía en la barra de pestañas.
    #[serde(skip)]
    pub pos: usize,
}

pub const MAX_CLOSED: usize = 25;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Bookmark {
    pub url: String,
    pub title: String,
    #[serde(default)]
    pub folder: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub control_enabled: bool,
    pub blocking_enabled: bool,
    pub country: Option<String>,
    /// Buscador: URL donde `%s` es el texto buscado.
    pub search: String,
    /// "auto" (idioma del sistema) o un código: es, en, fr...
    pub language: String,
    /// "dark" | "light" | "system"
    pub theme: String,
    /// violet | blue | green | pink | orange
    pub accent: String,
    pub font_size: u8,
    pub compact: bool,
    pub show_bookmarks: bool,
    /// "off" (no se guarda) | "session" (solo mientras Sombra está abierto) | "save" (se guarda en el equipo)
    pub history_mode: String,
    /// Borrar historial al cerrar Sombra (la caché y las cookies se borran siempre).
    pub clean_on_exit: bool,
    /// Guardar también las páginas de resultados de búsqueda en el historial.
    pub history_searches: bool,
    /// Minutos sin usar antes de bloquear las contraseñas (0 = nunca).
    pub vault_lock_min: u32,
    /// Protección reforzada contra la huella digital: las webs ven idioma inglés, hora UTC y
    /// un tamaño de ventana redondeado (como Tor Browser).
    pub fp_strict: bool,
    /// Nivel de seguridad, como Tor Browser: 0 normal, 1 más seguro, 2 el más seguro.
    pub security_level: u8,
    /// Webs (dominios) donde el usuario permite JavaScript aunque el nivel lo bloquee.
    pub js_allow: Vec<String>,
    /// Modo solo HTTPS (como Tor Browser): las webs http se abren por https; si no tienen
    /// versión cifrada, Sombra avisa antes de abrirlas sin cifrar.
    pub https_only: bool,
    /// Las pestañas nuevas se abren en modo Sombra (si no, en modo normal).
    pub default_private: bool,
    /// Modo normal: DNS seguro (cifrado, ver doh.rs) en vez del DNS del sistema.
    pub secure_dns: bool,
    /// Bloquear las cookies de terceros (Linux) / prevención de seguimiento estricta (Windows).
    pub block_3p_cookies: bool,
}

/// DuckDuckGo por su dirección dentro de la red Tor: ni el buscador ni ningún
/// nodo de salida ven quién busca.
pub const DDG_CLEARNET: &str = "https://duckduckgo.com/?q=%s";

pub const DDG_ONION: &str = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=%s";

impl Settings {
    /// Parte fija de la URL del buscador (lo que va antes de `%s`).
    pub fn search_prefix(&self) -> &str {
        self.search.split("%s").next().unwrap_or(&self.search)
    }

    /// Buscador para cada modo. Un buscador .onion solo existe dentro de Tor: en modo normal
    /// se usa su versión de internet (DuckDuckGo).
    pub fn search_for(&self, private: bool) -> String {
        if !private && self.search.contains(".onion") {
            DDG_CLEARNET.into()
        } else {
            self.search.clone()
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            control_enabled: false,
            blocking_enabled: true,
            country: None,
            search: DDG_ONION.into(),
            language: "auto".into(),
            theme: "dark".into(),
            accent: "violet".into(),
            font_size: 13,
            compact: false,
            show_bookmarks: true,
            history_mode: "session".into(),
            clean_on_exit: false,
            history_searches: false,
            vault_lock_min: 15,
            fp_strict: true,
            security_level: 0,
            js_allow: Vec::new(),
            https_only: true,
            default_private: false,
            secure_dns: true,
            block_3p_cookies: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub time: u64,
}

const MAX_HISTORY: usize = 5000;

#[derive(Clone, Serialize)]
pub struct LogEntry {
    pub time: u64,
    pub kind: String,
    /// Código para traducir el mensaje en la interfaz (vacío = mostrar `message`).
    pub code: String,
    pub params: serde_json::Value,
    pub message: String,
}

pub struct Shared {
    pub tor: Arc<Tor>,
    blocker: RwLock<Option<Arc<Blocker>>>,
    pub blocking_enabled: AtomicBool,
    pub stats: Stats,
    pub tabs: Mutex<Tabs>,
    /// Descargas de esta sesión (solo en memoria).
    pub downloads: Mutex<Vec<crate::downloads::Download>>,
    top_hosts: RwLock<HashSet<String>>,
    pub logs: Mutex<Vec<LogEntry>>,
    pub settings: Mutex<Settings>,
    pub bookmarks: Mutex<Vec<Bookmark>>,
    pub history: Mutex<Vec<HistoryEntry>>,
    approvals: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    next_approval: AtomicU64,
    pub app: OnceLock<AppHandle>,
    pub data_dir: PathBuf,
    pub vault: crate::vault::Vault,
    /// Webs que el usuario ha decidido abrir sin cifrar (solo mientras Sombra está abierto).
    pub http_ok: Mutex<HashSet<String>>,
    /// Webs que ya sabemos que tienen https (solo mientras Sombra está abierto).
    pub https_known: Mutex<HashSet<String>>,
    /// AutoFirma: hasta cuándo y por qué puertos puede la web hablar con ella (ver start_afirma).
    afirma: Mutex<Option<(std::time::Instant, Vec<u16>)>>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Shared {
    pub fn new(data_dir: PathBuf) -> Arc<Self> {
        let settings: Settings = read_json(&data_dir.join("settings.json")).unwrap_or_default();
        crate::doh::ENABLED.store(settings.secure_dns, std::sync::atomic::Ordering::Relaxed);
        let bookmarks: Vec<Bookmark> = read_json(&data_dir.join("bookmarks.json")).unwrap_or_default();
        let history: Vec<HistoryEntry> = if settings.history_mode == "save" {
            read_json(&data_dir.join("history.json")).unwrap_or_default()
        } else {
            let _ = std::fs::remove_file(data_dir.join("history.json"));
            Vec::new()
        };
        Arc::new(Self {
            history: Mutex::new(history),
            tor: Tor::new(),
            blocker: RwLock::new(None),
            blocking_enabled: AtomicBool::new(settings.blocking_enabled),
            stats: Stats::default(),
            tabs: Mutex::new(Tabs { next: 1, ..Default::default() }),
            downloads: Mutex::new(Vec::new()),
            top_hosts: RwLock::new(HashSet::new()),
            logs: Mutex::new(Vec::new()),
            settings: Mutex::new(settings),
            bookmarks: Mutex::new(bookmarks),
            approvals: Mutex::new(HashMap::new()),
            next_approval: AtomicU64::new(1),
            app: OnceLock::new(),
            vault: crate::vault::Vault::new(&data_dir),
            data_dir,
            http_ok: Mutex::new(HashSet::new()),
            https_known: Mutex::new(HashSet::new()),
            afirma: Mutex::new(None),
        })
    }

    /// Una pestaña normal ha abierto AutoFirma: durante 10 minutos la web puede hablar con
    /// ella en este mismo PC (127.0.0.1), solo por los puertos que van en el propio enlace
    /// (afirma://websocket?ports=50123,51234,... o afirma://service?ports=...). Fuera de eso,
    /// ninguna web llega a este PC. Sin puertos en el enlace (modo por servidor), nada se abre.
    pub fn start_afirma(&self, uri: &str) {
        let new: Vec<u16> = url::Url::parse(uri)
            .ok()
            .and_then(|u| u.query_pairs().find(|(k, _)| k == "ports").map(|(_, v)| v.split(',').filter_map(|p| p.trim().parse().ok()).collect()))
            .unwrap_or_default();
        let mut new: Vec<u16> = new.into_iter().filter(|p| *p >= 1024).take(8).collect();
        if new.is_empty() {
            return;
        }
        let mut g = self.afirma.lock();
        // Se conservan los puertos de un intento anterior aún vigente (AutoFirma reintenta con
        // puertos nuevos), como mucho 12.
        if let Some((_, old)) = g.as_ref().filter(|(t, _)| std::time::Instant::now() < *t) {
            for p in old {
                if !new.contains(p) && new.len() < 12 {
                    new.push(*p);
                }
            }
        }
        *g = Some((std::time::Instant::now() + Duration::from_secs(600), new));
    }

    pub fn afirma_port(&self, port: u16) -> bool {
        self.afirma.lock().as_ref().is_some_and(|(t, ps)| std::time::Instant::now() < *t && ps.contains(&port))
    }

    pub fn blocker(&self) -> Option<Arc<Blocker>> {
        self.blocker.read().clone()
    }

    pub fn set_blocker(&self, b: Blocker) {
        *self.blocker.write() = Some(Arc::new(b));
    }

    /// ¿Ha aceptado el usuario abrir esta web (o su dominio) sin cifrar?
    pub fn http_allowed(&self, host: &str) -> bool {
        self.http_ok.lock().iter().any(|a| host == a || host.ends_with(&format!(".{a}")))
    }

    /// Hosts de las webs abiertas en las pestañas: nunca se bloquean.
    pub fn is_top_level_host(&self, host: &str) -> bool {
        self.top_hosts.read().contains(host)
    }

    pub fn refresh_top_hosts(&self) {
        let set: HashSet<String> = self
            .tabs
            .lock()
            .list
            .iter()
            .filter_map(|t| url::Url::parse(&t.url).ok().and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase())))
            .collect();
        *self.top_hosts.write() = set;
    }

    pub fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) {
        if let Some(app) = self.app.get() {
            let _ = app.emit_to(EventTarget::webview("ui"), event, payload);
        }
    }

    /// Registro traducible: `code` + `params` se traducen en la interfaz; `message` es el texto de reserva.
    pub fn log_code(&self, kind: &str, code: &str, params: serde_json::Value, message: String) {
        let e = LogEntry { time: now(), kind: kind.into(), code: code.into(), params, message };
        self.store_log(e.clone());
        if kind == "intruso" {
            self.emit("intruder", e);
        }
    }

    fn store_log(&self, e: LogEntry) {
        {
            let mut l = self.logs.lock();
            l.push(e.clone());
            let n = l.len();
            if n > 500 {
                l.drain(0..n - 500);
            }
        }
        self.emit("log", e);
    }

    // ---------- Historial ----------

    pub fn add_history(&self, url: &str, title: &str) {
        let (mode, skip_search) = {
            let s = self.settings.lock();
            let prefix = s.search_prefix();
            (s.history_mode.clone(), !s.history_searches && prefix.len() > 8 && url.starts_with(prefix))
        };
        if mode == "off" || skip_search || !(url.starts_with("http://") || url.starts_with("https://")) {
            return;
        }
        {
            let mut h = self.history.lock();
            if let Some(last) = h.last_mut() {
                if last.url == url {
                    last.time = now();
                    if !title.is_empty() {
                        last.title = title.to_string();
                    }
                    drop(h);
                    self.save_history_as(&mode);
                    return;
                }
            }
            h.push(HistoryEntry { url: url.into(), title: title.into(), time: now() });
            let n = h.len();
            if n > MAX_HISTORY {
                h.drain(0..n - MAX_HISTORY);
            }
        }
        self.save_history_as(&mode);
    }

    /// Guarda solo si el modo leído al principio era "save" Y sigue siéndolo
    /// (evita escribir en disco si el usuario acaba de desactivar el guardado).
    fn save_history_as(&self, mode_at_start: &str) {
        if mode_at_start == "save" {
            self.save_history_if_needed();
        }
    }

    pub fn set_history_title(&self, url: &str, title: &str) {
        if title.trim().is_empty() {
            return;
        }
        let changed = {
            let mut h = self.history.lock();
            match h.iter_mut().rev().take(300).find(|e| e.url == url) {
                Some(e) if e.title != title => {
                    e.title = title.to_string();
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.save_history_if_needed();
        }
    }

    pub fn save_history_if_needed(&self) {
        if self.settings.lock().history_mode == "save" {
            let h = self.history.lock().clone();
            write_json(&self.data_dir.join("history.json"), &h);
        }
    }

    pub fn clear_history(&self) {
        self.history.lock().clear();
        let _ = std::fs::remove_file(self.data_dir.join("history.json"));
    }

    fn push_log(&self, kind: &str, message: String) {
        let e = LogEntry { time: now(), kind: kind.into(), code: String::new(), params: serde_json::Value::Null, message };
        self.store_log(e);
    }

    /// Evento de seguridad traducible.
    pub fn sec(&self, code: &str, params: serde_json::Value, fallback: String) {
        self.log_code("seguridad", code, params, fallback);
    }

    /// Alerta de intrusión traducible (se muestra también como aviso).
    pub fn intruder(&self, code: &str, params: serde_json::Value, fallback: String) {
        self.log_code("intruso", code, params, fallback);
    }

    pub fn log_ai(&self, message: String) {
        self.push_log("ia", message);
    }

    pub fn save_settings(&self) {
        let s = self.settings.lock().clone();
        write_json(&self.data_dir.join("settings.json"), &s);
    }

    pub fn save_bookmarks(&self) {
        let b = self.bookmarks.lock().clone();
        write_json(&self.data_dir.join("bookmarks.json"), &b);
    }

    /// Pide permiso al usuario en la interfaz. Si no contesta en 2 minutos, se deniega.
    /// `kind` + `params` se traducen en la interfaz; `message` es el texto de reserva.
    pub async fn ask_user(&self, kind: &str, params: serde_json::Value, message: String) -> bool {
        let id = self.next_approval.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.approvals.lock().insert(id, tx);
        self.emit("approval", serde_json::json!({ "id": id, "kind": kind, "params": params, "message": message }));
        if let Some(app) = self.app.get() {
            use tauri::Manager;
            if let Some(w) = app.get_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }
        let res = tokio::time::timeout(Duration::from_secs(120), rx).await;
        self.approvals.lock().remove(&id);
        let ok = matches!(res, Ok(Ok(true)));
        self.emit("approval-closed", id);
        ok
    }

    pub fn resolve_approval(&self, id: u64, allow: bool) {
        if let Some(tx) = self.approvals.lock().remove(&id) {
            let _ = tx.send(allow);
        }
    }

    pub fn deny_all_approvals(&self) {
        for (_, tx) in self.approvals.lock().drain() {
            let _ = tx.send(false);
        }
    }
}

pub fn read_json<T: for<'de> Deserialize<'de>>(p: &PathBuf) -> Option<T> {
    let s = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&s).ok()
}

/// Guarda un archivo de datos de forma segura: primero en uno temporal y luego lo cambia de
/// nombre. En Linux/Android solo lo puede leer tu usuario (permisos 600).
pub fn write_json<T: Serialize>(p: &PathBuf, v: &T) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        // Nombre temporal único: si dos guardados coinciden, no se pisan el archivo a medias.
        let tmp = p.with_extension(format!("{:016x}.tmp", rand::random::<u64>()));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let ok = o.open(&tmp).and_then(|mut f| {
            use std::io::Write;
            f.write_all(s.as_bytes())?;
            f.sync_all()
        });
        if ok.is_ok() && std::fs::rename(&tmp, p).is_ok() {
            return;
        }
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Linux/Android: la carpeta de datos de Sombra solo es accesible para tu usuario (700).
pub fn protect_dir(p: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = p;
}

// ---------- Sugerencias de la barra de direcciones ----------

#[derive(Serialize, Debug)]
pub struct Suggestion {
    pub url: String,
    pub title: String,
    /// "bookmark" | "history"
    pub kind: &'static str,
}

/// La dirección sin "https://" ni "www.", para comparar con lo que se escribe.
fn bare_url(url: &str) -> &str {
    let u = url.split_once("://").map_or(url, |(_, r)| r);
    u.strip_prefix("www.").unwrap_or(u)
}

/// Sugerencias para lo escrito en la barra: solo con lo que ya hay en este equipo (favoritos e
/// historial), nunca se envía nada a ningún sitio mientras se escribe. Cada palabra tiene que
/// aparecer en la dirección o en el título. Primero lo que empieza por lo escrito, los favoritos
/// y lo más visitado y reciente.
pub fn suggestions(history: &[HistoryEntry], bookmarks: &[Bookmark], query: &str, now: u64, limit: usize) -> Vec<Suggestion> {
    let q = query.trim().to_lowercase();
    let q = bare_url(&q).to_string();
    let words: Vec<&str> = q.split_whitespace().collect();
    if words.is_empty() || limit == 0 {
        return Vec::new();
    }
    struct Agg<'a> {
        title: &'a str,
        visits: u32,
        last: u64,
        bookmark: bool,
    }
    let mut seen: HashMap<&str, Agg> = HashMap::new();
    for e in history {
        let a = seen.entry(e.url.as_str()).or_insert(Agg { title: "", visits: 0, last: 0, bookmark: false });
        a.visits += 1;
        if e.time >= a.last {
            a.last = e.time;
            if !e.title.is_empty() {
                a.title = &e.title;
            }
        }
    }
    for b in bookmarks {
        let a = seen.entry(b.url.as_str()).or_insert(Agg { title: "", visits: 0, last: 0, bookmark: false });
        a.bookmark = true;
        if !b.title.is_empty() {
            a.title = &b.title;
        }
    }
    let mut out: Vec<(f64, Suggestion)> = seen
        .into_iter()
        .filter_map(|(url, a)| {
            let bare = bare_url(url).to_lowercase();
            let title = a.title.to_lowercase();
            if !words.iter().all(|w| bare.contains(w) || title.contains(w)) {
                return None;
            }
            let mut score = (1.0 + a.visits as f64).ln() * 10.0;
            if a.visits > 0 {
                let days = now.saturating_sub(a.last) as f64 / 86400.0;
                score += 20.0 / (1.0 + days);
            }
            if a.bookmark {
                score += 30.0;
            }
            if bare.starts_with(&q) {
                score += 50.0;
            } else if title.starts_with(&q) || title.split_whitespace().any(|t| t.starts_with(words[0])) {
                score += 10.0;
            }
            // Ante la duda, la página principal antes que una página interior.
            score -= bare.len() as f64 / 100.0;
            Some((score, Suggestion { url: url.to_string(), title: a.title.to_string(), kind: if a.bookmark { "bookmark" } else { "history" } }))
        })
        .collect();
    out.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.url.cmp(&b.1.url)));
    out.into_iter().take(limit).map(|(_, s)| s).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(url: &str, title: &str, time: u64) -> HistoryEntry {
        HistoryEntry { url: url.into(), title: title.into(), time }
    }

    #[test]
    fn sugerencias() {
        let now = 100_000_000;
        let hist = vec![
            h("https://www.youtube.com/", "YouTube", now - 100),
            h("https://www.youtube.com/", "YouTube", now - 50),
            h("https://www.youtube.com/watch?v=1", "Un vídeo", now - 10),
            h("https://es.wikipedia.org/wiki/Tor", "Tor - Wikipedia", now - 86400 * 30),
            h("https://example.com/you", "Otra", now - 5),
        ];
        let bm = vec![Bookmark { url: "https://github.com/".into(), title: "GitHub".into(), folder: String::new() }];
        let r = suggestions(&hist, &bm, "you", now, 8);
        assert_eq!(r[0].url, "https://www.youtube.com/");
        assert_eq!(r.len(), 3);
        // "https://" y "www." escritos no impiden encontrarla.
        assert_eq!(suggestions(&hist, &bm, "https://www.yout", now, 8)[0].url, "https://www.youtube.com/");
        // Varias palabras: todas tienen que aparecer (en la dirección o en el título).
        let r = suggestions(&hist, &bm, "tor wiki", now, 8);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].title, "Tor - Wikipedia");
        // Favorito sin visitas.
        let r = suggestions(&hist, &bm, "git", now, 8);
        assert_eq!((r[0].url.as_str(), r[0].kind), ("https://github.com/", "bookmark"));
        assert!(suggestions(&hist, &bm, "   ", now, 8).is_empty());
        assert!(suggestions(&hist, &bm, "zzz", now, 8).is_empty());
        assert_eq!(suggestions(&hist, &bm, "o", now, 2).len(), 2);
    }
}
