// Sombra - navegador ligero y privado. Sin publicidad, con Tor integrado y control para IAs.
// Copyright (C) 2026 Sombra contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of
// the GNU General Public License as published by the Free Software Foundation, either version 3
// of the License, or (at your option) any later version. See the LICENSE file.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod blocker;
mod control;
mod doh;
mod downloads;
mod proxy;
mod state;
mod tabs;
mod tor;
mod vault;

use serde_json::{json, Value};
use state::{Bookmark, Shared};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::webview::WebviewBuilder;
use tauri::{AppHandle, LogicalPosition, Manager, State, WebviewUrl};

type Sh<'a> = State<'a, Arc<Shared>>;

fn e2s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Certificado digital: qué se puede hacer en este sistema.
#[tauri::command]
fn cert_info() -> Value {
    json!({ "manager": cfg!(windows), "autofirma": autofirma_installed() })
}

fn autofirma_installed() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // AutoFirma registra el protocolo afirma:// al instalarse.
        std::process::Command::new("reg")
            .args(["query", r"HKCR\afirma"])
            .creation_flags(0x0800_0000)
            .output()
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-mime")
            .args(["query", "default", "x-scheme-handler/afirma"])
            .output()
            .is_ok_and(|o| o.status.success() && o.stdout.trim_ascii().ends_with(b".desktop"))
    }
}

/// Abre el gestor de certificados de Windows (importar un .p12/.pfx, verlos, exportarlos).
/// La contraseña del certificado la escribes tú en la ventana de Windows; Sombra no la ve.
#[tauri::command]
fn open_cert_manager() -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("rundll32.exe").arg("cryptui.dll,CryptUIStartCertMgr").spawn().map(|_| ()).map_err(e2s)
    }
    #[cfg(not(windows))]
    {
        Err("Solo en Windows".into())
    }
}

#[tauri::command]
fn get_state(sh: Sh) -> Value {
    let t = sh.tabs.lock();
    let ctl = control::control();
    let active_client = ctl.active_client.lock().clone();
    json!({
        "tabs": t.list,
        "active": t.active,
        "tor": sh.tor.status(),
        "stats": {
            "ads": sh.stats.ads.load(Ordering::Relaxed),
            "trackers": sh.stats.trackers.load(Ordering::Relaxed),
            "leaks": sh.stats.leaks_blocked.load(Ordering::Relaxed),
            "page": sh.stats.page_blocked.load(Ordering::Relaxed),
            "connections": sh.stats.connections.load(Ordering::Relaxed),
        },
        "blocker_ready": sh.blocker().is_some(),
        "settings": *sh.settings.lock(),
        "bookmarks": *sh.bookmarks.lock(),
        "control": {
            "enabled": control::is_running(),
            "port": control::port(),
            "client": active_client.map(|(c, t, a)| json!({ "name": c, "time": t, "action": a })),
            "token_file": sh.data_dir.join("control.json"),
        },
    })
}

#[tauri::command]
async fn new_tab(app: AppHandle, sh: Sh<'_>, url: Option<String>, private: Option<bool>) -> Result<u32, String> {
    match private {
        Some(p) => tabs::new_tab_mode(&app, &sh, url, p).await.map_err(e2s),
        None => tabs::new_tab(&app, &sh, url).await.map_err(e2s),
    }
}

#[tauri::command]
async fn close_tab(app: AppHandle, sh: Sh<'_>, id: u32) -> Result<(), String> {
    tabs::close(&app, &sh, id).await.map_err(e2s)
}

/// Descargas de esta sesión.
#[tauri::command]
fn downloads_list(sh: Sh) -> Vec<downloads::Download> {
    sh.downloads.lock().clone()
}

/// Muestra el archivo descargado en su carpeta.
#[tauri::command]
fn download_show(sh: Sh, id: u32) -> Result<(), String> {
    let p = downloads::path_of(&sh, id).ok_or("No existe esa descarga")?;
    downloads::reveal(&p).map_err(e2s)
}

#[tauri::command]
fn download_cancel(app: AppHandle, id: u32) {
    let _ = app.run_on_main_thread(move || downloads::cancel_native(id));
}

/// Quita de la lista una descarga terminada (o todas las terminadas).
#[tauri::command]
fn download_dismiss(sh: Sh, id: Option<u32>) {
    downloads::dismiss(&sh, id);
}

/// Reabre una pestaña cerrada (la última si no se dice cuál).
#[tauri::command]
async fn reopen_tab(app: AppHandle, sh: Sh<'_>, index: Option<usize>) -> Result<Option<u32>, String> {
    tabs::reopen(&app, &sh, index).await.map_err(e2s)
}

/// Pestañas cerradas, la más reciente primero.
#[tauri::command]
fn closed_tabs(sh: Sh) -> Vec<state::ClosedTab> {
    sh.tabs.lock().closed.iter().rev().cloned().collect()
}

#[tauri::command]
fn activate_tab(app: AppHandle, sh: Sh, id: u32) {
    tabs::activate(&app, &sh, id);
}

/// Permisos guardados de las webs (modo normal).
#[tauri::command]
fn site_perms(sh: Sh) -> Vec<state::SitePerm> {
    let mut l = sh.site_perms.lock().clone();
    l.sort_by(|a, b| (&a.origin, &a.perm).cmp(&(&b.origin, &b.perm)));
    l
}

/// Cambia (permitir/bloquear) o quita (`allow` vacío) un permiso guardado.
#[tauri::command]
fn site_perm_set(sh: Sh, origin: String, perm: String, allow: Option<bool>) -> Result<(), String> {
    if !state::PERMS.contains(&perm.as_str()) || state::origin_of(&origin).as_deref() != Some(origin.as_str()) {
        return Err("Permiso no válido".into());
    }
    match allow {
        Some(a) => sh.set_site_perm(&origin, &perm, a),
        None => sh.remove_site_perm(&origin, Some(&perm)),
    }
    Ok(())
}

#[tauri::command]
fn move_tab(sh: Sh, id: u32, to: usize) {
    tabs::move_tab(&sh, id, to);
}

#[tauri::command]
async fn navigate(app: AppHandle, sh: Sh<'_>, id: Option<u32>, input: String) -> Result<(), String> {
    let id = match id.or_else(|| tabs::active_id(&sh)) {
        Some(i) => i,
        None => tabs::new_tab(&app, &sh, None).await.map_err(e2s)?,
    };
    tabs::navigate(&app, &sh, id, &input).await.map_err(e2s)
}

#[tauri::command]
async fn nav_action(app: AppHandle, sh: Sh<'_>, action: String) -> Result<(), String> {
    let Some(id) = tabs::active_id(&sh) else { return Ok(()) };
    if action == "home" {
        tabs::go_home(&app, &sh, id);
        return Ok(());
    }
    // Pestaña con el aviso de "sin https": Recargar vuelve a probar si la web tiene https.
    if action == "reload" {
        let warn = sh.tabs.lock().list.iter().find(|t| t.id == id && t.https_warn).map(|t| t.url.clone());
        if let Some(url) = warn {
            return tabs::navigate(&app, &sh, id, &url).await.map_err(e2s);
        }
    }
    let js = match action.as_str() {
        "back" => "history.back()",
        "forward" => "history.forward()",
        "reload" => "location.reload()",
        "stop" => "window.stop()",
        _ => return Ok(()),
    };
    tabs::eval_tab(&app, id, format!("(() => {{ {js}; return 'ok'; }})()")).await.map(|_| ()).map_err(e2s)
}

#[tauri::command]
fn set_content_rect(app: AppHandle, sh: Sh, x: f64, y: f64, w: f64, h: f64) {
    sh.tabs.lock().rect = (x, y, w, h);
    tabs::layout(&app, &sh);
}

#[tauri::command]
fn set_country(sh: Sh, code: Option<String>) -> Result<(), String> {
    sh.tor.set_country(code.as_deref()).map_err(e2s)?;
    sh.settings.lock().country = sh.tor.status().country;
    sh.save_settings();
    Ok(())
}

#[tauri::command]
fn new_identity(sh: Sh) {
    sh.tor.new_identity();
    sh.sec("newIdLog", json!({}), "Nueva identidad de Tor: circuitos nuevos".into());
}

#[tauri::command]
fn set_blocking(sh: Sh, enabled: bool) {
    sh.blocking_enabled.store(enabled, Ordering::Relaxed);
    sh.settings.lock().blocking_enabled = enabled;
    sh.save_settings();
}

const LANGS: [&str; 14] = ["auto", "es", "en", "fr", "de", "it", "pt", "ca", "nl", "pl", "ru", "zh", "ja", "ar"];

/// Cambia ajustes. Solo se aceptan valores válidos; lo desconocido se ignora.
#[tauri::command]
fn set_settings(sh: Sh, patch: Value) -> Result<Value, String> {
    let mut history_change: Option<String> = None;
    {
        let mut s = sh.settings.lock();
        if let Some(v) = patch.get("search").and_then(|v| v.as_str()) {
            let v = v.trim();
            let ok = url::Url::parse(&v.replace("%s", "x")).map(|u| matches!(u.scheme(), "http" | "https")).unwrap_or(false);
            if !ok || !(v.contains("%s") || v.ends_with('=')) {
                return Err("searchInvalid".into());
            }
            s.search = v.to_string();
        }
        if let Some(v) = patch.get("language").and_then(|v| v.as_str()) {
            if LANGS.contains(&v) {
                s.language = v.into();
            }
        }
        if let Some(v) = patch.get("theme").and_then(|v| v.as_str()) {
            if ["dark", "light", "system"].contains(&v) {
                s.theme = v.into();
            }
        }
        if let Some(v) = patch.get("accent").and_then(|v| v.as_str()) {
            if ["violet", "blue", "green", "pink", "orange"].contains(&v) {
                s.accent = v.into();
            }
        }
        if let Some(v) = patch.get("font_size").and_then(|v| v.as_u64()) {
            s.font_size = v.clamp(11, 18) as u8;
        }
        if let Some(v) = patch.get("compact").and_then(|v| v.as_bool()) {
            s.compact = v;
        }
        if let Some(v) = patch.get("show_bookmarks").and_then(|v| v.as_bool()) {
            s.show_bookmarks = v;
        }
        if let Some(v) = patch.get("clean_on_exit").and_then(|v| v.as_bool()) {
            s.clean_on_exit = v;
        }
        if let Some(v) = patch.get("history_searches").and_then(|v| v.as_bool()) {
            s.history_searches = v;
        }
        if let Some(v) = patch.get("vault_lock_min").and_then(|v| v.as_u64()) {
            s.vault_lock_min = v.min(240) as u32;
        }
        if let Some(v) = patch.get("fp_strict").and_then(|v| v.as_bool()) {
            s.fp_strict = v;
        }
        if let Some(v) = patch.get("https_only").and_then(|v| v.as_bool()) {
            s.https_only = v;
        }
        if let Some(v) = patch.get("default_private").and_then(|v| v.as_bool()) {
            s.default_private = v;
        }
        if let Some(v) = patch.get("secure_dns").and_then(|v| v.as_bool()) {
            s.secure_dns = v;
            doh::ENABLED.store(v, std::sync::atomic::Ordering::Relaxed);
            doh::clear();
        }
        if let Some(v) = patch.get("block_3p_cookies").and_then(|v| v.as_bool()) {
            s.block_3p_cookies = v;
        }
        if let Some(v) = patch.get("restore_session").and_then(|v| v.as_bool()) {
            s.restore_session = v;
        }
        if let Some(v) = patch.get("security_level").and_then(|v| v.as_u64()) {
            s.security_level = v.min(2) as u8;
        }
        if let Some(v) = patch.get("history_mode").and_then(|v| v.as_str()) {
            if ["off", "session", "save"].contains(&v) && s.history_mode != v {
                s.history_mode = v.into();
                history_change = Some(v.into());
            }
        }
    }
    match history_change.as_deref() {
        Some("off") => sh.clear_history(),
        Some("session") => {
            let _ = std::fs::remove_file(sh.data_dir.join("history.json"));
        }
        Some("save") => sh.save_history_if_needed(),
        _ => {}
    }
    sh.save_settings();
    // La sesión puede haber dejado de quererse (o volver a quererse): se revisa enseguida.
    sh.session_dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(app) = sh.app.get() {
        tabs::layout(app, &sh);
        refresh_js(app, sh.inner());
    }
    Ok(json!(*sh.settings.lock()))
}

/// Tras cambiar el nivel de seguridad o los permisos de una web: si la pestaña activa tiene
/// JavaScript al revés de lo que ahora le toca, se vuelve a abrir (con la misma dirección).
fn refresh_js(app: &AppHandle, sh: &Arc<Shared>) {
    let Some(id) = tabs::active_id(sh) else { return };
    let Some(url) = sh.tabs.lock().list.iter().find(|t| t.id == id && t.has_view).map(|t| t.url.clone()) else { return };
    let Ok(u) = url::Url::parse(&url) else { return };
    if tabs::tab_js(id) == Some(tabs::js_allowed(sh, &u, tabs::tab_private(sh, id))) {
        return;
    }
    let (app, sh) = (app.clone(), sh.clone());
    tauri::async_runtime::spawn(async move {
        let _ = tabs::navigate(&app, &sh, id, &url).await;
    });
}

/// Modo solo HTTPS: el usuario decide abrir sin cifrar la web del aviso de esa pestaña
/// (vale para esa web y sus subdominios, solo hasta cerrar Sombra).
#[tauri::command]
async fn allow_http(app: AppHandle, sh: Sh<'_>, id: u32) -> Result<(), String> {
    let url = sh.tabs.lock().list.iter().find(|t| t.id == id && t.https_warn).map(|t| t.url.clone()).ok_or("sin aviso")?;
    let u = url::Url::parse(&url).map_err(e2s)?;
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    if host.is_empty() {
        return Err("web no válida".into());
    }
    sh.sec("httpAllowed", json!({ "host": host }), format!("Abierta sin cifrar (http): {host}"));
    sh.http_ok.lock().insert(host);
    tabs::navigate(&app, &sh, id, &url).await.map_err(e2s)
}

/// Permitir o volver a bloquear JavaScript en una web (cuando el nivel de seguridad lo bloquea).
#[tauri::command]
fn set_js_site(app: AppHandle, sh: Sh, host: String, allow: bool) -> Result<Value, String> {
    let host = host.trim().trim_start_matches("www.").to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err("web no válida".into());
    }
    {
        let mut s = sh.settings.lock();
        s.js_allow.retain(|h| *h != host);
        if allow {
            s.js_allow.push(host);
        }
    }
    sh.save_settings();
    refresh_js(&app, sh.inner());
    Ok(json!(*sh.settings.lock()))
}

/// Barra de la ventana propia (Linux): "min", "max" (maximizar / restaurar), "close"
/// y "drag" (mover la ventana arrastrando la barra de pestañas).
#[tauri::command]
fn window_action(app: AppHandle, action: String) -> Result<(), String> {
    let w = app.get_window("main").ok_or("sin ventana")?;
    match action.as_str() {
        "min" => w.minimize().map_err(e2s),
        "close" => w.close().map_err(e2s),
        "drag" => w.start_dragging().map_err(e2s),
        a if a.starts_with("resize:") => {
            use tauri_runtime::ResizeDirection as D;
            let d = match &a[7..] {
                "North" => D::North,
                "South" => D::South,
                "East" => D::East,
                "West" => D::West,
                "NorthEast" => D::NorthEast,
                "NorthWest" => D::NorthWest,
                "SouthEast" => D::SouthEast,
                "SouthWest" => D::SouthWest,
                _ => return Err("dirección desconocida".into()),
            };
            w.start_resize_dragging(d).map_err(e2s)
        }
        "max" => {
            if w.is_maximized().map_err(e2s)? {
                w.unmaximize().map_err(e2s)
            } else {
                w.maximize().map_err(e2s)
            }
        }
        _ => Err("acción desconocida".into()),
    }
}

/// Historial, del más reciente al más antiguo, filtrado por texto.
#[tauri::command]
fn get_history(sh: Sh, query: Option<String>, limit: Option<usize>) -> Value {
    let q = query.unwrap_or_default().to_lowercase();
    let h = sh.history.lock();
    let items: Vec<&state::HistoryEntry> = h
        .iter()
        .rev()
        .filter(|e| q.is_empty() || e.url.to_lowercase().contains(&q) || e.title.to_lowercase().contains(&q))
        .take(limit.unwrap_or(300).min(2000))
        .collect();
    json!({ "items": items, "total": h.len() })
}

/// Sugerencias de la barra de direcciones (favoritos e historial de este equipo).
#[tauri::command]
fn suggest(sh: Sh, query: String) -> Vec<state::Suggestion> {
    let h = sh.history.lock();
    let b = sh.bookmarks.lock();
    state::suggestions(&h, &b, &query, state::now(), 8)
}

#[tauri::command]
fn remove_history(sh: Sh, url: String) {
    sh.history.lock().retain(|e| e.url != url);
    sh.save_history_if_needed();
}

/// Limpiador: borra lo que el usuario marque.
#[tauri::command]
async fn clean(app: AppHandle, sh: Sh<'_>, opts: Value) -> Result<Value, String> {
    let on = |k: &str| opts.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let mut done = Vec::new();
    if on("history") {
        sh.clear_history();
        sh.clear_session();
        sh.tabs.lock().closed.clear();
        doh::clear();
        done.push("history");
    }
    if on("cache") {
        let ids: Vec<u32> = sh.tabs.lock().list.iter().map(|t| t.id).collect();
        for id in ids {
            if let Some(wv) = app.get_webview(&tabs::label(id)) {
                let _ = wv.clear_all_browsing_data();
            }
        }
        done.push("cache");
    }
    if on("logs") {
        sh.logs.lock().clear();
        done.push("logs");
    }
    if on("identity") {
        sh.tor.new_identity();
        done.push("identity");
    }
    if on("tabs") {
        let ids: Vec<u32> = sh.tabs.lock().list.iter().map(|t| t.id).collect();
        for id in ids {
            let _ = tabs::close(&app, &sh, id).await;
        }
        // Cerrar todas para borrarlas: tampoco se pueden reabrir.
        sh.tabs.lock().closed.clear();
        doh::clear();
        done.push("tabs");
    }
    if on("stats") {
        for a in [&sh.stats.ads, &sh.stats.trackers, &sh.stats.leaks_blocked, &sh.stats.page_blocked, &sh.stats.connections] {
            a.store(0, Ordering::Relaxed);
        }
        done.push("stats");
    }
    sh.sec("cleaned", json!({ "what": done }), format!("Limpieza: {}", done.join(", ")));
    Ok(json!({ "done": done }))
}

#[tauri::command]
fn add_bookmark(sh: Sh, url: String, title: String, folder: Option<String>) {
    {
        let mut b = sh.bookmarks.lock();
        if !b.iter().any(|x| x.url == url) {
            b.push(Bookmark { url, title, folder: folder.unwrap_or_default() });
        }
    }
    sh.save_bookmarks();
}

#[tauri::command]
fn remove_bookmark(sh: Sh, url: String) {
    sh.bookmarks.lock().retain(|x| x.url != url);
    sh.save_bookmarks();
}

#[tauri::command]
async fn set_control(app: AppHandle, sh: Sh<'_>, enabled: bool) -> Result<u16, String> {
    sh.settings.lock().control_enabled = enabled;
    sh.save_settings();
    if enabled {
        control::start(app, sh.inner().clone()).await.map_err(e2s)
    } else {
        control::stop(&sh);
        Ok(0)
    }
}

#[tauri::command]
fn cut_ai(sh: Sh) {
    control::cut(&sh);
}

#[tauri::command]
fn resolve_approval(sh: Sh, id: u64, allow: bool) {
    sh.resolve_approval(id, allow);
}

#[tauri::command]
fn get_logs(sh: Sh) -> Value {
    json!(*sh.logs.lock())
}

#[tauri::command]
fn clear_logs(sh: Sh) {
    sh.logs.lock().clear();
}

/// Intentos de huella digital detectados en la pestaña activa.
#[tauri::command]
async fn page_privacy(app: AppHandle, sh: Sh<'_>) -> Result<Value, String> {
    let Some(id) = tabs::active_id(&sh) else { return Ok(json!(null)) };
    let has_view = sh.tabs.lock().list.iter().any(|t| t.id == id && t.has_view);
    if !has_view {
        return Ok(json!(null));
    }
    // Nivel de seguridad: si la web tiene JavaScript y si el usuario la ha permitido.
    let url = sh.tabs.lock().list.iter().find(|t| t.id == id).map(|t| t.url.clone()).unwrap_or_default();
    let host = url::Url::parse(&url).ok().and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_ascii_lowercase())).unwrap_or_default();
    let (level, allowed) = {
        let s = sh.settings.lock();
        (s.security_level, s.js_allow.iter().any(|h| *h == host))
    };
    let tab_js = tabs::tab_js(id).unwrap_or(true);
    let mut v = if tab_js {
        let key = &tabs::ENGINE.get().map(|e| e.fp_key.clone()).unwrap_or_default();
        let js = format!("(() => {{ const s = window['{key}']; return s ? s.read() : JSON.stringify({{ fp: 0, kinds: {{}} }}); }})()");
        tabs::eval_tab(&app, id, js).await.unwrap_or_else(|_| json!({ "fp": 0, "kinds": {} }))
    } else {
        // Sin JavaScript la web no puede intentar sacar la huella (y no se le pregunta nada).
        json!({ "fp": 0, "kinds": {} })
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("js".into(), json!(tab_js));
        o.insert("level".into(), json!(level));
        o.insert("host".into(), json!(host));
        o.insert("site_allowed".into(), json!(allowed));
    }
    Ok(v)
}

/* ---------- contraseñas ---------- */

/// Las operaciones con la contraseña maestra tardan medio segundo (Argon2): fuera del hilo principal.
async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> Result<R, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(e2s)
}

#[tauri::command]
fn vault_status(sh: Sh) -> Value {
    sh.vault.status()
}

#[tauri::command]
async fn vault_create(sh: Sh<'_>, password: String, hint: String, lang: String) -> Result<String, String> {
    let s = sh.inner().clone();
    let r = blocking(move || s.vault.create(&password, &hint, &lang)).await?;
    sh.emit("vault", sh.vault.status());
    r
}

#[tauri::command]
async fn vault_unlock(sh: Sh<'_>, password: String) -> Result<(), String> {
    let s = sh.inner().clone();
    let r = blocking(move || s.vault.unlock(&password)).await?;
    if r.is_err() {
        sh.sec("vaultBad", json!({}), "Contraseña maestra incorrecta".into());
    }
    sh.emit("vault", sh.vault.status());
    r
}

#[tauri::command]
async fn vault_recover(sh: Sh<'_>, phrase: String, password: String, hint: String) -> Result<(), String> {
    let s = sh.inner().clone();
    let r = blocking(move || s.vault.recover(&phrase, &password, &hint)).await?;
    if r.is_err() {
        sh.sec("vaultBadPhrase", json!({}), "Frase de recuperación incorrecta".into());
    }
    sh.emit("vault", sh.vault.status());
    r
}

#[tauri::command]
fn vault_lock(sh: Sh) {
    sh.vault.lock();
    sh.emit("vault", sh.vault.status());
}

#[tauri::command]
fn vault_list(sh: Sh, query: String) -> Result<Value, String> {
    sh.vault.list(&query)
}

#[tauri::command]
fn vault_reveal(sh: Sh, id: u64) -> Result<String, String> {
    sh.vault.reveal(id)
}

#[tauri::command]
fn vault_delete(sh: Sh, id: u64) -> Result<(), String> {
    sh.vault.delete(id)?;
    sh.emit("vault", sh.vault.status());
    Ok(())
}

#[tauri::command]
fn vault_never_remove(sh: Sh, host: String) -> Result<(), String> {
    sh.vault.remove_never(&host)
}

/// Web de la pestaña activa, tal como la ve el motor (no lo que diga la página).
fn active_host(app: &AppHandle, sh: &Shared) -> Option<(u32, String)> {
    let id = tabs::active_id(sh)?;
    let url = app.get_webview(&tabs::label(id))?.url().ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    Some((id, url.host_str()?.to_string()))
}

#[tauri::command]
fn vault_matches(app: AppHandle, sh: Sh) -> Value {
    let st = sh.vault.status();
    let Some((_, host)) = active_host(&app, &sh) else { return json!({ "vault": st, "host": null, "items": [] }) };
    let items = sh.vault.matches(&host).unwrap_or_default();
    json!({ "vault": st, "host": host, "items": items })
}

/// Rellena el usuario y la contraseña en la pestaña activa. Solo la interfaz de
/// Sombra puede pedirlo (las IAs y las webs no). `generated`: contraseña nueva
/// para un registro (rellena los campos de contraseña vacíos).
#[tauri::command]
async fn vault_fill(app: AppHandle, sh: Sh<'_>, id: Option<u64>, generated: Option<String>) -> Result<String, String> {
    let (tab, host) = active_host(&app, &sh).ok_or("vaultNoMatch")?;
    let (user, pass, new) = match (id, generated) {
        (_, Some(g)) if !g.is_empty() => (String::new(), zeroize::Zeroizing::new(g), true),
        (Some(i), _) => {
            let (u, p) = sh.vault.for_fill(i, &host)?;
            (u, p, false)
        }
        _ => return Err("vaultNoMatch".into()),
    };
    let js = zeroize::Zeroizing::new(
        FILL_JS
            .replace("__USER__", &serde_json::to_string(&user).unwrap_or_default())
            .replace("__PASS__", &serde_json::to_string(pass.as_str()).unwrap_or_default())
            .replace("__NEW__", if new { "true" } else { "false" }),
    );
    let r = tabs::eval_tab(&app, tab, js.to_string()).await.map_err(e2s)?;
    Ok(r.as_str().unwrap_or("ok").to_string())
}

const FILL_JS: &str = r#"(() => { const U = __USER__, P = __PASS__, NEW = __NEW__;
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const set = (e, v) => { const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value'); d.set.call(e, v);
    e.dispatchEvent(new Event('input', { bubbles: true })); e.dispatchEvent(new Event('change', { bubbles: true })); };
  const pws = [...document.querySelectorAll('input[type=password]')].filter(vis);
  if (!pws.length) return 'nofield';
  if (NEW) { const empty = pws.filter(e => !e.value); (empty.length ? empty : pws).forEach(e => set(e, P)); return 'ok'; }
  const pw = pws[0]; set(pw, P);
  if (U) {
    const root = pw.form || document;
    const ins = [...root.querySelectorAll('input')].filter(e => vis(e) && /^(text|email|tel)$/.test(e.type) && (e.compareDocumentPosition(pw) & 4));
    const u = ins.reverse().find(e => /user|mail|login|name|usuario|correo/i.test((e.name || '') + (e.id || '') + (e.autocomplete || ''))) || ins[0];
    if (u && u.value !== U) set(u, U);
  }
  return 'ok'; })()"#;

/// Respuesta a "¿Guardar la contraseña?".
#[tauri::command]
fn cred_answer(sh: Sh, id: u64, action: String) -> Result<(), String> {
    sh.vault.answer(id, &action)?;
    sh.emit("vault", sh.vault.status());
    Ok(())
}

/// Recoge de la pestaña activa los avisos "se ha enviado una contraseña".
/// Las pestañas no tienen ningún canal con Sombra (ver vendor/PARCHE.md): es Sombra quien
/// pasa a preguntar. La web se toma del motor; si la página dice otra cosa, se descarta.
async fn collect_creds(app: &AppHandle, sh: &Shared) {
    let Some(id) = tabs::active_id(sh) else { return };
    if !sh.tabs.lock().list.iter().any(|t| t.id == id && t.has_view) {
        return;
    }
    let Some(wv) = app.get_webview(&tabs::label(id)) else { return };
    let Ok(url) = wv.url() else { return };
    if !matches!(url.scheme(), "http" | "https") {
        return;
    }
    let Some(host) = url.host_str().map(str::to_owned) else { return };
    let key = tabs::ENGINE.get().map(|e| e.fp_key.clone()).unwrap_or_default();
    let js = format!("(() => {{ const s = window['{key}']; return s ? s.take() : null; }})()");
    let Ok(v) = tabs::eval_tab(app, id, js).await else { return };
    let Some(items) = v.get("items").and_then(Value::as_array) else { return };
    if items.is_empty() || v.get("host").and_then(Value::as_str) != Some(host.as_str()) {
        return;
    }
    for it in items.iter().take(5) {
        let user = it.get("user").and_then(Value::as_str).unwrap_or("");
        let pass = zeroize::Zeroizing::new(it.get("pass").and_then(Value::as_str).unwrap_or("").to_string());
        if pass.is_empty() || pass.len() > 512 || user.len() > 200 {
            continue;
        }
        #[cfg(debug_assertions)]
        if std::env::var("SOMBRA_SELFTEST").is_ok() {
            log::warn!("SELFTEST aviso recibido de {host} (usuario: {user})");
        }
        if let Some(q) = sh.vault.capture(&host, user.trim(), pass) {
            sh.emit("cred", q);
        }
    }
}

/// Trae al frente la ventana de la Sombra que ya está abierta (Windows).
fn focus_existing(data_dir: &std::path::Path) {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextLengthW, GetWindowThreadProcessId, IsIconic, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
        };
        use windows_core::BOOL;
        let Some(pid) = std::fs::read_to_string(data_dir.join("sombra.pid")).ok().and_then(|s| s.trim().parse::<u32>().ok()) else {
            return;
        };
        unsafe extern "system" fn each(h: HWND, l: LPARAM) -> BOOL {
            let mut p = 0u32;
            unsafe {
                GetWindowThreadProcessId(h, Some(&mut p));
                if p == l.0 as u32 && IsWindowVisible(h).as_bool() && GetWindowTextLengthW(h) > 0 {
                    if IsIconic(h).as_bool() {
                        let _ = ShowWindow(h, SW_RESTORE);
                    }
                    let _ = SetForegroundWindow(h);
                    return BOOL(0);
                }
            }
            BOOL(1)
        }
        unsafe {
            let _ = EnumWindows(Some(each), LPARAM(pid as isize));
        }
    }
    #[cfg(not(windows))]
    let _ = data_dir;
}

fn main() {
    let _ = env_logger::try_init();
    let data_dir = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("Sombra");
    let _ = std::fs::create_dir_all(&data_dir);
    state::protect_dir(&data_dir);
    // Modo Sombra: nada de la navegación se conserva; su carpeta del motor se borra al abrir y
    // al cerrar. Modo normal: su propia carpeta, que se conserva (sesiones, cookies).
    // Una sola Sombra abierta a la vez: una segunda copia borraría la carpeta del modo Sombra
    // que usa la primera. Si ya hay una, se trae al frente su ventana y esta se cierra.
    let _lock = match std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(data_dir.join("sombra.lock")) {
        Ok(f) => {
            if f.try_lock().is_err() {
                focus_existing(&data_dir);
                return;
            }
            if let Err(e) = std::fs::write(data_dir.join("sombra.pid"), std::process::id().to_string()) {
                log::warn!("No se pudo guardar sombra.pid (otra copia no podrá traer esta ventana al frente): {e}");
            }
            Some(f)
        }
        Err(_) => None,
    };
    let web_dir = data_dir.join("webview");
    let normal_dir = data_dir.join("webview-normal");
    let _ = std::fs::remove_dir_all(&web_dir);
    let _ = std::fs::remove_file(data_dir.join("control.json"));

    let shared = Shared::new(data_dir.clone());

    // Idiomas reales del sistema, para la interfaz de Sombra (las webs pueden ver otros).
    let sys_langs: Vec<String> = sys_locale::get_locales().collect();
    let fp_strict = shared.settings.lock().fp_strict;
    // Huella digital reforzada: las webs piden las páginas en inglés (cabecera Accept-Language).
    // Windows: argumentos del motor (browser_args). Linux: idiomas del motor WebKit (abajo).
    // Se aplica al abrir Sombra.
    let level = shared.settings.lock().security_level;
    // Zona horaria real, para que la interfaz de Sombra muestre tu hora aunque las webs vean UTC.
    let sys_tz = iana_time_zone::get_timezone().unwrap_or_default();
    // Linux (WebKit): huella reforzada = todo el motor en UTC, también el código en segundo
    // plano (Workers), al que no llega el script de las páginas. En Windows el motor no hace
    // caso de esta variable: allí solo cambia la hora que ven las páginas (por script).
    #[cfg(target_os = "linux")]
    if fp_strict {
        std::env::set_var("TZ", "UTC");
    }
    // Linux (WebKit): niveles "más seguro" y "el más seguro" sin compilador JIT ni WebAssembly.
    // El motor lee estas variables al arrancar sus procesos, así que van antes de crear nada.
    #[cfg(target_os = "linux")]
    if level >= 1 {
        std::env::set_var("JSC_useJIT", "false");
        std::env::set_var("JSC_useWasm", "false");
    }

    tauri::Builder::default()
        .manage(shared.clone())
        .invoke_handler(tauri::generate_handler![
            get_state,
            cert_info,
            open_cert_manager,
            new_tab,
            close_tab,
            reopen_tab,
            closed_tabs,
            downloads_list,
            download_show,
            download_cancel,
            download_dismiss,
            activate_tab,
            move_tab,
            site_perms,
            site_perm_set,
            navigate,
            nav_action,
            set_content_rect,
            set_country,
            new_identity,
            set_blocking,
            add_bookmark,
            remove_bookmark,
            set_control,
            cut_ai,
            resolve_approval,
            get_logs,
            clear_logs,
            page_privacy,
            set_settings,
            get_history,
            suggest,
            remove_history,
            clean,
            vault_status,
            vault_create,
            vault_unlock,
            vault_recover,
            vault_lock,
            vault_list,
            vault_reveal,
            vault_delete,
            vault_never_remove,
            vault_matches,
            vault_fill,
            cred_answer,
            window_action,
            set_js_site,
            allow_http,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let sh = shared.clone();
            let _ = sh.app.set(handle.clone());

            // 1) Proxy local (antes de crear ninguna vista web).
            let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            std_listener.set_nonblocking(true)?;
            let proxy_port = std_listener.local_addr()?.port();
            let sh_proxy = sh.clone();
            tauri::async_runtime::spawn(async move {
                if let Ok(l) = tokio::net::TcpListener::from_std(std_listener) {
                    proxy::serve(l, sh_proxy, true).await;
                }
            });
            // Proxy del modo normal (salida directa), en otro puerto.
            let normal_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            normal_listener.set_nonblocking(true)?;
            let normal_port = normal_listener.local_addr()?.port();
            let sh_proxy = sh.clone();
            tauri::async_runtime::spawn(async move {
                if let Ok(l) = tokio::net::TcpListener::from_std(normal_listener) {
                    proxy::serve(l, sh_proxy, false).await;
                }
            });

            // 2) Tor: se prepara, pero solo arranca al usar el modo Sombra (ver Tor::ensure_started).
            sh.tor.set_base(sh.data_dir.join("tor"));
            if let Some(c) = sh.settings.lock().country.clone() {
                let _ = sh.tor.set_country(Some(&c));
            }

            // Bloqueo automático de las contraseñas.
            let sh_v = sh.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    let mins = sh_v.settings.lock().vault_lock_min;
                    if sh_v.vault.auto_lock(mins) {
                        sh_v.emit("vault", sh_v.vault.status());
                    }
                }
            });

            // Avisos de contraseñas enviadas en la pestaña activa (ver collect_creds).
            let (app_c, sh_c) = (handle.clone(), sh.clone());
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    collect_creds(&app_c, &sh_c).await;
                }
            });

            #[cfg(debug_assertions)]
            if ["SOMBRA_SELFTEST", "SOMBRA_AUDIT"].iter().any(|v| std::env::var(v).is_ok())
                || std::env::var("SOMBRA_SECTEST").is_ok_and(|v| !["modos", "afirma", "reabrir", "descargas", "cookies", "sesion", "iconos", "menu", "medir", "permisos"].contains(&v.as_str()))
            {
                sh.settings.lock().default_private = true;
            }
            // Si las pestañas nuevas son del modo Sombra, Tor arranca ya (estará listo antes).
            if sh.settings.lock().default_private {
                let tor = sh.tor.clone();
                tauri::async_runtime::spawn(async move { tor.ensure_started() });
            }

            // Solo en pruebas (SOMBRA_SECTEST=descargas): progreso, carpeta y cancelar.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("descargas") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let ver = |sh: &Arc<Shared>| {
                        sh.downloads.lock().iter().map(|d| format!("#{} {} [{}] {}/{} eta={:?} en {}", d.id, d.name, d.state, d.received, d.total, d.eta, d.folder)).collect::<Vec<_>>().join(" | ")
                    };
                    let _ = tabs::new_tab_mode(&app2, &sh2, Some("https://proof.ovh.net/files/10Mb.dat".into()), false).await;
                    for i in 0..60 {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        if i % 3 == 0 {
                            log::warn!("SECTEST descargas 1 ({i} s): {}", ver(&sh2));
                        }
                        if sh2.downloads.lock().iter().any(|d| d.state != "progress") {
                            break;
                        }
                    }
                    log::warn!("SECTEST descargas 2 terminada: {}", ver(&sh2));
                    let _ = tabs::new_tab_mode(&app2, &sh2, Some("https://proof.ovh.net/files/100Mb.dat".into()), false).await;
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let id = sh2.downloads.lock().iter().rev().find(|d| d.state == "progress").map(|d| d.id);
                    log::warn!("SECTEST descargas 3 en marcha: {}", ver(&sh2));
                    if let Some(id) = id {
                        let _ = app2.run_on_main_thread(move || downloads::cancel_native(id));
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    log::warn!("SECTEST descargas 4 cancelada: {}", ver(&sh2));
                    downloads::dismiss(&sh2, None);
                    log::warn!("SECTEST descargas 5 tras quitar terminadas: {}", ver(&sh2));
                    log::warn!("SECTEST descargas fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=sesion): recuperar las pestañas. SOMBRA_FASE=1 abre
            // pestañas; SOMBRA_FASE=2 (siguiente arranque) mira qué ha vuelto.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("sesion") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    let lista = |sh: &Arc<Shared>| {
                        let t = sh.tabs.lock();
                        let l: Vec<String> = t.list.iter().map(|x| format!("{}{}{}:{}", if Some(x.id) == t.active { "*" } else { "" }, if x.private { "S" } else { "N" }, if x.has_view { "+" } else { "z" }, x.url)).collect();
                        format!("{l:?}")
                    };
                    if std::env::var("SOMBRA_FASE").as_deref() == Ok("1") {
                        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                        let a = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), false).await.unwrap_or(0);
                        tabs::wait_loaded(&sh2, a, 60).await;
                        let b = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikidata.org/wiki/Special:BlankPage".into()), false).await.unwrap_or(0);
                        tabs::wait_loaded(&sh2, b, 60).await;
                        let _ = tabs::new_tab_mode(&app2, &sh2, Some("https://check.torproject.org/".into()), true).await;
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        tabs::activate(&app2, &sh2, a);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        log::warn!("SECTEST sesion 1 abiertas: {}", lista(&sh2));
                        log::warn!("SECTEST sesion 1 guardada: {}", std::fs::read_to_string(sh2.data_dir.join("session.json")).unwrap_or_default().replace('\n', " "));
                    } else {
                        log::warn!("SECTEST sesion 2 al arrancar: {}", lista(&sh2));
                        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                        log::warn!("SECTEST sesion 2 tras cargar la activa: {}", lista(&sh2));
                        let dormida = sh2.tabs.lock().list.iter().find(|x| !x.has_view).map(|x| x.id);
                        if let Some(d) = dormida {
                            tabs::activate(&app2, &sh2, d);
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        }
                        log::warn!("SECTEST sesion 3 tras abrir la dormida: {}", lista(&sh2));
                    }
                    log::warn!("SECTEST sesion fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=iconos): iconos de las webs y mover pestañas.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("iconos") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let lista = |sh: &Arc<Shared>| {
                        let t = sh.tabs.lock();
                        let l: Vec<String> = t.list.iter().map(|x| format!("{}#{} {} icono={}", if x.private { "S" } else { "N" }, x.id, x.url, if x.favicon.is_empty() { "no".to_string() } else { format!("{} letras {}", x.favicon.len(), &x.favicon[..30.min(x.favicon.len())]) })).collect();
                        format!("{l:?}")
                    };
                    let a = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, a, 60).await;
                    let b = tabs::new_tab_mode(&app2, &sh2, Some("https://github.com/".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, b, 60).await;
                    let c = tabs::new_tab_mode(&app2, &sh2, Some("https://www.torproject.org/".into()), true).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, c, 90).await;
                    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                    log::warn!("SECTEST iconos 1: {}", lista(&sh2));
                    let _ = tabs::navigate(&app2, &sh2, a, "https://www.wikidata.org/wiki/Special:BlankPage").await;
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    log::warn!("SECTEST iconos 2 otra web (sin el icono anterior): {}", lista(&sh2));
                    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                    log::warn!("SECTEST iconos 3 icono nuevo: {}", lista(&sh2));
                    tabs::move_tab(&sh2, c, 0);
                    tabs::move_tab(&sh2, a, 99);
                    log::warn!("SECTEST iconos 4 movidas (Sombra al principio, wikidata al final): {}", lista(&sh2));
                    log::warn!("SECTEST iconos fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=menu): abre una web normal y espera a que alguien use
            // "Abrir enlace en modo Sombra" con el ratón (se ve en la lista de pestañas).
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("menu") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let a = tabs::new_tab_mode(&app2, &sh2, Some("https://en.wikipedia.org/wiki/Tor_(network)".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, a, 60).await;
                    log::warn!("SECTEST menu listo");
                    for _ in 0..60 {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        let l: Vec<String> = sh2.tabs.lock().list.iter().map(|x| format!("{}:{}", if x.private { "S" } else { "N" }, x.url)).collect();
                        if l.iter().any(|x| x.starts_with("S:")) {
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            let l: Vec<String> = sh2.tabs.lock().list.iter().map(|x| format!("{}:{}", if x.private { "S" } else { "N" }, x.url)).collect();
                            log::warn!("SECTEST menu abierta en modo Sombra: {l:?}");
                            break;
                        }
                    }
                    log::warn!("SECTEST menu fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=medir): una web normal y Sombra en reposo, para medir
            // desde fuera cuánta memoria y procesador gasta (tools/medir.sh).
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("medir") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let url = std::env::var("SOMBRA_MEDIR_URL").unwrap_or_else(|_| "https://en.wikipedia.org/wiki/Web_browser".into());
                    let a = tabs::new_tab_mode(&app2, &sh2, Some(url), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, a, 60).await;
                    log::warn!("SECTEST medir cargada tor_listo={}", sh2.tor.is_ready());
                    for _ in 0..5 {
                        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                        let js = "(() => JSON.stringify({ anim: document.getAnimations().filter(a => a.playState === 'running').map(a => (a.animationName || a.constructor.name) + '@' + (a.effect && a.effect.target ? (a.effect.target.id || a.effect.target.className) : '?')), hidden: document.hidden, w: innerWidth, h: innerHeight }))()";
                        log::warn!("SECTEST medir interfaz: {:?} tor={:?}", tabs::eval_label(&app2, "ui", js.into()).await.map(|v| v.to_string()), sh2.tor.status().message);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(50)).await;
                    log::warn!("SECTEST medir fin tor_listo={}", sh2.tor.is_ready());
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=permisos): las webs piden permisos y la prueba contesta
            // por el usuario (como si pulsara Permitir / Denegar en el aviso).
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("permisos") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    sh2.remove_site_perm("https://www.wikipedia.org", None);
                    let pedir = |app: AppHandle, id: u32, js: &'static str| async move {
                        let _ = tabs::eval_tab(&app, id, js.into()).await;
                    };
                    let leer = |app: AppHandle, id: u32| async move { tabs::eval_tab(&app, id, "String(window.__p)".into()).await.map(|v| v.to_string()).unwrap_or_default() };
                    // Contesta la pregunta que aparezca (o dice que no ha aparecido ninguna).
                    let contestar = |sh: Arc<Shared>, allow: bool| async move {
                        for _ in 0..50 {
                            if let Some(id) = sh.pending_approvals().first().copied() {
                                sh.resolve_approval(id, allow);
                                return true;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        false
                    };
                    const NOTIF: &str = "(() => { window.__p = 'esperando'; Notification.requestPermission().then(r => window.__p = r); return 1; })()";
                    const GEO: &str = "(() => { window.__p = 'esperando'; navigator.geolocation.getCurrentPosition(() => window.__p = 'ubicacion dada', e => window.__p = 'error ' + e.code, { timeout: 8000 }); return 1; })()";
                    let n = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, n, 60).await;
                    pedir(app2.clone(), n, NOTIF).await;
                    let pregunto = contestar(sh2.clone(), true).await;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    log::warn!("SECTEST permisos 1 notificaciones, pregunta={pregunto}, permitido -> web: {} guardado: {:?}", leer(app2.clone(), n).await, sh2.site_perms.lock().clone());
                    pedir(app2.clone(), n, NOTIF).await;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    log::warn!("SECTEST permisos 2 otra vez (sin preguntar={}): web: {}", sh2.pending_approvals().is_empty(), leer(app2.clone(), n).await);
                    pedir(app2.clone(), n, GEO).await;
                    let pregunto = contestar(sh2.clone(), false).await;
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    log::warn!("SECTEST permisos 3 ubicación, pregunta={pregunto}, denegado -> web: {} guardado: {:?}", leer(app2.clone(), n).await, sh2.site_perms.lock().clone());
                    sh2.remove_site_perm("https://www.wikipedia.org", Some("geolocation"));
                    // El motor recuerda la respuesta mientras la página siga abierta: se recarga.
                    let _ = tabs::navigate(&app2, &sh2, n, "https://www.wikipedia.org/?otra=1").await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    tabs::wait_loaded(&sh2, n, 60).await;
                    pedir(app2.clone(), n, GEO).await;
                    let pregunto = contestar(sh2.clone(), false).await;
                    log::warn!("SECTEST permisos 4 quitado en Ajustes: vuelve a preguntar={pregunto}");
                    sh2.tor.ensure_started();
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    let p = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), true).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, p, 90).await;
                    pedir(app2.clone(), p, NOTIF).await;
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    log::warn!("SECTEST permisos 5 modo Sombra: sin preguntar={} web: {}", sh2.pending_approvals().is_empty(), leer(app2.clone(), p).await);
                    sh2.remove_site_perm("https://www.wikipedia.org", None);
                    log::warn!("SECTEST permisos fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=cookies): DNS seguro y cookies de terceros (modo normal).
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("cookies") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let txt = |app: AppHandle, id: u32| async move {
                        tabs::eval_tab(&app, id, "document.body ? document.body.innerText.slice(0, 300) : ''".into()).await.map(|v| v.to_string()).unwrap_or_else(|e| format!("error {e}"))
                    };
                    // SOMBRA_3P=off: la misma prueba sin el bloqueo, para comparar.
                    if std::env::var("SOMBRA_3P").as_deref() == Ok("off") {
                        sh2.settings.lock().block_3p_cookies = false;
                    }
                    let a = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, a, 60).await;
                    let bloqueo = sh2.settings.lock().block_3p_cookies;
                    let pagina: String = txt(app2.clone(), a).await.chars().take(60).collect();
                    log::warn!(
                        "SECTEST cookies 1 bloqueo={} dns seguro={} en memoria={} pagina: {}",
                        bloqueo,
                        doh::ENABLED.load(std::sync::atomic::Ordering::Relaxed),
                        doh::cached("www.wikipedia.org"),
                        pagina
                    );
                    // Webs de otros dominios, incrustadas, intentan guardar cookies (las de
                    // Wikimedia ponen siempre "WMF-Last-Access" y "GeoIP").
                    #[cfg(target_os = "linux")]
                    {
                        log::warn!("SECTEST cookies 2 antes: {:?}", tabs::cookie_domains(&app2, a).await);
                        let _ = tabs::eval_tab(&app2, a, "(() => { for (const u of ['https://www.wikidata.org/wiki/Special:BlankPage', 'https://commons.wikimedia.org/wiki/Special:BlankPage']) { const f = document.createElement('iframe'); f.src = u; document.body.appendChild(f); } return 'ok'; })()".into()).await;
                        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                        log::warn!("SECTEST cookies 3 tras los iframes (con bloqueo no deben salir wikidata ni wikimedia): {:?}", tabs::cookie_domains(&app2, a).await);
                        let _ = tabs::navigate(&app2, &sh2, a, "https://www.wikidata.org/wiki/Special:BlankPage").await;
                        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                        log::warn!("SECTEST cookies 4 wikidata abierta directamente (debe salir): {:?}", tabs::cookie_domains(&app2, a).await);
                    }
                    log::warn!("SECTEST cookies fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=reabrir): reabrir pestañas cerradas.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("reabrir") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let lista = |sh: &Arc<Shared>| {
                        let t = sh.tabs.lock();
                        let l: Vec<String> = t.list.iter().map(|x| format!("{}{}:{}", if Some(x.id) == t.active { "*" } else { "" }, if x.private { "S" } else { "N" }, x.url)).collect();
                        format!("{l:?} cerradas={}", t.closed.len())
                    };
                    let a = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, a, 60).await;
                    let b = tabs::new_tab_mode(&app2, &sh2, Some("https://example.com/".into()), false).await.unwrap_or(0);
                    tabs::wait_loaded(&sh2, b, 60).await;
                    log::warn!("SECTEST reabrir 1 abiertas: {}", lista(&sh2));
                    let _ = tabs::close(&app2, &sh2, a).await;
                    log::warn!("SECTEST reabrir 2 cerrada wikipedia: {}", lista(&sh2));
                    let r = tabs::reopen(&app2, &sh2, None).await;
                    log::warn!("SECTEST reabrir 3 reabierta {r:?}: {}", lista(&sh2));
                    let ids: Vec<u32> = sh2.tabs.lock().list.iter().map(|t| t.id).collect();
                    for id in ids {
                        let _ = tabs::close(&app2, &sh2, id).await;
                    }
                    log::warn!("SECTEST reabrir 4 todas cerradas: {}", lista(&sh2));
                    let r = tabs::reopen(&app2, &sh2, None).await;
                    log::warn!("SECTEST reabrir 5 reabre en la vacía {r:?}: {}", lista(&sh2));
                    let r = tabs::reopen(&app2, &sh2, Some(99)).await;
                    log::warn!("SECTEST reabrir 6 índice malo {r:?}");
                    let _ = clean(app2.clone(), app2.state::<Arc<Shared>>(), json!({ "tabs": true })).await;
                    log::warn!("SECTEST reabrir 7 tras limpiar pestañas: {}", lista(&sh2));
                    log::warn!("SECTEST reabrir fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=afirma): AutoFirma solo abre los puertos de su enlace
            // y solo desde el modo normal.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("afirma") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    let ev = |app: AppHandle, id: u32, js: String| async move {
                        match tokio::time::timeout(std::time::Duration::from_secs(10), tabs::eval_tab(&app, id, js)).await {
                            Ok(Ok(v)) => v.to_string(),
                            r => format!("{r:?}"),
                        }
                    };
                    let bloqueado = |sh: &Arc<Shared>, port: u16| sh.logs.lock().iter().any(|l| l.code == "localBlocked" && l.message.contains(&format!("127.0.0.1:{port}")));
                    let sondear = |app: AppHandle, id: u32, port: u16| async move {
                        let _ = ev(app, id, format!("(() => {{ fetch('https://127.0.0.1:{port}/afirma', {{ mode: 'no-cors' }}).catch(() => 0); return 'ok'; }})()")).await;
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    };
                    let n = tabs::new_tab_mode(&app2, &sh2, Some("https://www.wikipedia.org/".into()), false).await.unwrap_or(0);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    tabs::wait_loaded(&sh2, n, 60).await;
                    // 1) Sin AutoFirma: este PC cerrado.
                    sondear(app2.clone(), n, 55001).await;
                    log::warn!("SECTEST afirma 1 antes: 55001 bloqueado={}", bloqueado(&sh2, 55001));
                    // 2) La web abre AutoFirma con sus puertos: solo esos se abren.
                    let _ = ev(app2.clone(), n, "(() => { location.href = 'afirma://websocket?ports=55002,55003&v=4&idsession=x'; return 'ok'; })()".into()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    log::warn!("SECTEST afirma 2 puertos: 55002={} 55003={} 55004={}", sh2.afirma_port(55002), sh2.afirma_port(55003), sh2.afirma_port(55004));
                    sondear(app2.clone(), n, 55002).await;
                    sondear(app2.clone(), n, 55004).await;
                    log::warn!("SECTEST afirma 3 proxy: 55002 bloqueado={} 55004 bloqueado={}", bloqueado(&sh2, 55002), bloqueado(&sh2, 55004));
                    // 4) Modo Sombra: AutoFirma no se abre ni abre puertos.
                    sh2.tor.ensure_started();
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    let p = tabs::new_tab_mode(&app2, &sh2, Some("https://check.torproject.org/".into()), true).await.unwrap_or(0);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    tabs::wait_loaded(&sh2, p, 90).await;
                    let _ = ev(app2.clone(), p, "(() => { location.href = 'afirma://websocket?ports=56001&v=4'; return 'ok'; })()".into()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    sondear(app2.clone(), p, 55002).await;
                    log::warn!("SECTEST afirma 4 sombra: 56001 abierto={} 55002 bloqueado desde Sombra={}", sh2.afirma_port(56001), bloqueado(&sh2, 55002));
                    log::warn!("SECTEST afirma fin");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=modos): modo normal y modo Sombra.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("modos") {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    let ev = |app: AppHandle, id: u32, js: &'static str| async move {
                        match tokio::time::timeout(std::time::Duration::from_secs(10), tabs::eval_tab(&app, id, js.into())).await {
                            Ok(Ok(v)) => v.to_string(),
                            r => format!("{r:?}"),
                        }
                    };
                    let abrir = |app: AppHandle, sh: Arc<Shared>, url: &'static str, private: bool| async move {
                        let r = tabs::new_tab_mode(&app, &sh, Some(url.into()), private).await;
                        log::warn!("SECTEST modos abrir {url} private={private}: {r:?}");
                        let id = r.unwrap_or(0);
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        tabs::wait_loaded(&sh, id, 90).await;
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        id
                    };
                    const TXT: &str = "(() => document.title + ' | ' + (document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').slice(0, 160))()";
                    const INFO: &str = "(() => JSON.stringify({ rtc: typeof RTCPeerConnection, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, lang: navigator.language, cookie: document.cookie, ls: (() => { try { return localStorage.getItem('modo'); } catch (e) { return 'err'; } })() }))()";
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    // 1) Modo normal: funciona sin esperar a Tor y sale directo.
                    let t0 = std::time::Instant::now();
                    let n = abrir(app2.clone(), sh2.clone(), "https://check.torproject.org/", false).await;
                    log::warn!("SECTEST modos 1 normal (tor listo={}, {:.0} s): {}", sh2.tor.is_ready(), t0.elapsed().as_secs_f32(), ev(app2.clone(), n, TXT).await);
                    sh2.tor.ensure_started();
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    // 2) Modo Sombra: por Tor.
                    let p = abrir(app2.clone(), sh2.clone(), "https://check.torproject.org/", true).await;
                    log::warn!("SECTEST modos 2 sombra: {}", ev(app2.clone(), p, TXT).await);
                    // 3) No comparten cookies ni almacenamiento.
                    let _ = tabs::navigate(&app2, &sh2, n, "https://www.wikipedia.org/").await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    tabs::wait_loaded(&sh2, n, 60).await;
                    log::warn!("SECTEST modos 3 normal página: {} {:?}", ev(app2.clone(), n, "(() => location.href + ' ' + document.title)()").await, sh2.tabs.lock().list.iter().find(|t| t.id == n).map(|t| serde_json::to_string(t).unwrap_or_default()));
                    let r = ev(app2.clone(), n, "(() => { document.cookie = 'modo=normal; max-age=3600; path=/'; localStorage.setItem('modo', 'normal'); return 'ok'; })()").await;
                    log::warn!("SECTEST modos 3 normal guardar: {r}");
                    let _ = tabs::navigate(&app2, &sh2, p, "https://www.wikipedia.org/").await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    tabs::wait_loaded(&sh2, p, 60).await;
                    log::warn!("SECTEST modos 3 normal: {}", ev(app2.clone(), n, INFO).await);
                    log::warn!("SECTEST modos 3 normal detalle: {}", ev(app2.clone(), n, "(() => { let e = ''; try { localStorage.setItem('x', '1'); } catch (x) { e = String(x); } return JSON.stringify({ href: location.href, ce: navigator.cookieEnabled, e, c: (document.cookie = 'b=2; path=/', document.cookie) }); })()").await);
                    log::warn!("SECTEST modos 3 sombra (sin cookie ni modo): {}", ev(app2.clone(), p, INFO).await);
                    // 4) Búsqueda en modo normal: DuckDuckGo de internet (el .onion no existe fuera de Tor).
                    let _ = tabs::navigate(&app2, &sh2, n, "sombra navegador").await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    tabs::wait_loaded(&sh2, n, 60).await;
                    let url_n = sh2.tabs.lock().list.iter().find(|t| t.id == n).map(|t| t.url.clone()).unwrap_or_default();
                    log::warn!("SECTEST modos 4 búsqueda normal: {url_n}");
                    // 5) Un .onion desde una pestaña normal se abre en una pestaña Sombra.
                    let antes = sh2.tabs.lock().list.len();
                    let _ = tabs::navigate(&app2, &sh2, n, "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/").await;
                    let (despues, activa) = {
                        let t = sh2.tabs.lock();
                        (t.list.len(), t.list.iter().find(|x| Some(x.id) == t.active).map(|x| (x.private, x.url.clone())))
                    };
                    log::warn!("SECTEST modos 5 onion desde normal: pestañas {antes}->{despues}, activa={activa:?}");
                    // 6) Historial: solo el modo normal.
                    let h: Vec<String> = sh2.history.lock().iter().map(|e| e.url.clone()).collect();
                    log::warn!("SECTEST modos 6 historial: {h:?}");
                    // 7) Red local: desde una web normal no se llega (el proxy lo corta).
                    let r = ev(app2.clone(), n, "(() => { window.__lan = 'esperando'; fetch('https://192.168.1.1/', { mode: 'no-cors' }).then(() => window.__lan = 'ALCANZADA', e => window.__lan = 'bloqueada: ' + e); return 'ok'; })()").await;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    log::warn!("SECTEST modos 7 red local desde web normal: {r} {}", ev(app2.clone(), n, "(() => String(window.__lan))()").await);
                    // 8) DNS rebinding: un dominio de internet que apunta a 127.0.0.1 (localtest.me),
                    // aunque lo abras tú, no llega a este PC.
                    let _ = tabs::navigate(&app2, &sh2, n, "https://localtest.me/").await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    tabs::wait_loaded(&sh2, n, 30).await;
                    log::warn!("SECTEST modos 8 dominio que apunta a este PC: {}", ev(app2.clone(), n, TXT).await);
                    log::warn!("SECTEST modos fin");
                });
            }

            // Solo en pruebas (SOMBRA_SELFTEST=1): entra en una web de práctica con datos falsos
            // y comprueba que llega el aviso "¿Guardar la contraseña?".
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SELFTEST").is_ok() {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    sh2.tor.ensure_started();
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    let Ok(id) = tabs::new_tab(&app2, &sh2, Some("https://the-internet.herokuapp.com/login".into())).await else { return };
                    tabs::wait_loaded(&sh2, id, 60).await;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    // ¿Ve la web algún rastro de Tauri / wry / WebView?
                    let t = "(() => JSON.stringify({ g: Object.getOwnPropertyNames(window).filter(k => /tauri|ipc|wry|webview|messageHandlers/i.test(k)), isTauri: 'isTauri' in window, internals: '__TAURI_INTERNALS__' in window, ipc: 'ipc' in window, webkitHandlers: !!(window.webkit && window.webkit.messageHandlers), chromeWebview: !!(window.chrome && window.chrome.webview) }))()";
                    let r = tabs::eval_tab(&app2, id, t.into()).await;
                    log::warn!("SELFTEST rastros: {r:?}");
                    // ¿Qué huella ve la web? (con la protección reforzada activada)
                    let f = "(() => { window.__h = 'esperando'; const urls = ['https://echo.hoppscotch.io/', 'https://postman-echo.com/headers', 'https://httpbin.org/headers']; const go = i => i >= urls.length ? Promise.reject('sin respuesta') : fetch(urls[i]).then(r => r.ok ? r.text() : go(i + 1), () => go(i + 1)); go(0).then(t => { const m = /accept-language\\x22\\s*:\\s*\\x22([^\\x22]*)/i.exec(t); window.__h = m ? m[1] : t.slice(0, 300); }).catch(e => { window.__h = 'error ' + e; }); const d = new Date(2020, 0, 1, 12, 30); return JSON.stringify({ lang: navigator.language, langs: navigator.languages, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, loc: Intl.DateTimeFormat().resolvedOptions().locale, off: new Date().getTimezoneOffset(), hours: d.getHours(), str: d.toString(), parse: new Date('2020-01-01T12:00').toISOString(), screen: [screen.width, screen.height, innerWidth, innerHeight, outerWidth], native: [Date.prototype.getHours.toString(), Function.prototype.toString.toString(), Object.getOwnPropertyDescriptor(Navigator.prototype, 'language').get.toString()], proto: 'prototype' in Date.prototype.getHours, dateFn: Date.toString(), inst: new Date() instanceof Date, cores: navigator.hardwareConcurrency }); })()";
                    let r = tabs::eval_tab(&app2, id, f.into()).await;
                    log::warn!("SELFTEST huella: {r:?}");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    let r = tabs::eval_tab(&app2, id, "(() => String(window.__h))()".into()).await;
                    log::warn!("SELFTEST Accept-Language: {r:?}");
                    let js = "(() => { document.querySelector('#username').value = 'tomsmith'; document.querySelector('#password').value = 'SuperSecretPassword!'; document.querySelector('button[type=submit]').click(); return 'ok'; })()";
                    let r = tabs::eval_tab(&app2, id, js.into()).await;
                    log::warn!("SELFTEST relleno: {r:?}");
                    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                    let d = tabs::eval_tab(&app2, id, "(() => location.pathname)()".into()).await;
                    log::warn!("SELFTEST diagnóstico: página tras enviar = {d:?}");
                });
            }

            // Solo en pruebas (SOMBRA_SECTEST=1): niveles de seguridad y anuncios de YouTube.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SECTEST").is_ok_and(|v| !["modos", "afirma", "reabrir", "descargas", "cookies", "sesion", "iconos", "menu", "medir", "permisos"].contains(&v.as_str())) {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    sh2.tor.ensure_started();
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    // SOMBRA_SECTEST=https: modo solo HTTPS.
                    if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("https") {
                        let estado = |sh: &Arc<Shared>| {
                            let t = sh.tabs.lock();
                            t.list.iter().find(|x| Some(x.id) == t.active).map(|x| format!("url={} vista={} aviso={}", x.url, x.has_view, x.https_warn)).unwrap_or_default()
                        };
                        let ir = |app: AppHandle, sh: Arc<Shared>, url: &'static str| async move {
                            match tabs::active_id(&sh) {
                                Some(id) => { let _ = tabs::navigate(&app, &sh, id, url).await; }
                                None => { let _ = tabs::new_tab(&app, &sh, Some(url.into())).await; }
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            if let Some(id) = tabs::active_id(&sh) {
                                tabs::wait_loaded(&sh, id, 60).await;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        };
                        ir(app2.clone(), sh2.clone(), "http://example.com/").await;
                        log::warn!("SECTEST https 1 escrito http con https: {}", estado(&sh2));
                        ir(app2.clone(), sh2.clone(), "info.cern.ch").await;
                        log::warn!("SECTEST https 2 certificado caducado (escrita sin http): {}", estado(&sh2));
                        ir(app2.clone(), sh2.clone(), "http://httpforever.com/").await;
                        log::warn!("SECTEST https 3 sin cifrado en el 443: {}", estado(&sh2));
                        ir(app2.clone(), sh2.clone(), "https://example.com/").await;
                        if let Some(id) = tabs::active_id(&sh2) {
                            let _ = tabs::eval_tab(&app2, id, "(() => { location.href = 'http://www.wikipedia.org/'; return 'ok'; })()".into()).await;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                        if let Some(id) = tabs::active_id(&sh2) {
                            tabs::wait_loaded(&sh2, id, 60).await;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        log::warn!("SECTEST https 4 enlace a http desde una web: {}", estado(&sh2));
                        ir(app2.clone(), sh2.clone(), "http://httpforever.com/").await;
                        sh2.http_ok.lock().insert("httpforever.com".into());
                        ir(app2.clone(), sh2.clone(), "http://httpforever.com/").await;
                        let id = tabs::active_id(&sh2).unwrap_or(0);
                        let r = tokio::time::timeout(std::time::Duration::from_secs(8), tabs::eval_tab(&app2, id, "(() => document.title + ' | ' + location.href)()".into())).await;
                        log::warn!("SECTEST https 5 permitida sin cifrar: {} página={r:?}", estado(&sh2));
                        // El proxy: ¿deja salir algo sin cifrar (puerto 80) a una web no permitida?
                        let port = tabs::ENGINE.get().map(|e| e.proxy_port).unwrap_or(0);
                        for (host, p) in [("example.org", 80u16), ("example.org", 443), ("httpforever.com", 80)] {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let r: std::io::Result<u8> = async {
                                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                                s.write_all(&[5, 1, 0]).await?;
                                let mut b = [0u8; 2];
                                s.read_exact(&mut b).await?;
                                let mut req = vec![5, 1, 0, 3, host.len() as u8];
                                req.extend_from_slice(host.as_bytes());
                                req.extend_from_slice(&p.to_be_bytes());
                                s.write_all(&req).await?;
                                let mut rep = [0u8; 10];
                                s.read_exact(&mut rep).await?;
                                Ok(rep[1])
                            }
                            .await;
                            log::warn!("SECTEST https proxy {host}:{p} -> {r:?} (0 = sale, 2 = bloqueado)");
                        }
                        log::warn!("SECTEST https fin");
                        return;
                    }
                    sh2.settings.lock().https_only = false;
                    let probe = "(() => JSON.stringify({ text: (document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').slice(0, 160), wasm: typeof WebAssembly, webgl: !!document.createElement('canvas').getContext('webgl'), title: document.title }))()";
                    let level = sh2.settings.lock().security_level;
                    let paso = |app: AppHandle, sh: Arc<Shared>, nombre: &'static str, url: &'static str| async move {
                        let id = match tabs::active_id(&sh) {
                            Some(id) => { let _ = tabs::navigate(&app, &sh, id, url).await; tabs::active_id(&sh).unwrap_or(id) }
                            None => tabs::new_tab(&app, &sh, Some(url.into())).await.unwrap_or(0),
                        };
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let id = tabs::active_id(&sh).unwrap_or(id);
                        tabs::wait_loaded(&sh, id, 60).await;
                        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                        let id = tabs::active_id(&sh).unwrap_or(id);
                        let r = tokio::time::timeout(std::time::Duration::from_secs(8), tabs::eval_tab(&app, id, probe.into())).await;
                        log::warn!("SECTEST nivel={level} {nombre}: pestaña={id} js={:?} sonda={r:?}", tabs::tab_js(id));
                    };
                    // SOMBRA_SECTEST=yt: solo la parte de YouTube.
                    if std::env::var("SOMBRA_SECTEST").as_deref() != Ok("yt") {
                        paso(app2.clone(), sh2.clone(), "https", "https://www.enable-javascript.com/").await;
                        paso(app2.clone(), sh2.clone(), "http", "http://httpforever.com/").await;
                        sh2.settings.lock().js_allow = vec!["enable-javascript.com".into()];
                        paso(app2.clone(), sh2.clone(), "https permitida", "https://www.enable-javascript.com/").await;
                        sh2.settings.lock().js_allow.clear();
                    }
                    // SOMBRA_SECTEST=levels: sin la parte de YouTube.
                    if std::env::var("SOMBRA_SECTEST").as_deref() == Ok("levels") {
                        log::warn!("SECTEST youtube anuncios: omitido");
                        return;
                    }
                    if let Some(id) = tabs::active_id(&sh2) {
                        let _ = tabs::navigate(&app2, &sh2, id, "https://www.youtube.com/watch?v=jNQXAC9IVRw").await;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    if let Some(id) = tabs::active_id(&sh2) {
                        tabs::wait_loaded(&sh2, id, 60).await;
                        // Se espera al título que ve Sombra (preguntar a la página mientras carga
                        // cierra WebKit en WSL).
                        for _ in 0..40 {
                            if sh2.tabs.lock().list.iter().any(|t| t.id == id && t.title.contains("YouTube") && !t.loading) {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                        log::warn!("SECTEST nivel={level} youtube cargado: pestaña={id} js={:?}", tabs::tab_js(id));
                        let y = "(() => { const p = window.ytInitialPlayerResponse; return JSON.stringify({ title: document.title, url: location.href.slice(0, 80), pr: !!p, ads: p ? ['adPlacements','playerAds','adSlots'].filter(k => k in p) : null, enScripts: [...document.scripts].filter(s => s.text.includes('adPlacements')).length, conPR: [...document.scripts].filter(s => s.text.includes('ytInitialPlayerResponse')).length, status: p && p.playabilityStatus ? p.playabilityStatus.status : null, adShowing: !!document.querySelector('.ad-showing') }); })()";
                        let r = tokio::time::timeout(std::time::Duration::from_secs(8), tabs::eval_tab(&app2, id, y.into())).await;
                        log::warn!("SECTEST nivel={level} youtube anuncios: {r:?}");
                    }
                });
            }

            // Solo en pruebas (SOMBRA_AUDIT=1): auditoría de seguridad. Prueba lo que haría una web
            // maliciosa (tools/audit-probe.js), una descarga y CreepJS. Resultados en el registro.
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_AUDIT").is_ok() {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    sh2.tor.ensure_started();
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    async fn abrir(app: &AppHandle, sh: &Arc<Shared>, url: &str) -> u32 {
                        let id = match tabs::active_id(sh) {
                            Some(id) => { let _ = tabs::navigate(app, sh, id, url).await; id }
                            None => tabs::new_tab(app, sh, Some(url.into())).await.unwrap_or(0),
                        };
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let id = tabs::active_id(sh).unwrap_or(id);
                        tabs::wait_loaded(sh, id, 60).await;
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        tabs::active_id(sh).unwrap_or(id)
                    }
                    async fn esperar(app: &AppHandle, id: u32, var: &str, secs: u64) -> String {
                        for _ in 0..secs {
                            match tabs::eval_tab(app, id, format!("(() => String(window.{var}))()")).await {
                                Ok(Value::String(s)) if s == "esperando" || s == "undefined" => {}
                                Ok(v) => return v.to_string(),
                                Err(_) => {}
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        "sin resultado".into()
                    }
                    // La sonda también se prueba en una web http (sin el modo solo HTTPS).
                    sh2.settings.lock().https_only = false;
                    let probe = include_str!("../../tools/audit-probe.js");
                    let id = abrir(&app2, &sh2, "https://check.torproject.org/").await;
                    let r = tabs::eval_tab(&app2, id, "(() => document.title)()".into()).await;
                    log::warn!("AUDIT tor: {r:?}");
                    for url in ["https://example.com/", "http://httpforever.com/"] {
                        let id = abrir(&app2, &sh2, url).await;
                        let r = tabs::eval_tab(&app2, id, probe.into()).await;
                        log::warn!("AUDIT sonda lanzada en {url}: {r:?}");
                        log::warn!("AUDIT sonda {url}: {}", esperar(&app2, id, "__audit", 40).await);
                    }
                    // Descarga: ¿guarda la web un archivo sin preguntar?
                    let dl = dirs::download_dir().unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join("Downloads"));
                    let antes: Vec<_> = std::fs::read_dir(&dl).map(|d| d.flatten().map(|e| e.file_name()).collect()).unwrap_or_default();
                    let _ = abrir(&app2, &sh2, "https://proof.ovh.net/files/1Mb.dat").await;
                    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
                    let despues: Vec<_> = std::fs::read_dir(&dl).map(|d| d.flatten().map(|e| e.file_name()).collect()).unwrap_or_default();
                    let nuevos: Vec<_> = despues.iter().filter(|f| !antes.contains(f)).collect();
                    log::warn!("AUDIT descarga: carpeta={dl:?} nuevos={nuevos:?}");
                    // CreepJS: detecta mentiras en la huella.
                    let id = abrir(&app2, &sh2, "https://abrahamjuliot.github.io/creepjs/").await;
                    tokio::time::sleep(std::time::Duration::from_secs(45)).await;
                    let r = tabs::eval_tab(&app2, id, "(() => (document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').slice(0, 2500))()".into()).await;
                    log::warn!("AUDIT creepjs: {r:?}");
                    log::warn!("AUDIT fin");
                });
            }

            // 3) Bloqueador (cargar las listas tarda un par de segundos).
            let sh_b = sh.clone();
            std::thread::spawn(move || {
                sh_b.set_blocker(blocker::Blocker::new());
            });

            // 4) Ventana y la interfaz.
            // Nombre totalmente aleatorio (solo letras) para que las webs no puedan reconocerlo.
            let fp_key: String = {
                use rand::Rng;
                let mut r = rand::thread_rng();
                (0..12).map(|_| (b'a' + r.gen_range(0..26)) as char).collect()
            };
            let _ = tabs::ENGINE.set(tabs::Engine {
                args: tabs::browser_args(proxy_port, fp_strict, level),
                proxy_port,
                data_dir: web_dir.clone(),
                normal_args: tabs::browser_args_normal(normal_port),
                normal_port,
                normal_dir: normal_dir.clone(),
                fp_key,
                fp_seed: rand::random(),
            });
            // 5) Sesión anterior: las pestañas normales que había al cerrar. Solo se carga la
            // activa, cuando la interfaz ya ha dicho dónde va la web; las demás, al abrirlas.
            #[cfg(debug_assertions)]
            let skip_session = ["SOMBRA_SELFTEST", "SOMBRA_AUDIT"].iter().any(|v| std::env::var(v).is_ok()) || std::env::var("SOMBRA_SECTEST").is_ok_and(|v| v != "sesion");
            #[cfg(not(debug_assertions))]
            let skip_session = false;
            let session = if skip_session { Default::default() } else { sh.take_session() };
            if let Some(active) = tabs::restore(&sh, session) {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    for _ in 0..150 {
                        if sh2.tabs.lock().rect.2 > 1.0 {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    tabs::wake(&app2, &sh2, active).await;
                });
            }
            // La sesión se guarda poco después de cada cambio de pestañas (y al cerrar).
            {
                let sh2 = sh.clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        if sh2.session_dirty.swap(false, std::sync::atomic::Ordering::Relaxed) {
                            let sh3 = sh2.clone();
                            let _ = tauri::async_runtime::spawn_blocking(move || sh3.save_session()).await;
                        }
                    }
                });
            }
            // En Linux la ventana no lleva la barra del sistema (en Ubuntu/WSL solo traía la ×):
            // Sombra pone − □ × juntos a la derecha de las pestañas. En Windows, la del sistema.
            let window = tauri::window::WindowBuilder::new(app, "main")
                .title("Sombra")
                .inner_size(1200.0, 800.0)
                .min_inner_size(420.0, 360.0)
                .decorations(cfg!(windows))
                .build()?;
            let size = window.inner_size()?;
            let ui = tabs::engine_setup(WebviewBuilder::new("ui", WebviewUrl::App("index.html".into())), true)
                .auto_resize()
                .initialization_script(format!("window.__SYS_LANGS = {}; window.__SYS_TZ = {};", json!(sys_langs), json!(sys_tz)));
            // Solo en pruebas: guarda los errores de la interfaz para poder diagnosticarlos.
            #[cfg(debug_assertions)]
            let ui = ui.initialization_script(
                "window.__errs = []; addEventListener('error', e => __errs.push(String(e.message) + ' @' + e.filename + ':' + e.lineno)); addEventListener('unhandledrejection', e => __errs.push('promesa: ' + String(e.reason)));",
            );
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_UIDIAG").is_ok() {
                let app3 = handle.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
                    let js = "(() => JSON.stringify({ errs: window.__errs, newtab: document.getElementById('newtab').className, S: typeof S, keys: typeof showVault, n: document.querySelectorAll('script').length }))()";
                    let r = tabs::eval_label(&app3, "ui", js.into()).await;
                    log::warn!("UIDIAG {r:?}");
                });
            }
            let ui_view = window.add_child(ui, LogicalPosition::new(0.0, 0.0), size)?;
            // Linux: la interfaz y las pestañas comparten el motor; sus idiomas se fijan aquí,
            // antes de abrir ninguna web.
            #[cfg(target_os = "linux")]
            if fp_strict {
                let _ = ui_view.with_webview(|pw| {
                    use webkit2gtk::{WebContextExt, WebViewExt};
                    if let Some(ctx) = pw.inner().context() {
                        ctx.set_preferred_languages(&["en-US", "en"]);
                    }
                });
            }
            #[cfg(not(target_os = "linux"))]
            let _ = &ui_view;

            // 5) Puerta de control para IAs, si estaba activada.
            if sh.settings.lock().control_enabled {
                let h = handle.clone();
                let s2 = sh.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = control::start(h, s2).await;
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("no se pudo iniciar Sombra")
        .run(move |app, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(sh) = app.try_state::<Arc<Shared>>() {
                    let _ = std::fs::remove_file(sh.data_dir.join("control.json"));
                    if sh.settings.lock().clean_on_exit {
                        sh.clear_history();
                    } else {
                        sh.save_history_pending();
                    }
                    // Lo último: las pestañas tal como quedaron (o nada, si no se quiere).
                    sh.save_session();
                }
                let dir = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("Sombra").join("webview");
                let _ = std::fs::remove_dir_all(dir);
            }
        });
}
