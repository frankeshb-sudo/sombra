// Sombra - navegador ligero y privado. Sin publicidad, con Tor integrado y control para IAs.
// Copyright (C) 2026 Sombra contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of
// the GNU General Public License as published by the Free Software Foundation, either version 3
// of the License, or (at your option) any later version. See the LICENSE file.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod blocker;
mod control;
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
async fn new_tab(app: AppHandle, sh: Sh<'_>, url: Option<String>) -> Result<u32, String> {
    tabs::new_tab(&app, &sh, url).await.map_err(e2s)
}

#[tauri::command]
async fn close_tab(app: AppHandle, sh: Sh<'_>, id: u32) -> Result<(), String> {
    tabs::close(&app, &sh, id).await.map_err(e2s)
}

#[tauri::command]
fn activate_tab(app: AppHandle, sh: Sh, id: u32) {
    tabs::activate(&app, &sh, id);
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
    Ok(json!(*sh.settings.lock()))
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
    let key = &tabs::ENGINE.get().map(|e| e.fp_key.clone()).unwrap_or_default();
    let js = format!("(() => {{ const s = window['{key}']; return JSON.stringify(s || {{ fp: 0, kinds: {{}} }}); }})()");
    tabs::eval_tab(&app, id, js).await.map_err(e2s)
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

/// La única orden que pueden llamar las pestañas: el script de Sombra avisa de
/// que se ha enviado un formulario con contraseña. La web se toma del motor, no
/// de lo que diga la página.
#[tauri::command]
fn cred_capture(webview: tauri::Webview, sh: Sh, user: String, pass: String) {
    let pass = zeroize::Zeroizing::new(pass);
    if !webview.label().starts_with("tab-") || pass.is_empty() || pass.len() > 512 || user.len() > 200 {
        return;
    }
    let Ok(url) = webview.url() else { return };
    if !matches!(url.scheme(), "http" | "https") {
        return;
    }
    let Some(host) = url.host_str() else { return };
    #[cfg(debug_assertions)]
    if std::env::var("SOMBRA_SELFTEST").is_ok() {
        log::warn!("SELFTEST aviso recibido de {host} (usuario: {user})");
    }
    if let Some(q) = sh.vault.capture(host, user.trim(), pass) {
        sh.emit("cred", q);
    }
}

fn main() {
    let _ = env_logger::try_init();
    let data_dir = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("Sombra");
    let _ = std::fs::create_dir_all(&data_dir);
    // Nada de la navegación se conserva: la carpeta del motor se borra al abrir y al cerrar.
    let web_dir = data_dir.join("webview");
    let _ = std::fs::remove_dir_all(&web_dir);
    let _ = std::fs::remove_file(data_dir.join("control.json"));

    let shared = Shared::new(data_dir.clone());

    tauri::Builder::default()
        .manage(shared.clone())
        .invoke_handler(tauri::generate_handler![
            get_state,
            new_tab,
            close_tab,
            activate_tab,
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
            cred_capture,
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
                    proxy::serve(l, sh_proxy).await;
                }
            });

            // 2) Tor en segundo plano.
            let tor = sh.tor.clone();
            let tor_dir = sh.data_dir.join("tor");
            let country = sh.settings.lock().country.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(c) = country.as_deref() {
                    let _ = tor.set_country(Some(c));
                }
                tor.start(tor_dir).await;
            });

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

            // Solo en pruebas (SOMBRA_SELFTEST=1): entra en una web de práctica con datos falsos
            // y comprueba que llega el aviso "¿Guardar la contraseña?".
            #[cfg(debug_assertions)]
            if std::env::var("SOMBRA_SELFTEST").is_ok() {
                let (app2, sh2) = (handle.clone(), sh.clone());
                tauri::async_runtime::spawn(async move {
                    while !sh2.tor.is_ready() {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    let Ok(id) = tabs::new_tab(&app2, &sh2, Some("https://the-internet.herokuapp.com/login".into())).await else { return };
                    tabs::wait_loaded(&sh2, id, 60).await;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let js = "(() => { document.querySelector('#username').value = 'tomsmith'; document.querySelector('#password').value = 'SuperSecretPassword!'; document.querySelector('button[type=submit]').click(); return 'ok'; })()";
                    let r = tabs::eval_tab(&app2, id, js.into()).await;
                    log::warn!("SELFTEST relleno: {r:?}");
                    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                    let d = tabs::eval_tab(&app2, id, "(() => location.pathname)()".into()).await;
                    log::warn!("SELFTEST diagnóstico: página tras enviar = {d:?}");
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
                args: tabs::browser_args(proxy_port),
                proxy_port,
                data_dir: web_dir.clone(),
                fp_key,
            });
            let window = tauri::window::WindowBuilder::new(app, "main")
                .title("Sombra")
                .inner_size(1200.0, 800.0)
                .min_inner_size(420.0, 360.0)
                .build()?;
            let size = window.inner_size()?;
            let ui = tabs::engine_setup(WebviewBuilder::new("ui", WebviewUrl::App("index.html".into()))).auto_resize();
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
            window.add_child(ui, LogicalPosition::new(0.0, 0.0), size)?;

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
                    }
                }
                let dir = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("Sombra").join("webview");
                let _ = std::fs::remove_dir_all(dir);
            }
        });
}
