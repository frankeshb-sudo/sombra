// Sombra - puerta de control para IAs (Claude, ChatGPT, IA local o cualquier programa).
// Solo escucha en 127.0.0.1, exige un token secreto, detecta intrusos y pide permiso
// al usuario para cada IA nueva y antes de enviar formularios.
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use crate::state::{now, Shared};
use crate::tabs;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tauri::AppHandle;
use tokio::sync::oneshot;

pub const DEFAULT_PORT: u16 = 47821;
/// Límite de pestañas que una IA puede tener abiertas a la vez.
const MAX_AI_TABS: usize = 30;

#[derive(Default)]
pub struct Control {
    token: Mutex<String>,
    port: Mutex<u16>,
    approved: Mutex<HashSet<String>>,
    fails: Mutex<Vec<Instant>>,
    locked_until: Mutex<Option<Instant>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    pub active_client: Mutex<Option<(String, u64, String)>>,
}

pub static CONTROL: OnceLock<Arc<Control>> = OnceLock::new();

pub fn control() -> Arc<Control> {
    CONTROL.get_or_init(|| Arc::new(Control::default())).clone()
}

#[derive(Clone)]
struct Ctx {
    app: AppHandle,
    sh: Arc<Shared>,
    ctl: Arc<Control>,
}

fn new_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn token_file(sh: &Shared) -> std::path::PathBuf {
    sh.data_dir.join("control.json")
}

pub fn is_running() -> bool {
    control().shutdown.lock().is_some()
}

pub fn port() -> u16 {
    *control().port.lock()
}

/// Enciende la puerta de control. Escribe el token en un archivo que solo lee tu usuario.
pub async fn start(app: AppHandle, sh: Arc<Shared>) -> anyhow::Result<u16> {
    let ctl = control();
    if ctl.shutdown.lock().is_some() {
        return Ok(*ctl.port.lock());
    }
    let mut listener = None;
    for p in DEFAULT_PORT..DEFAULT_PORT + 10 {
        if let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", p)).await {
            listener = Some((l, p));
            break;
        }
    }
    let (listener, port) = listener.ok_or_else(|| anyhow::anyhow!("No hay puerto libre para la puerta de control"))?;
    let token = new_token();
    *ctl.token.lock() = token.clone();
    *ctl.port.lock() = port;
    crate::state::write_json(&token_file(&sh), &json!({ "port": port, "token": token, "api": format!("http://127.0.0.1:{port}/v1/") }));

    let (tx, rx) = oneshot::channel::<()>();
    *ctl.shutdown.lock() = Some(tx);
    let ctx = Ctx { app, sh: sh.clone(), ctl: ctl.clone() };
    let router = Router::new().route("/v1/{action}", post(handle)).fallback(fallback).with_state(ctx);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    sh.sec("ctlOn", json!({ "port": port }), format!("Puerta de control para IAs activada en 127.0.0.1:{port}"));
    Ok(port)
}

pub fn stop(sh: &Shared) {
    let ctl = control();
    if let Some(tx) = ctl.shutdown.lock().take() {
        let _ = tx.send(());
    }
    ctl.approved.lock().clear();
    *ctl.active_client.lock() = None;
    *ctl.token.lock() = String::new();
    let _ = std::fs::remove_file(token_file(sh));
    sh.deny_all_approvals();
    sh.sec("ctlOff", json!({}), "Puerta de control para IAs desactivada".into());
}

/// Botón "Cortar IA": expulsa a todas las IAs y cambia el token.
pub fn cut(sh: &Shared) {
    let ctl = control();
    ctl.approved.lock().clear();
    *ctl.active_client.lock() = None;
    sh.deny_all_approvals();
    if ctl.shutdown.lock().is_some() {
        let token = new_token();
        *ctl.token.lock() = token.clone();
        let port = *ctl.port.lock();
        crate::state::write_json(&token_file(sh), &json!({ "port": port, "token": token, "api": format!("http://127.0.0.1:{port}/v1/") }));
    }
    sh.sec("ctlCut", json!({}), "IA desconectada por el usuario. Token cambiado.".into());
    sh.emit("ai-activity", json!({ "client": null }));
}

async fn fallback(ConnectInfo(peer): ConnectInfo<SocketAddr>, State(ctx): State<Ctx>) -> Response {
    ctx.sh.intruder("unknownReq", json!({}), "Petición desconocida a la puerta de control".into());
    (StatusCode::NOT_FOUND, "no").into_response()
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "ok": false, "error": msg }))).into_response()
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Comprueba que quien llama es una IA legítima en este PC. Devuelve su nombre.
async fn guard(ctx: &Ctx, peer: SocketAddr, headers: &HeaderMap) -> Result<String, Response> {
    let sh = &ctx.sh;
    let ctl = &ctx.ctl;
    if !peer.ip().is_loopback() {
        sh.intruder("externalConn", json!({ "peer": peer.to_string() }), format!("Conexión externa rechazada desde {peer}"));
        return Err(err(StatusCode::FORBIDDEN, "solo conexiones locales"));
    }
    if let Some(t) = *ctl.locked_until.lock() {
        if Instant::now() < t {
            return Err(err(StatusCode::TOO_MANY_REQUESTS, "bloqueado temporalmente por intentos fallidos"));
        }
    }
    // Una página web nunca debe poder usar esta puerta (los navegadores envían estas cabeceras).
    if headers.contains_key("origin") || headers.contains_key("sec-fetch-site") || headers.contains_key("referer") {
        sh.intruder("webPage", json!({}), "Una página web intentó usar la puerta de control. Bloqueado.".into());
        return Err(err(StatusCode::FORBIDDEN, "origen no permitido"));
    }
    let port = *ctl.port.lock();
    let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        sh.intruder("badHost", json!({ "host": host }), format!("Cabecera Host sospechosa: {host}"));
        return Err(err(StatusCode::FORBIDDEN, "host no permitido"));
    }
    let given = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    let token = ctl.token.lock().clone();
    if !ct_eq(given, &token) {
        let n = {
            let mut f = ctl.fails.lock();
            let cutoff = Instant::now() - Duration::from_secs(60);
            f.retain(|t| *t > cutoff);
            f.push(Instant::now());
            f.len()
        };
        sh.intruder("badToken", json!({ "n": n }), format!("Intento de acceso con token incorrecto ({n} en el último minuto)"));
        if n >= 5 {
            *ctl.locked_until.lock() = Some(Instant::now() + Duration::from_secs(300));
            sh.intruder("lockout", json!({}), "Demasiados intentos: puerta de control bloqueada 5 minutos".into());
        }
        return Err(err(StatusCode::UNAUTHORIZED, "token incorrecto"));
    }
    let client: String = headers
        .get("x-sombra-client")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("IA sin nombre")
        .chars()
        .filter(|c| c.is_alphanumeric() || " -_.()".contains(*c))
        .take(40)
        .collect();
    let client = if client.trim().is_empty() { "IA sin nombre".to_string() } else { client };
    if !ctl.approved.lock().contains(&client) {
        let ok = sh.ask_user("newAi", json!({ "client": client }), format!("«{client}» quiere controlar Sombra. ¿Le das permiso durante esta sesión?")).await;
        if !ok {
            sh.sec("aiDenied", json!({ "client": client }), format!("Acceso denegado a «{client}»"));
            return Err(err(StatusCode::FORBIDDEN, "el usuario no ha dado permiso"));
        }
        ctl.approved.lock().insert(client.clone());
        sh.sec("aiAllowed", json!({ "client": client }), format!("«{client}» autorizada para controlar Sombra"));
    }
    Ok(client)
}

async fn handle(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(ctx): State<Ctx>,
    Path(action): Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    let client = match guard(&ctx, peer, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let args = body.map(|b| b.0).unwrap_or(json!({}));
    *ctx.ctl.active_client.lock() = Some((client.clone(), now(), action.clone()));
    ctx.sh.emit("ai-activity", json!({ "client": client, "action": action }));
    ctx.sh.log_ai(format!("{client}: {action} {}", summarize(&args)));
    match run(&ctx, &client, &action, &args).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

fn summarize(a: &Value) -> String {
    let mut s = a.to_string();
    if let Some(t) = a.get("text") {
        if t.is_string() {
            s = s.replace(t.as_str().unwrap_or(""), "•••");
        }
    }
    s.chars().take(160).collect()
}

fn tab_arg(sh: &Shared, a: &Value) -> anyhow::Result<u32> {
    if let Some(t) = a.get("tab").and_then(|v| v.as_u64()) {
        return Ok(t as u32);
    }
    tabs::active_id(sh).ok_or_else(|| anyhow::anyhow!("no hay pestaña activa"))
}

fn id_arg(a: &Value) -> anyhow::Result<u64> {
    a.get("id").and_then(|v| v.as_u64()).ok_or_else(|| anyhow::anyhow!("falta 'id' (número de elemento devuelto por 'read')"))
}

async fn run(ctx: &Ctx, client: &str, action: &str, a: &Value) -> anyhow::Result<Value> {
    let (app, sh) = (&ctx.app, &ctx.sh);
    match action {
        "status" => Ok(json!({
            "ok": true,
            "tor": sh.tor.status(),
            "tabs": sh.tabs.lock().list,
            "active": tabs::active_id(sh),
        })),
        "open" => {
            let url = a.get("url").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("falta 'url'"))?;
            let wants_new = a.get("new_tab").and_then(|v| v.as_bool()).unwrap_or(false);
            if wants_new && sh.tabs.lock().list.len() >= MAX_AI_TABS {
                anyhow::bail!("Demasiadas pestañas abiertas ({MAX_AI_TABS}). Cierra alguna con close_tab.");
            }
            let id = if a.get("new_tab").and_then(|v| v.as_bool()).unwrap_or(false) || tabs::active_id(sh).is_none() {
                tabs::new_tab(app, sh, None).await?
            } else {
                tab_arg(sh, a)?
            };
            tabs::activate(app, sh, id);
            tabs::navigate(app, sh, id, url).await?;
            tabs::wait_loaded(sh, id, 45).await;
            let page = read(ctx, id, 3000).await?;
            Ok(json!({ "ok": true, "tab": id, "page": page }))
        }
        "read" => {
            let id = tab_arg(sh, a)?;
            let max = a.get("max_chars").and_then(|v| v.as_u64()).unwrap_or(8000).min(60000);
            Ok(json!({ "ok": true, "tab": id, "page": read(ctx, id, max).await? }))
        }
        "click" => {
            let id = tab_arg(sh, a)?;
            let el = id_arg(a)?;
            let info = tabs::eval_tab(app, id, probe_js(el)).await?;
            if info.get("exists").and_then(|v| v.as_bool()) != Some(true) {
                anyhow::bail!("No existe el elemento {el}. Vuelve a llamar a 'read'.");
            }
            if info.get("submit").and_then(|v| v.as_bool()) == Some(true) {
                let what = info.get("label").and_then(|v| v.as_str()).unwrap_or("formulario");
                let host = current_host(sh, id);
                let ok = sh.ask_user("submit", json!({ "client": client, "host": host }), format!("«{client}» quiere enviar un formulario en {host} (botón «{what}»). ¿Lo permites?")).await;
                if !ok {
                    anyhow::bail!("El usuario no ha permitido enviar el formulario");
                }
            }
            tabs::eval_tab(app, id, click_js(el)).await?;
            tabs::wait_loaded(sh, id, 30).await;
            Ok(json!({ "ok": true, "tab": id, "url": current_url(sh, id) }))
        }
        "type" => {
            let id = tab_arg(sh, a)?;
            let el = id_arg(a)?;
            let text = a.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let info = tabs::eval_tab(app, id, probe_js(el)).await?;
            if info.get("exists").and_then(|v| v.as_bool()) != Some(true) {
                anyhow::bail!("No existe el elemento {el}. Vuelve a llamar a 'read'.");
            }
            if info.get("password").and_then(|v| v.as_bool()) == Some(true) {
                sh.emit("notice", json!({ "code": "password", "message": "Una IA ha llegado a un campo de contraseña: escríbela tú en la página." }));
                anyhow::bail!("Por seguridad, las contraseñas las escribe el usuario. Pídele que la escriba en Sombra.");
            }
            let r = tabs::eval_tab(app, id, type_js(el, text)).await?;
            if a.get("submit").and_then(|v| v.as_bool()) == Some(true) {
                let host = current_host(sh, id);
                let ok = sh.ask_user("submit", json!({ "client": client, "host": host }), format!("«{client}» quiere enviar un formulario en {host}. ¿Lo permites?")).await;
                if !ok {
                    anyhow::bail!("El usuario no ha permitido enviar el formulario");
                }
                tabs::eval_tab(app, id, submit_js(el)).await?;
                tabs::wait_loaded(sh, id, 30).await;
            }
            Ok(json!({ "ok": true, "result": r }))
        }
        "select" => {
            let id = tab_arg(sh, a)?;
            let el = id_arg(a)?;
            let v = a.get("value").and_then(|v| v.as_str()).unwrap_or("");
            Ok(json!({ "ok": true, "result": tabs::eval_tab(app, id, select_js(el, v)).await? }))
        }
        "scroll" => {
            let id = tab_arg(sh, a)?;
            let dy = a.get("dy").and_then(|v| v.as_i64()).unwrap_or(600);
            tabs::eval_tab(app, id, format!("(() => {{ window.scrollBy(0, {dy}); return 'ok'; }})()")).await?;
            Ok(json!({ "ok": true }))
        }
        "back" | "forward" | "reload" => {
            let id = tab_arg(sh, a)?;
            let js = match action {
                "back" => "history.back()",
                "forward" => "history.forward()",
                _ => "location.reload()",
            };
            tabs::eval_tab(app, id, format!("(() => {{ {js}; return 'ok'; }})()")).await?;
            tabs::wait_loaded(sh, id, 30).await;
            Ok(json!({ "ok": true, "url": current_url(sh, id) }))
        }
        "tabs" => Ok(json!({ "ok": true, "tabs": sh.tabs.lock().list, "active": tabs::active_id(sh) })),
        "switch_tab" => {
            let id = tab_arg(sh, a)?;
            tabs::activate(app, sh, id);
            Ok(json!({ "ok": true }))
        }
        "close_tab" => {
            let id = tab_arg(sh, a)?;
            tabs::close(app, sh, id).await?;
            Ok(json!({ "ok": true }))
        }
        "country" => {
            let code = a.get("code").and_then(|v| v.as_str());
            sh.tor.set_country(code)?;
            sh.settings.lock().country = sh.tor.status().country;
            sh.save_settings();
            Ok(json!({ "ok": true, "country": sh.tor.status().country }))
        }
        "new_identity" => {
            sh.tor.new_identity();
            Ok(json!({ "ok": true }))
        }
        _ => anyhow::bail!(
            "Acción desconocida. Disponibles: status, open, read, click, type, select, scroll, back, forward, reload, tabs, switch_tab, close_tab, country, new_identity"
        ),
    }
}

fn current_url(sh: &Shared, id: u32) -> String {
    sh.tabs.lock().list.iter().find(|t| t.id == id).map(|t| t.url.clone()).unwrap_or_default()
}

fn current_host(sh: &Shared, id: u32) -> String {
    url::Url::parse(&current_url(sh, id))
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| "esta web".into())
}

/// Lee la página: texto visible + lista numerada de elementos con los que se puede interactuar.
async fn read(ctx: &Ctx, id: u32, max: u64) -> anyhow::Result<Value> {
    let v = tabs::eval_tab(&ctx.app, id, read_js(max)).await?;
    if v.get("captcha").and_then(|x| x.as_bool()) == Some(true) {
        tabs::activate(&ctx.app, &ctx.sh, id);
        ctx.sh.emit("captcha", current_host(&ctx.sh, id));
        ctx.sh.sec("captcha", json!({ "h": current_host(&ctx.sh, id) }), format!("CAPTCHA en {}: esperando a que lo resuelvas tú", current_host(&ctx.sh, id)));
    }
    Ok(v)
}

fn read_js(max: u64) -> String {
    format!(
        r#"(() => {{ try {{
  const els = [...document.querySelectorAll('a[href],button,input,select,textarea,[role=button],[role=link],[role=checkbox],[role=tab],[contenteditable=true],summary')];
  const out = []; let i = 0;
  document.querySelectorAll('[data-sombra-id]').forEach(e => e.removeAttribute('data-sombra-id'));
  for (const e of els) {{
    const r = e.getBoundingClientRect(); const st = getComputedStyle(e);
    if ((r.width === 0 && r.height === 0) || st.visibility === 'hidden' || st.display === 'none') continue;
    if (e.tagName === 'INPUT' && e.type === 'hidden') continue;
    i++; e.setAttribute('data-sombra-id', String(i));
    const lab = ((e.labels && e.labels[0] && e.labels[0].innerText) || e.getAttribute('aria-label') || e.placeholder || e.name || e.title || '').trim();
    const o = {{ id: i, tag: e.tagName.toLowerCase() }};
    if (e.type) o.type = e.type;
    if (lab) o.label = lab.slice(0, 80);
    const t = (e.tagName === 'INPUT' || e.tagName === 'TEXTAREA') ? (e.type === 'password' ? (e.value ? '(rellenado)' : '') : e.value) : e.innerText;
    if (t && t.trim()) o.text = t.trim().replace(/\s+/g, ' ').slice(0, 80);
    if (e.href) o.href = String(e.href).slice(0, 200);
    if (e.tagName === 'SELECT') o.options = [...e.options].slice(0, 30).map(x => x.value + '=' + x.text.trim().slice(0, 30));
    if (e.type === 'checkbox' || e.type === 'radio') o.checked = e.checked;
    out.push(o);
    if (i >= 400) break;
  }}
  const captcha = !!document.querySelector('iframe[src*="recaptcha"],iframe[src*="hcaptcha"],iframe[src*="challenges.cloudflare.com"],.g-recaptcha,.h-captcha,.cf-turnstile,#challenge-form,#cf-challenge-running');
  const text = (document.body ? document.body.innerText : '').replace(/\n{{3,}}/g, '\n\n');
  return JSON.stringify({{ url: location.href, title: document.title, captcha, text: text.slice(0, {max}), truncated: text.length > {max}, elements: out }});
}} catch (e) {{ return JSON.stringify({{ error: String(e) }}); }} }})()"#
    )
}

fn el_js(id: u64) -> String {
    format!("document.querySelector('[data-sombra-id=\"{id}\"]')")
}

fn probe_js(id: u64) -> String {
    format!(
        r#"(() => {{ const e = {}; if (!e) return JSON.stringify({{ exists: false }});
  const form = e.form || e.closest('form');
  const isBtn = e.tagName === 'BUTTON' ? ((e.getAttribute('type') || 'submit').toLowerCase() === 'submit') : (e.tagName === 'INPUT' && ['submit','image'].includes(e.type));
  return JSON.stringify({{ exists: true, password: e.tagName === 'INPUT' && e.type === 'password', submit: !!(form && isBtn), label: (e.innerText || e.value || e.getAttribute('aria-label') || '').trim().slice(0, 40) }});
}})()"#,
        el_js(id)
    )
}

fn click_js(id: u64) -> String {
    format!(
        r#"(() => {{ const e = {}; if (!e) return 'missing'; e.scrollIntoView({{ block: 'center' }}); e.focus && e.focus(); e.click(); return 'ok'; }})()"#,
        el_js(id)
    )
}

fn type_js(id: u64, text: &str) -> String {
    let t = serde_json::to_string(text).unwrap_or_else(|_| "''".into());
    format!(
        r#"(() => {{ const e = {}; if (!e) return 'missing'; e.scrollIntoView({{ block: 'center' }}); e.focus && e.focus();
  if (e.isContentEditable) {{ e.innerText = {t}; e.dispatchEvent(new InputEvent('input', {{ bubbles: true }})); return 'ok'; }}
  const proto = e.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value').set; setter.call(e, {t});
  e.dispatchEvent(new Event('input', {{ bubbles: true }})); e.dispatchEvent(new Event('change', {{ bubbles: true }})); return 'ok'; }})()"#,
        el_js(id)
    )
}

fn submit_js(id: u64) -> String {
    format!(
        r#"(() => {{ const e = {}; if (!e) return 'missing'; const f = e.form || e.closest('form');
  if (f) {{ f.requestSubmit ? f.requestSubmit() : f.submit(); return 'ok'; }}
  e.dispatchEvent(new KeyboardEvent('keydown', {{ key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }})); return 'enter'; }})()"#,
        el_js(id)
    )
}

fn select_js(id: u64, v: &str) -> String {
    let v = serde_json::to_string(v).unwrap_or_else(|_| "''".into());
    format!(
        r#"(() => {{ const e = {}; if (!e) return 'missing';
  if (e.type === 'checkbox' || e.type === 'radio') {{ const want = {v} !== 'false'; if (e.checked !== want) e.click(); return 'ok'; }}
  e.value = {v}; e.dispatchEvent(new Event('input', {{ bubbles: true }})); e.dispatchEvent(new Event('change', {{ bubbles: true }})); return e.value; }})()"#,
        el_js(id)
    )
}
