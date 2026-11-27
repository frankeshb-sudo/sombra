// Sombra - proxy SOCKS5 local. Todo el tráfico de las pestañas pasa por aquí:
//  1) se bloquean dominios de publicidad y rastreo,
//  2) modo Sombra: lo demás sale SOLO por Tor (si Tor falla, no hay conexión: "kill switch");
//     modo normal: sale directo (otro puerto, otro perfil del motor; nunca se mezclan).
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use crate::blocker::BlockKind;
use crate::state::Shared;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn serve(listener: TcpListener, shared: Arc<Shared>, private: bool) {
    loop {
        let Ok((sock, peer)) = listener.accept().await else { continue };
        // Solo el propio Sombra (127.0.0.1) puede usar el proxy.
        if !peer.ip().is_loopback() {
            continue;
        }
        let sh = shared.clone();
        tokio::spawn(async move {
            let _ = handle(sock, sh, private).await;
        });
    }
}

const REP_OK: u8 = 0x00;
const REP_FAIL: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_CMD_UNSUPPORTED: u8 = 0x07;

async fn reply(s: &mut TcpStream, code: u8) -> std::io::Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn handle(mut s: TcpStream, sh: Arc<Shared>, private: bool) -> anyhow::Result<()> {
    s.set_nodelay(true).ok();
    // Saludo: versión 5, sin autenticación.
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        anyhow::bail!("no es SOCKS5");
    }
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await?;
    s.write_all(&[5, 0]).await?;

    // Petición.
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[1] != 1 {
        // Solo CONNECT. UDP (lo que usa WebRTC/QUIC) no se permite: evitaría Tor.
        sh.stats.leaks_blocked.fetch_add(1, Ordering::Relaxed);
        reply(&mut s, REP_CMD_UNSUPPORTED).await?;
        return Ok(());
    }
    let host = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_ascii_lowercase()
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => anyhow::bail!("tipo de dirección desconocido"),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    // Nunca dejar que una web alcance tu red local o este mismo PC. En modo normal sí se
    // puede abrir a propósito una dirección local (el router, una impresora...): solo la web
    // que tú has abierto, no lo que una web de internet pida por su cuenta.
    // Solo si la dirección es local en sí (192.168.1.1, router.lan...): un dominio de internet
    // abierto por ti nunca puede apuntar a tu red local (DNS rebinding).
    // AutoFirma (modo normal): tras abrirla, la web le habla en este PC, solo por los puertos
    // que iban en el enlace afirma://. Nunca a los puertos del propio Sombra.
    let afirma_ok = !private && is_loopback(&host) && sh.afirma_port(port) && !own_port(port);
    let local_ok = afirma_ok || !private && is_local(&host) && sh.is_top_level_host(&host);
    if is_local(&host) && !local_ok {
        sh.stats.leaks_blocked.fetch_add(1, Ordering::Relaxed);
        sh.sec("localBlocked", serde_json::json!({ "host": format!("{host}:{port}") }), format!("Bloqueado acceso a red local: {host}:{port}"));
        reply(&mut s, REP_NOT_ALLOWED).await?;
        return Ok(());
    }

    // Publicidad y rastreadores (sin bloquear nunca la web que tú has abierto).
    if sh.blocking_enabled.load(Ordering::Relaxed) && !sh.is_top_level_host(&host) {
        if let Some(b) = sh.blocker() {
            if let Some(kind) = b.check_host(&host) {
                match kind {
                    BlockKind::Ad => sh.stats.ads.fetch_add(1, Ordering::Relaxed),
                    BlockKind::Tracker => sh.stats.trackers.fetch_add(1, Ordering::Relaxed),
                };
                sh.stats.page_blocked.fetch_add(1, Ordering::Relaxed);
                reply(&mut s, REP_NOT_ALLOWED).await?;
                return Ok(());
            }
        }
    }

    // Modo solo HTTPS: nada sale sin cifrar (puerto 80) salvo las webs que el usuario ha
    // aceptado abrir así. Los .onion ya van cifrados de punta a punta dentro de Tor.
    if port == 80 && !host.ends_with(".onion") && !is_local(&host) && sh.settings.lock().https_only && !sh.http_allowed(&host) {
        sh.stats.page_blocked.fetch_add(1, Ordering::Relaxed);
        reply(&mut s, REP_NOT_ALLOWED).await?;
        return Ok(());
    }

    if !private {
        return direct(s, &sh, &host, port, local_ok).await;
    }

    // Salida únicamente por Tor.
    // Los servicios .onion a veces fallan al primer intento mientras Tor encuentra la ruta: se reintenta.
    let attempts = if host.ends_with(".onion") { 3 } else { 1 };
    let mut result = sh.tor.connect(&host, port).await;
    for _ in 1..attempts {
        if result.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        result = sh.tor.connect(&host, port).await;
    }
    let (mut tor_stream, cut) = match result {
        Ok(t) => t,
        Err(_) => {
            reply(&mut s, REP_FAIL).await?;
            return Ok(());
        }
    };
    reply(&mut s, REP_OK).await?;
    sh.stats.connections.fetch_add(1, Ordering::Relaxed);
    // Se corta si se pide un circuito nuevo para este dominio (por ejemplo, en cada búsqueda).
    let cut_signal = cut.notified();
    tokio::pin!(cut_signal);
    cut_signal.as_mut().enable();
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut s, &mut tor_stream) => {}
        _ = cut_signal => {}
    }
    Ok(())
}

fn is_loopback(host: &str) -> bool {
    matches!(host.trim_end_matches('.'), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Puertos en los que escucha el propio Sombra (proxys y puerta de control de las IAs).
fn own_port(port: u16) -> bool {
    // Sin motor todavía no se conocen: se trata como propio (no se deja pasar).
    crate::tabs::ENGINE.get().map_or(true, |e| e.proxy_port == port || e.normal_port == port) || crate::control::port() == port
}

pub fn is_local(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    const LOCAL_SUFFIXES: [&str; 8] = [".localhost", ".local", ".lan", ".internal", ".home", ".home.arpa", ".corp", ".intranet"];
    if h == "localhost" || LOCAL_SUFFIXES.iter().any(|s| h.ends_with(s)) || !h.contains('.') && h.parse::<IpAddr>().is_err() && !h.contains(':') {
        return true;
    }
    match h.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
        }
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// Modo normal: conexión directa. Los .onion solo existen dentro de Tor. Se comprueba también
/// la dirección a la que apunta el nombre: una web no puede llegar a tu red local con un
/// dominio que apunte a 192.168.x.x (salvo la dirección local que tú has abierto).
async fn direct(mut s: TcpStream, sh: &Shared, host: &str, port: u16, local_ok: bool) -> anyhow::Result<()> {
    if host.ends_with(".onion") {
        reply(&mut s, REP_NOT_ALLOWED).await?;
        return Ok(());
    }
    let Some(mut out) = connect_direct(host, port, local_ok).await else {
        reply(&mut s, REP_FAIL).await?;
        return Ok(());
    };
    out.set_nodelay(true).ok();
    reply(&mut s, REP_OK).await?;
    sh.stats.connections.fetch_add(1, Ordering::Relaxed);
    let _ = tokio::io::copy_bidirectional(&mut s, &mut out).await;
    Ok(())
}

/// Conexión directa a una web: primero IPv4 (muchas redes no tienen IPv6 y esa ruta se queda
/// colgada) y cada dirección con su tiempo máximo. Nunca a la red local salvo `local_ok`.
pub async fn connect_direct(host: &str, port: u16, local_ok: bool) -> Option<TcpStream> {
    use std::time::Duration;
    let mut addrs: Vec<std::net::SocketAddr> = match tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host, port))).await {
        Ok(Ok(a)) => a.filter(|a| local_ok || !is_local(&a.ip().to_string())).collect(),
        _ => return None,
    };
    addrs.sort_by_key(|a| a.is_ipv6());
    for a in addrs.iter().take(4) {
        if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_secs(6), TcpStream::connect(a)).await {
            return Some(st);
        }
    }
    None
}
