// Sombra - DNS seguro para el modo normal (DNS sobre HTTPS, RFC 8484).
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.
//
// Sin esto, cada dirección que abres se pregunta al DNS del sistema en claro y tu compañía de
// internet ve todas las webs que visitas. Con esto las preguntas van cifradas a Cloudflare (y si no
// responde, a AdGuard, su servicio sin filtros). Los dos aceptan HTTP/1.1; Quad9 solo HTTP/2. El modo Sombra no lo necesita: allí los nombres los resuelve Tor.
// Las respuestas se guardan un rato solo en memoria.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

/// Activado en Ajustes (por defecto, sí).
pub static ENABLED: AtomicBool = AtomicBool::new(true);

struct Provider {
    /// Nombre del certificado del servidor (y cabecera Host).
    name: &'static str,
    ips: [IpAddr; 2],
}

/// Se conecta directamente a la IP: no hace falta un DNS en claro para encontrar al DNS seguro.
const PROVIDERS: [Provider; 2] = [
    Provider { name: "cloudflare-dns.com", ips: [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))] },
    Provider { name: "unfiltered.adguard-dns.com", ips: [IpAddr::V4(Ipv4Addr::new(94, 140, 14, 140)), IpAddr::V4(Ipv4Addr::new(94, 140, 14, 141))] },
];

/// El último servidor que respondió bien (se prueba primero).
static BEST: AtomicUsize = AtomicUsize::new(0);
/// Conexiones abiertas para reutilizar (cada pregunta nueva no repite el saludo TLS), con el
/// momento en que se dejaron libres.
static POOL: Mutex<Vec<(usize, Instant, TlsStream<TcpStream>)>> = parking_lot::const_mutex(Vec::new());
const POOL_MAX: usize = 8;
/// Una conexión parada más tiempo no se reutiliza: el servidor puede haberla cerrado, o la red
/// haber cambiado (otra wifi) y la conexión quedar muerta sin avisar.
const POOL_IDLE: Duration = Duration::from_secs(20);
static CACHE: LazyLock<Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>> = LazyLock::new(Default::default);
const CACHE_MAX: usize = 4096;
const A: u16 = 1;
const AAAA: u16 = 28;
/// Tamaño máximo de una respuesta DNS.
const MAX_BODY: usize = 65_535;

fn tls() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("TLS")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// ¿Se resolvió `host` por DNS seguro? (solo para las pruebas)
#[cfg(debug_assertions)]
pub fn cached(host: &str) -> bool {
    CACHE.lock().contains_key(host)
}

/// Borra lo que se recuerda (al limpiar el historial).
pub fn clear() {
    CACHE.lock().clear();
}

/// Direcciones de `host` por DNS seguro. `Some(vacío)` si el nombre no existe; `None` si
/// ningún servidor responde (entonces la web no se abre: nunca se pregunta en claro).
pub async fn resolve(host: &str) -> Option<Vec<IpAddr>> {
    let key = host.trim_end_matches('.').to_ascii_lowercase();
    {
        let c = CACHE.lock();
        if let Some((ips, until)) = c.get(&key) {
            if *until > Instant::now() {
                return Some(ips.clone());
            }
        }
    }
    let (a, aaaa) = tokio::join!(ask_any(&key, A), ask_any(&key, AAAA));
    if a.is_none() && aaaa.is_none() {
        return None;
    }
    let (mut ips, mut ttl) = (Vec::new(), u32::MAX);
    for (v, t) in [a, aaaa].into_iter().flatten() {
        if !v.is_empty() {
            ttl = ttl.min(t);
        }
        ips.extend(v);
    }
    let ttl = if ips.is_empty() { 30 } else { ttl.clamp(30, 600) };
    let mut c = CACHE.lock();
    if c.len() >= CACHE_MAX {
        let now = Instant::now();
        c.retain(|_, (_, until)| *until > now);
        if c.len() >= CACHE_MAX {
            c.clear();
        }
    }
    c.insert(key, (ips.clone(), Instant::now() + Duration::from_secs(ttl as u64)));
    Some(ips)
}

/// Pregunta a los servidores en orden, empezando por el último que funcionó.
async fn ask_any(name: &str, qtype: u16) -> Option<(Vec<IpAddr>, u32)> {
    let q = query(name, qtype)?;
    let first = BEST.load(Ordering::Relaxed);
    for k in 0..PROVIDERS.len() {
        let p = (first + k) % PROVIDERS.len();
        if let Some(r) = ask(p, &q).await.and_then(|b| parse(&b, qtype)) {
            BEST.store(p, Ordering::Relaxed);
            return Some(r);
        }
    }
    None
}

async fn ask(p: usize, q: &[u8]) -> Option<Vec<u8>> {
    let pooled = {
        let mut pool = POOL.lock();
        pool.retain(|(_, t, _)| t.elapsed() < POOL_IDLE);
        pool.iter().position(|(i, _, _)| *i == p).map(|k| pool.swap_remove(k).2)
    };
    // Una conexión guardada puede haberla cerrado el servidor: si falla, se abre otra.
    if let Some(mut s) = pooled {
        if let Ok(Some((body, keep))) = timeout(Duration::from_secs(4), exchange(&mut s, PROVIDERS[p].name, q)).await {
            if keep {
                put(p, s);
            }
            return Some(body);
        }
    }
    let mut s = connect(p).await?;
    let (body, keep) = timeout(Duration::from_secs(5), exchange(&mut s, PROVIDERS[p].name, q)).await.ok()??;
    if keep {
        put(p, s);
    }
    Some(body)
}

fn put(p: usize, s: TlsStream<TcpStream>) {
    let mut pool = POOL.lock();
    if pool.len() < POOL_MAX {
        pool.push((p, Instant::now(), s));
    }
}

async fn connect(p: usize) -> Option<TlsStream<TcpStream>> {
    let pr = &PROVIDERS[p];
    let name = rustls::pki_types::ServerName::try_from(pr.name).ok()?;
    for ip in pr.ips {
        let Ok(Ok(tcp)) = timeout(Duration::from_secs(3), TcpStream::connect((ip, 443))).await else { continue };
        tcp.set_nodelay(true).ok();
        if let Ok(Ok(t)) = timeout(Duration::from_secs(4), tokio_rustls::TlsConnector::from(tls()).connect(name.clone(), tcp)).await {
            return Some(t);
        }
    }
    None
}

fn find(b: &[u8], pat: &[u8]) -> Option<usize> {
    b.windows(pat.len()).position(|w| w == pat)
}

async fn more<S: AsyncReadExt + Unpin>(s: &mut S, b: &mut Vec<u8>) -> Option<()> {
    let mut tmp = [0u8; 4096];
    let n = s.read(&mut tmp).await.ok()?;
    if n == 0 || b.len() > MAX_BODY + 16_384 {
        return None;
    }
    b.extend_from_slice(&tmp[..n]);
    Some(())
}

/// Una pregunta por HTTP/1.1. Devuelve la respuesta y si la conexión se puede reutilizar.
async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, host: &str, q: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut req = format!(
        "POST /dns-query HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        q.len()
    )
    .into_bytes();
    req.extend_from_slice(q);
    s.write_all(&req).await.ok()?;
    let mut b = Vec::with_capacity(1024);
    let end = loop {
        if let Some(p) = find(&b, b"\r\n\r\n") {
            break p + 4;
        }
        if b.len() > 16_384 {
            return None;
        }
        more(s, &mut b).await?;
    };
    let head = std::str::from_utf8(&b[..end]).ok()?.to_ascii_lowercase();
    let mut lines = head.split("\r\n");
    if lines.next()?.split(' ').nth(1)? != "200" {
        return None;
    }
    let (mut len, mut chunked, mut close) = (None, false, false);
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let v = v.trim();
            match k.trim() {
                "content-length" => len = v.parse::<usize>().ok(),
                "transfer-encoding" => chunked = v.contains("chunked"),
                "connection" => close = v.contains("close"),
                _ => {}
            }
        }
    }
    let mut rest = b.split_off(end);
    let body = if chunked {
        let mut out = Vec::new();
        loop {
            let p = loop {
                if let Some(p) = find(&rest, b"\r\n") {
                    break p;
                }
                more(s, &mut rest).await?;
            };
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..p]).ok()?.split(';').next()?.trim(), 16).ok()?;
            rest.drain(..p + 2);
            if size == 0 {
                // Fin (sin cabeceras finales: si las hubiera, la conexión no se reutiliza).
                while rest.len() < 2 {
                    more(s, &mut rest).await?;
                }
                close |= &rest[..2] != b"\r\n";
                break out;
            }
            if out.len() + size > MAX_BODY {
                return None;
            }
            while rest.len() < size + 2 {
                more(s, &mut rest).await?;
            }
            out.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
    } else {
        let len = len?;
        if len > MAX_BODY {
            return None;
        }
        while rest.len() < len {
            more(s, &mut rest).await?;
        }
        rest.truncate(len);
        rest
    };
    Some((body, !close))
}

/// Pregunta DNS (formato binario) para `name` y el tipo `qtype` (A o AAAA).
fn query(name: &str, qtype: u16) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    // Número 0 (RFC 8484, mejor para la caché), recursión pedida, una pregunta.
    let mut q = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        if l.is_empty() || l.len() > 63 || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return None;
        }
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    Some(q)
}

fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *m.get(i)?;
        match l & 0xc0 {
            0 if l == 0 => return Some(i + 1),
            0 => i += 1 + l as usize,
            // Puntero de compresión: el nombre termina aquí.
            0xc0 => return m.get(i + 1).map(|_| i + 2),
            _ => return None,
        }
    }
}

/// Lee una respuesta: direcciones del tipo pedido y el tiempo que valen (segundos).
/// `Some(vacío)` si el nombre no existe; `None` si la respuesta no es válida.
fn parse(m: &[u8], qtype: u16) -> Option<(Vec<IpAddr>, u32)> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    match m[3] & 0x0f {
        0 => {}
        3 => return Some((Vec::new(), 60)), // No existe.
        _ => return None,
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i)? + 4;
    }
    let (mut out, mut ttl) = (Vec::new(), u32::MAX);
    for _ in 0..an {
        i = skip_name(m, i)?;
        let h = m.get(i..i + 10)?;
        let t = u16::from_be_bytes([h[0], h[1]]);
        let rttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let len = u16::from_be_bytes([h[8], h[9]]) as usize;
        i += 10;
        let d = m.get(i..i + len)?;
        i += len;
        let ip = match (t, len) {
            (A, 4) if qtype == A => IpAddr::from([d[0], d[1], d[2], d[3]]),
            (AAAA, 16) if qtype == AAAA => IpAddr::from(<[u8; 16]>::try_from(d).ok()?),
            _ => continue,
        };
        out.push(ip);
        ttl = ttl.min(rttl);
    }
    Some((out, if ttl == u32::MAX { 60 } else { ttl }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pregunta_y_respuesta() {
        let q = query("www.Example.com.", A).unwrap();
        assert_eq!(&q[12..], b"\x03www\x07Example\x03com\x00\x00\x01\x00\x01");
        assert!(query("bad..name", A).is_none());
        assert!(query("a b.com", A).is_none());
        assert!(query(&"a".repeat(64), A).is_none());
        // Respuesta: CNAME (comprimido) y luego la dirección A.
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        r.extend_from_slice(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x01\x00\x00\x06\x03cdn\xc0\x10");
        r.extend_from_slice(b"\xc0\x2d\x00\x01\x00\x01\x00\x00\x00\x50\x00\x04\x5d\xb8\xd7\x0e");
        assert_eq!(parse(&r, A), Some((vec!["93.184.215.14".parse().unwrap()], 80)));
        assert_eq!(parse(&r, AAAA), Some((vec![], 60)));
        // No existe.
        let mut nx = q.clone();
        nx[2] = 0x81;
        nx[3] = 0x83;
        assert_eq!(parse(&nx, A), Some((vec![], 60)));
        // Error del servidor, o respuesta cortada.
        let mut fail = q.clone();
        fail[2] = 0x81;
        fail[3] = 0x82;
        assert_eq!(parse(&fail, A), None);
        assert_eq!(parse(&r[..r.len() - 3], A), None);
    }

    /// Pregunta de verdad a los servidores (necesita internet): `tools/unittest.sh doh -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn servidores_reales() {
        for p in 0..PROVIDERS.len() {
            let q = query("example.com", A).unwrap();
            let b = ask(p, &q).await.unwrap_or_else(|| panic!("{} no responde", PROVIDERS[p].name));
            let (ips, _) = parse(&b, A).unwrap();
            assert!(!ips.is_empty(), "{}", PROVIDERS[p].name);
        }
        let ips = resolve("www.wikipedia.org").await.unwrap();
        assert!(ips.iter().any(|i| i.is_ipv4()) && ips.iter().any(|i| i.is_ipv6()), "{ips:?}");
        assert_eq!(resolve("no-existe-sombra-1234.example").await, Some(vec![]));
        // La segunda vez sale de la memoria y reutiliza conexiones.
        let t = std::time::Instant::now();
        resolve("www.wikipedia.org").await.unwrap();
        assert!(t.elapsed() < Duration::from_millis(5));
    }

    #[tokio::test]
    async fn http_con_trozos() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = b.read(&mut buf).await;
            b.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").await.unwrap();
        });
        assert_eq!(exchange(&mut a, "x", b"q").await, Some((b"abcde".to_vec(), true)));
        let (mut a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = b.read(&mut buf).await;
            b.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nwxyz").await.unwrap();
        });
        assert_eq!(exchange(&mut a, "x", b"q").await, Some((b"wxyz".to_vec(), false)));
    }
}
