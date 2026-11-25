// Sombra - Tor integrado (Arti, la implementación en Rust del Proyecto Tor).
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use arti_client::{CountryCode, DataStream, IsolationToken, StreamPrefs, TorClient};
use futures::StreamExt;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tor_rtcompat::PreferredRuntime;

/// Aislamiento por web: cada dominio usa sus propios circuitos de Tor, así dos webs
/// distintas no pueden relacionarse por compartir circuito. `notify` corta las
/// conexiones abiertas de ese dominio cuando se pide un circuito nuevo.
struct HostIso {
    token: IsolationToken,
    notify: Arc<Notify>,
}

#[derive(Clone, Serialize, Default)]
pub struct TorStatus {
    pub ready: bool,
    pub progress: f32,
    pub message: String,
    pub country: Option<String>,
    pub error: Option<String>,
}

pub struct Tor {
    client: RwLock<Option<Arc<TorClient<PreferredRuntime>>>>,
    prefs: RwLock<StreamPrefs>,
    status: RwLock<TorStatus>,
    hosts: Mutex<HashMap<String, HostIso>>,
}

impl Tor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            hosts: Mutex::new(HashMap::new()),
            client: RwLock::new(None),
            prefs: RwLock::new(StreamPrefs::new()),
            status: RwLock::new(TorStatus {
                message: "Conectando con la red Tor...".into(),
                ..Default::default()
            }),
        })
    }

    pub fn status(&self) -> TorStatus {
        self.status.read().clone()
    }

    pub fn is_ready(&self) -> bool {
        self.status.read().ready
    }

    /// Arranca Tor en segundo plano. Hasta que esté listo, no sale ni un byte a internet.
    pub async fn start(self: Arc<Self>, base: PathBuf) {
        let cfg = arti_client::config::TorClientConfigBuilder::from_directories(
            base.join("state"),
            base.join("cache"),
        )
        .build();
        let cfg = match cfg {
            Ok(c) => c,
            Err(e) => {
                self.fail(format!("Configuración de Tor inválida: {e}"));
                return;
            }
        };
        let client = match TorClient::builder().config(cfg).create_unbootstrapped() {
            Ok(c) => c,
            Err(e) => {
                self.fail(format!("No se pudo iniciar Tor: {e}"));
                return;
            }
        };
        // Progreso del arranque para la interfaz.
        let me = self.clone();
        let mut events = client.bootstrap_events();
        tokio::spawn(async move {
            while let Some(ev) = events.next().await {
                let mut s = me.status.write();
                s.progress = ev.as_frac();
                if ev.ready_for_traffic() {
                    s.ready = true;
                    s.message = "Conectado a Tor".into();
                } else {
                    s.message = format!("Conectando con Tor... {:.0}%", ev.as_frac() * 100.0);
                }
            }
        });
        loop {
            match client.bootstrap().await {
                Ok(()) => break,
                Err(e) => {
                    self.status.write().error = Some(format!("{e}"));
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        *self.client.write() = Some(client);
        let mut s = self.status.write();
        s.ready = true;
        s.progress = 1.0;
        s.error = None;
        s.message = "Conectado a Tor".into();
    }

    fn fail(&self, msg: String) {
        let mut s = self.status.write();
        s.error = Some(msg.clone());
        s.message = msg;
    }

    /// Abre una conexión anónima. Si Tor no está listo, espera; nunca usa la conexión directa.
    /// Devuelve también un aviso que se dispara si hay que cortar esta conexión (circuito nuevo).
    pub async fn connect(&self, host: &str, port: u16) -> anyhow::Result<(DataStream, Arc<Notify>)> {
        let mut waited = 0;
        let client = loop {
            if let Some(c) = self.client.read().clone() {
                break c;
            }
            if waited >= 90 {
                anyhow::bail!("Tor todavía no está listo");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            waited += 1;
        };
        let mut prefs = self.prefs.read().clone();
        let (token, notify) = {
            let mut h = self.hosts.lock();
            // Límite de memoria: se olvidan los dominios sin conexiones abiertas.
            if h.len() > 1000 {
                h.retain(|_, v| Arc::strong_count(&v.notify) > 1);
            }
            let e = h.entry(host.to_string()).or_insert_with(|| HostIso { token: IsolationToken::new(), notify: Arc::new(Notify::new()) });
            (e.token, e.notify.clone())
        };
        prefs.set_isolation(token);
        let stream = client.connect_with_prefs((host, port), &prefs).await?;
        Ok((stream, notify))
    }

    /// Circuito nuevo para un dominio: las conexiones abiertas se cortan y las
    /// siguientes salen por otro camino de Tor. Se usa en cada búsqueda.
    pub fn rotate_host(&self, host: &str) {
        let old = self.hosts.lock().insert(host.to_string(), HostIso { token: IsolationToken::new(), notify: Arc::new(Notify::new()) });
        if let Some(o) = old {
            o.notify.notify_waiters();
        }
    }

    /// Elige el país de salida ("DE", "FR"...) o `None` para cualquiera.
    pub fn set_country(&self, code: Option<&str>) -> anyhow::Result<()> {
        let mut p = StreamPrefs::new();
        let norm = match code {
            Some(c) if !c.is_empty() && !c.eq_ignore_ascii_case("any") => {
                let up = c.to_ascii_uppercase();
                let cc = CountryCode::from_str(&up).map_err(|e| anyhow::anyhow!("País no válido: {e}"))?;
                p.exit_country(cc);
                Some(up)
            }
            _ => {
                p.any_exit_country();
                None
            }
        };
        *self.prefs.write() = p;
        self.new_identity();
        self.status.write().country = norm;
        Ok(())
    }

    /// Nueva identidad: circuitos nuevos, sin relación con los anteriores.
    pub fn new_identity(&self) {
        {
            let mut g = self.client.write();
            if let Some(c) = g.as_ref() {
                *g = Some(c.isolated_client());
            }
        }
        // Se cortan todas las conexiones abiertas: lo siguiente ya sale por circuitos nuevos.
        for (_, h) in self.hosts.lock().drain() {
            h.notify.notify_waiters();
        }
    }
}
