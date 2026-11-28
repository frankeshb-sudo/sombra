// Sombra - descargas: progreso, tiempo que queda y carpeta de cada archivo.
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.
//
// Windows (WebView2) y Linux (WebKitGTK) avisan aquí de cada descarga (ver tabs.rs). La lista
// solo vive en memoria: se pierde al cerrar Sombra y nunca se guarda en el disco.

use crate::state::Shared;
use serde::Serialize;
use std::path::Path;
use std::time::Instant;

const MAX: usize = 30;

#[derive(Clone, Serialize)]
pub struct Download {
    pub id: u32,
    /// Nombre del archivo.
    pub name: String,
    /// Carpeta donde se guarda.
    pub folder: String,
    pub received: u64,
    /// 0 si la web no dice cuánto ocupa.
    pub total: u64,
    /// "progress" | "done" | "failed" | "cancelled"
    pub state: &'static str,
    pub private: bool,
    /// Segundos que quedan (si se sabe).
    pub eta: Option<u64>,
    #[serde(skip)]
    pub path: String,
    #[serde(skip)]
    sample: Option<(Instant, u64)>,
    #[serde(skip)]
    speed: f64,
    #[serde(skip)]
    emitted: Option<Instant>,
}

fn split(path: &str) -> (String, String) {
    let p = Path::new(path);
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let folder = p.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    (name, folder)
}

fn emit(sh: &Shared, list: &[Download]) {
    sh.emit("downloads", list.to_vec());
}

/// Empieza una descarga. Devuelve su número.
pub fn start(sh: &Shared, private: bool, path: &str, total: u64) -> u32 {
    let mut l = sh.downloads.lock();
    let id = l.iter().map(|d| d.id).max().unwrap_or(0) + 1;
    let (name, folder) = split(path);
    l.push(Download {
        id,
        name,
        folder,
        received: 0,
        total,
        state: "progress",
        private,
        eta: None,
        path: path.to_string(),
        sample: None,
        speed: 0.0,
        emitted: None,
    });
    // Las terminadas más antiguas salen de la lista; las que están en marcha, nunca.
    while l.len() > MAX {
        match l.iter().position(|d| d.state != "progress") {
            Some(i) => {
                l.remove(i);
            }
            None => break,
        }
    }
    emit(sh, &l);
    id
}

/// Ruta definitiva (cuando el sistema la decide o la cambia).
pub fn set_path(sh: &Shared, id: u32, path: &str) {
    if path.is_empty() {
        return;
    }
    let mut l = sh.downloads.lock();
    if let Some(d) = l.iter_mut().find(|d| d.id == id) {
        d.path = path.to_string();
        (d.name, d.folder) = split(path);
    }
    emit(sh, &l);
}

/// Bytes recibidos. Calcula la velocidad (media suave) y el tiempo que queda; avisa a la
/// interfaz como mucho 4 veces por segundo.
pub fn progress(sh: &Shared, id: u32, received: u64, total: u64) {
    let mut l = sh.downloads.lock();
    let Some(d) = l.iter_mut().find(|d| d.id == id && d.state == "progress") else { return };
    let now = Instant::now();
    d.received = received;
    if total > 0 {
        d.total = total;
    }
    match d.sample {
        Some((t, b)) => {
            let dt = now.duration_since(t).as_secs_f64();
            if dt >= 0.5 {
                let s = received.saturating_sub(b) as f64 / dt;
                d.speed = if d.speed == 0.0 { s } else { d.speed * 0.7 + s * 0.3 };
                d.sample = Some((now, received));
            }
        }
        None => d.sample = Some((now, received)),
    }
    d.eta = (d.total > d.received && d.speed > 1.0).then(|| ((d.total - d.received) as f64 / d.speed).ceil() as u64);
    if d.emitted.is_some_and(|t| now.duration_since(t).as_millis() < 250) {
        return;
    }
    d.emitted = Some(now);
    emit(sh, &l);
}

/// Fin de una descarga: "done", "failed" o "cancelled".
pub fn finish(sh: &Shared, id: u32, state: &'static str) {
    let mut l = sh.downloads.lock();
    // Solo una vez (en Linux, tras un fallo o una cancelación llega también "finished").
    if let Some(d) = l.iter_mut().find(|d| d.id == id && d.state == "progress") {
        d.state = state;
        d.eta = None;
        if state == "done" && d.total == 0 {
            d.total = d.received;
        }
    }
    emit(sh, &l);
}

/// Quita de la lista las descargas terminadas (todas, o solo `id`).
pub fn dismiss(sh: &Shared, id: Option<u32>) {
    let mut l = sh.downloads.lock();
    l.retain(|d| d.state == "progress" || id.is_some_and(|i| i != d.id));
    emit(sh, &l);
}

/// Carpeta de descargas del sistema (la crea si no existe).
#[cfg_attr(windows, allow(dead_code))] // En Windows lo decide WebView2.
pub fn folder() -> std::path::PathBuf {
    let d = dirs::download_dir().unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join("Downloads"));
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Ruta libre para `name` en `dir`: "informe.pdf", "informe (1).pdf", "informe (2).pdf"...
/// El nombre que propone la web se limpia: nada de carpetas ni nombres ocultos.
#[cfg_attr(windows, allow(dead_code))] // En Windows lo decide WebView2.
pub fn free_path(dir: &Path, name: &str) -> std::path::PathBuf {
    let clean: String = name.chars().map(|c| if matches!(c, '/' | '\\' | ':') || c.is_control() { '_' } else { c }).collect();
    let clean = clean.trim().trim_start_matches('.').to_string();
    let clean = if clean.is_empty() { "descarga".to_string() } else { clean };
    let p = Path::new(&clean);
    let (stem, ext) = (
        p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| clean.clone()),
        p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default(),
    );
    let mut out = dir.join(&clean);
    let mut n = 1;
    while out.exists() && n < 1000 {
        out = dir.join(format!("{stem} ({n}){ext}"));
        n += 1;
    }
    out
}

/// Ruta del archivo de una descarga (para mostrarlo en su carpeta).
pub fn path_of(sh: &Shared, id: u32) -> Option<String> {
    sh.downloads.lock().iter().find(|d| d.id == id).map(|d| d.path.clone())
}

/// Abre la carpeta de la descarga con el archivo marcado (si ya existe).
pub fn reveal(path: &str) -> std::io::Result<()> {
    let p = Path::new(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = std::process::Command::new("explorer.exe");
        if p.is_file() {
            // explorer necesita "/select,<ruta>" en un solo argumento, con la ruta entre comillas.
            c.raw_arg(format!("/select,\"{}\"", path.replace('"', "")));
        } else if let Some(d) = p.parent() {
            c.arg(d);
        }
        c.creation_flags(CREATE_NO_WINDOW).spawn().map(|_| ())
    }
    #[cfg(not(windows))]
    {
        let dir = if p.is_dir() { p } else { p.parent().unwrap_or(p) };
        std::process::Command::new("xdg-open").arg(dir).spawn().map(|_| ())
    }
}

/// Descargas en marcha del sistema (WebView2 / WebKitGTK), para poder cancelarlas. Solo se
/// tocan desde el hilo principal (son objetos del sistema que no se pueden pasar entre hilos).
#[cfg(windows)]
pub type Native = webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2DownloadOperation;
#[cfg(not(windows))]
pub type Native = webkit2gtk::Download;

thread_local! {
    static NATIVE: std::cell::RefCell<std::collections::HashMap<u32, Native>> = Default::default();
}

pub fn keep_native(id: u32, n: Native) {
    NATIVE.with(|m| m.borrow_mut().insert(id, n));
}

pub fn drop_native(id: u32) {
    NATIVE.with(|m| m.borrow_mut().remove(&id));
}

/// Cancela una descarga en marcha (hay que llamarla en el hilo principal).
pub fn cancel_native(id: u32) {
    let n = NATIVE.with(|m| m.borrow_mut().remove(&id));
    if let Some(n) = n {
        #[cfg(windows)]
        unsafe {
            let _ = n.Cancel();
        }
        #[cfg(not(windows))]
        {
            use webkit2gtk::DownloadExt;
            n.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn ruta_libre() {
        let dir = std::env::temp_dir().join(format!("sombra-dl-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("a.txt"));
        assert_eq!(super::free_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), "x").unwrap();
        assert_eq!(super::free_path(&dir, "a.txt"), dir.join("a (1).txt"));
        assert_eq!(super::free_path(&dir, "../../etc/passwd"), dir.join("_.._etc_passwd"));
        assert_eq!(super::free_path(&dir, ".bashrc"), dir.join("bashrc"));
        assert_eq!(super::free_path(&dir, "  "), dir.join("descarga"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nombre_y_carpeta() {
        let (n, f) = split("/home/ana/Descargas/informe final.pdf");
        assert_eq!((n.as_str(), f.as_str()), ("informe final.pdf", "/home/ana/Descargas"));
    }
}
