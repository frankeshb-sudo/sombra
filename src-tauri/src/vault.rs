// Sombra - bóveda de contraseñas cifrada.
//
// Cómo funciona:
//  - Una clave aleatoria de 256 bits (la "clave de datos") cifra las contraseñas
//    con XChaCha20-Poly1305.
//  - Esa clave se guarda dos veces, cifrada con:
//      1) la contraseña maestra (Argon2id), y
//      2) la frase de recuperación de 12 palabras (Argon2id).
//    Así, con la frase se puede poner una contraseña maestra nueva sin perder nada.
//  - En el disco solo hay datos cifrados y la pista (que el usuario elige).
//  - Nada sale del equipo: no hay nube ni sincronización.
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

use crate::state::{now, write_json};

// Argon2id: 32 MiB y 3 pasadas. Medio segundo en un portátil viejo: lento para
// quien intente adivinar la contraseña, aceptable para ti.
const ARGON_M_KIB: u32 = 32 * 1024;
const ARGON_T: u32 = 3;
const MIN_MASTER: usize = 8;
const MAX_PENDING: usize = 5;
const PENDING_TTL: u64 = 300;

type Key = Zeroizing<[u8; 32]>;

#[derive(Serialize, Deserialize, Clone)]
struct Kdf {
    m: u32,
    t: u32,
    p: u32,
    salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Wrapped {
    kdf: Kdf,
    nonce: String,
    key: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct VaultFile {
    v: u32,
    hint: String,
    /// Clave de datos cifrada con la contraseña maestra.
    pw: Wrapped,
    /// Clave de datos cifrada con la frase de recuperación.
    rc: Wrapped,
    nonce: String,
    data: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Entry {
    id: u64,
    host: String,
    user: String,
    pass: String,
    created: u64,
    updated: u64,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.pass.zeroize();
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Data {
    entries: Vec<Entry>,
    /// Webs donde el usuario ha dicho "Nunca".
    never: Vec<String>,
    next: u64,
}

struct Capture {
    host: String,
    user: String,
    pass: Zeroizing<String>,
    time: u64,
}

#[derive(Default)]
struct Inner {
    file: Option<VaultFile>,
    key: Option<Key>,
    data: Option<Data>,
    last_use: u64,
    pending: HashMap<u64, Capture>,
    next_cap: u64,
}

pub struct Vault {
    path: PathBuf,
    inner: Mutex<Inner>,
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn derive(secret: &[u8], k: &Kdf) -> anyhow::Result<Key> {
    let salt = hex::decode(&k.salt)?;
    let params = Params::new(k.m, k.t, k.p, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, &salt, &mut out[..])
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(out)
}

fn new_kdf() -> Kdf {
    Kdf { m: ARGON_M_KIB, t: ARGON_T, p: 1, salt: hex::encode(rand_bytes::<16>()) }
}

fn seal(key: &[u8; 32], plain: &[u8]) -> (String, String) {
    let nonce = rand_bytes::<24>();
    let ct = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key)).encrypt(XNonce::from_slice(&nonce), plain).expect("cifrado");
    (hex::encode(nonce), hex::encode(ct))
}

fn open(key: &[u8; 32], nonce: &str, ct: &str) -> Option<Zeroizing<Vec<u8>>> {
    let n = hex::decode(nonce).ok()?;
    if n.len() != 24 {
        return None;
    }
    let c = hex::decode(ct).ok()?;
    XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key)).decrypt(XNonce::from_slice(&n), c.as_slice()).ok().map(Zeroizing::new)
}

fn wrap(secret: &[u8], dek: &[u8; 32]) -> anyhow::Result<Wrapped> {
    let kdf = new_kdf();
    let kek = derive(secret, &kdf)?;
    let (nonce, key) = seal(&kek, dek);
    Ok(Wrapped { kdf, nonce, key })
}

fn unwrap(secret: &[u8], w: &Wrapped) -> Option<Key> {
    let kek = derive(secret, &w.kdf).ok()?;
    let raw = open(&kek, &w.nonce, &w.key)?;
    if raw.len() != 32 {
        return None;
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&raw);
    Some(k)
}

fn strip_accents(s: &str) -> String {
    s.chars()
        // Quita también las tildes "sueltas" (Unicode descompuesto).
        .filter(|c| !('\u{300}'..='\u{36f}').contains(c))
        .map(|c| match c {
            'á' | 'à' | 'ä' | 'â' => 'a',
            'é' | 'è' | 'ë' | 'ê' => 'e',
            'í' | 'ì' | 'ï' | 'î' => 'i',
            'ó' | 'ò' | 'ö' | 'ô' => 'o',
            'ú' | 'ù' | 'ü' | 'û' => 'u',
            'ñ' => 'n',
            'ç' => 'c',
            c => c,
        })
        .collect()
}

/// Lee la frase aunque se escriba sin tildes, con mayúsculas o con espacios de más.
fn parse_phrase(phrase: &str) -> Option<Zeroizing<Vec<u8>>> {
    let words: Vec<String> = phrase.split_whitespace().map(|w| strip_accents(&w.to_lowercase())).collect();
    if words.len() != 12 {
        return None;
    }
    for lang in [Language::Spanish, Language::English] {
        let list = lang.word_list();
        let canon: Option<Vec<&str>> =
            words.iter().map(|w| list.iter().find(|x| strip_accents(x) == *w).copied()).collect();
        if let Some(c) = canon {
            if let Ok(m) = Mnemonic::parse_in_normalized(lang, &c.join(" ")) {
                return Some(Zeroizing::new(m.to_entropy()));
            }
        }
    }
    None
}

fn norm_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase().trim_start_matches("www.").to_string()
}

/// Misma web: mismo dominio registrable según la lista oficial de sufijos públicos.
/// login.ejemplo.com ↔ ejemplo.com sí; ana.github.io ↔ luis.github.io NO (son webs de
/// personas distintas sobre un dominio compartido).
fn same_site(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (psl::domain_str(a), psl::domain_str(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

impl Vault {
    pub fn new(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("vault.json");
        let file = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<VaultFile>(&b).ok());
        Self { path, inner: Mutex::new(Inner { file, next_cap: 1, ..Default::default() }) }
    }

    fn persist(&self, g: &mut Inner) {
        let (Some(key), Some(data), Some(file)) = (g.key.as_ref(), g.data.as_ref(), g.file.as_mut()) else { return };
        let plain = Zeroizing::new(serde_json::to_vec(data).unwrap_or_default());
        let (nonce, ct) = seal(key, &plain);
        file.nonce = nonce;
        file.data = ct;
        write_json(&self.path, file);
    }

    pub fn status(&self) -> Value {
        let g = self.inner.lock();
        json!({
            "exists": g.file.is_some(),
            "unlocked": g.key.is_some(),
            "hint": g.file.as_ref().map(|f| f.hint.clone()).unwrap_or_default(),
            "count": g.data.as_ref().map(|d| d.entries.len()).unwrap_or(0),
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().key.is_some()
    }

    /// Crea la bóveda y devuelve la frase de recuperación (solo se muestra esta vez).
    pub fn create(&self, password: &str, hint: &str, lang: &str) -> Result<String, String> {
        if self.inner.lock().file.is_some() {
            return Err("vaultExists".into());
        }
        if password.chars().count() < MIN_MASTER {
            return Err("vaultShort".into());
        }
        let dek = Zeroizing::new(rand_bytes::<32>());
        let entropy = Zeroizing::new(rand_bytes::<16>());
        let language = if matches!(lang, "es" | "ca") { Language::Spanish } else { Language::English };
        let phrase = Mnemonic::from_entropy_in(language, &entropy[..]).map_err(|e| e.to_string())?.to_string();
        let pw = wrap(password.as_bytes(), &dek).map_err(|e| e.to_string())?;
        let rc = wrap(&entropy[..], &dek).map_err(|e| e.to_string())?;
        let mut g = self.inner.lock();
        if g.file.is_some() {
            return Err("vaultExists".into());
        }
        g.file = Some(VaultFile { v: 1, hint: hint.chars().take(100).collect(), pw, rc, nonce: String::new(), data: String::new() });
        g.key = Some(dek);
        g.data = Some(Data { next: 1, ..Default::default() });
        g.last_use = now();
        self.persist(&mut g);
        Ok(phrase)
    }

    fn load(&self, g: &mut Inner, key: Key) -> Result<(), String> {
        let file = g.file.as_ref().ok_or("vaultNone")?;
        let raw = open(&key, &file.nonce, &file.data).ok_or("vaultWrong")?;
        let data: Data = serde_json::from_slice(&raw).map_err(|_| "vaultWrong")?;
        g.key = Some(key);
        g.data = Some(data);
        g.last_use = now();
        Ok(())
    }

    pub fn unlock(&self, password: &str) -> Result<(), String> {
        let w = self.inner.lock().file.as_ref().map(|f| f.pw.clone()).ok_or("vaultNone")?;
        let key = unwrap(password.as_bytes(), &w).ok_or("vaultWrong")?;
        let mut g = self.inner.lock();
        self.load(&mut g, key)
    }

    /// Recupera con la frase de 12 palabras y pone una contraseña maestra nueva.
    pub fn recover(&self, phrase: &str, new_password: &str, hint: &str) -> Result<(), String> {
        if new_password.chars().count() < MIN_MASTER {
            return Err("vaultShort".into());
        }
        let entropy = parse_phrase(phrase).ok_or("vaultPhrase")?;
        let w = self.inner.lock().file.as_ref().map(|f| f.rc.clone()).ok_or("vaultNone")?;
        let key = unwrap(&entropy, &w).ok_or("vaultPhrase")?;
        let pw = wrap(new_password.as_bytes(), &key).map_err(|e| e.to_string())?;
        let mut g = self.inner.lock();
        self.load(&mut g, key)?;
        if let Some(f) = g.file.as_mut() {
            f.pw = pw;
            f.hint = hint.chars().take(100).collect();
        }
        self.persist(&mut g);
        Ok(())
    }

    pub fn lock(&self) {
        let mut g = self.inner.lock();
        g.key = None; // Zeroizing borra la clave de la memoria
        g.data = None; // Entry::drop borra cada contraseña
    }

    /// Bloqueo automático tras `mins` minutos sin usar. Devuelve true si se ha bloqueado.
    pub fn auto_lock(&self, mins: u32) -> bool {
        let mut g = self.inner.lock();
        let t = now();
        g.pending.retain(|_, c| t.saturating_sub(c.time) < PENDING_TTL);
        let expired = mins > 0 && g.key.is_some() && t.saturating_sub(g.last_use) >= mins as u64 * 60;
        if expired {
            g.key = None;
            g.data = None;
        }
        expired
    }

    fn with_data<R>(&self, f: impl FnOnce(&mut Data) -> R) -> Result<R, String> {
        let mut g = self.inner.lock();
        g.last_use = now();
        let d = g.data.as_mut().ok_or("vaultLocked")?;
        Ok(f(d))
    }

    pub fn list(&self, query: &str) -> Result<Value, String> {
        let q = query.to_lowercase();
        self.with_data(|d| {
            let mut items: Vec<Value> = d
                .entries
                .iter()
                .filter(|e| q.is_empty() || e.host.contains(&q) || e.user.to_lowercase().contains(&q))
                .map(|e| json!({ "id": e.id, "host": e.host, "user": e.user, "updated": e.updated }))
                .collect();
            items.sort_by(|a, b| a["host"].as_str().cmp(&b["host"].as_str()));
            json!({ "items": items, "never": d.never })
        })
    }

    pub fn reveal(&self, id: u64) -> Result<String, String> {
        self.with_data(|d| d.entries.iter().find(|e| e.id == id).map(|e| e.pass.clone()))?.ok_or_else(|| "vaultNoMatch".into())
    }

    pub fn delete(&self, id: u64) -> Result<(), String> {
        self.with_data(|d| d.entries.retain(|e| e.id != id))?;
        self.persist(&mut self.inner.lock());
        Ok(())
    }

    pub fn remove_never(&self, host: &str) -> Result<(), String> {
        self.with_data(|d| d.never.retain(|h| h != host))?;
        self.persist(&mut self.inner.lock());
        Ok(())
    }

    /// Usuarios guardados para esta web (sin contraseñas).
    pub fn matches(&self, host: &str) -> Result<Vec<Value>, String> {
        let h = norm_host(host);
        self.with_data(|d| {
            d.entries.iter().filter(|e| same_site(&e.host, &h)).map(|e| json!({ "id": e.id, "user": e.user, "host": e.host })).collect()
        })
    }

    /// Usuario y contraseña para rellenar, solo si la entrada es de esta misma web.
    pub fn for_fill(&self, id: u64, host: &str) -> Result<(String, Zeroizing<String>), String> {
        let h = norm_host(host);
        self.with_data(|d| d.entries.iter().find(|e| e.id == id && same_site(&e.host, &h)).map(|e| (e.user.clone(), Zeroizing::new(e.pass.clone()))))?
            .ok_or_else(|| "vaultNoMatch".into())
    }

    fn save_entry(d: &mut Data, host: &str, user: &str, pass: &str) {
        let t = now();
        if let Some(e) = d.entries.iter_mut().find(|e| e.host == host && e.user == user) {
            e.pass.zeroize();
            e.pass = pass.to_string();
            e.updated = t;
        } else {
            let id = d.next.max(1);
            d.next = id + 1;
            d.entries.push(Entry { id, host: host.into(), user: user.into(), pass: pass.into(), created: t, updated: t });
        }
    }

    /// Una web ha enviado un formulario con contraseña. Devuelve la pregunta para
    /// el usuario, o None si no hay que preguntar (ya guardada o "Nunca").
    pub fn capture(&self, host: &str, user: &str, pass: Zeroizing<String>) -> Option<Value> {
        let host = norm_host(host);
        let mut g = self.inner.lock();
        let mut update = false;
        if let Some(d) = g.data.as_ref() {
            if d.never.iter().any(|n| same_site(n, &host)) {
                return None;
            }
            if let Some(e) = d.entries.iter().find(|e| e.host == host && e.user == user) {
                if e.pass == *pass {
                    return None;
                }
                update = true;
            }
        }
        // La misma pregunta no se repite.
        if g.pending.values().any(|c| c.host == host && c.user == user && *c.pass == *pass) {
            return None;
        }
        // Una sola pregunta por web: la nueva sustituye a la anterior (si te equivocas al
        // escribir y repites, o si una web intenta llenar la pantalla de avisos).
        g.pending.retain(|_, c| c.host != host);
        if g.pending.len() >= MAX_PENDING {
            let oldest = g.pending.iter().min_by_key(|(_, c)| c.time).map(|(k, _)| *k);
            if let Some(k) = oldest {
                g.pending.remove(&k);
            }
        }
        let id = g.next_cap;
        g.next_cap += 1;
        g.pending.insert(id, Capture { host: host.clone(), user: user.to_string(), pass, time: now() });
        Some(json!({ "id": id, "host": host, "user": user, "update": update, "exists": g.file.is_some(), "unlocked": g.key.is_some() }))
    }

    /// Respuesta a "¿Guardar la contraseña?": save | never | no.
    pub fn answer(&self, id: u64, action: &str) -> Result<(), String> {
        let mut g = self.inner.lock();
        if action == "no" {
            g.pending.remove(&id);
            return Ok(());
        }
        if g.data.is_none() {
            return Err("vaultLocked".into());
        }
        let c = g.pending.remove(&id).ok_or("vaultNoMatch")?;
        g.last_use = now();
        let d = g.data.as_mut().ok_or("vaultLocked")?;
        match action {
            "save" => Self::save_entry(d, &c.host, &c.user, &c.pass),
            "never" => {
                if !d.never.contains(&c.host) {
                    d.never.push(c.host.clone());
                }
            }
            _ => {}
        }
        self.persist(&mut g);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_recover() {
        let dir = std::env::temp_dir().join(format!("sombra-vault-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("vault.json"));
        let v = Vault::new(&dir);
        assert_eq!(v.create("corta", "", "es"), Err("vaultShort".into()));
        let phrase = v.create("contraseña-larga", "mi pista", "es").unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
        let cap = v.capture("www.ejemplo.com", "ana", Zeroizing::new("secreta1".into())).unwrap();
        v.answer(cap["id"].as_u64().unwrap(), "save").unwrap();
        // La misma contraseña no vuelve a preguntar.
        assert!(v.capture("ejemplo.com", "ana", Zeroizing::new("secreta1".into())).is_none());
        v.lock();
        assert!(v.list("").is_err());

        // Desde el disco, con la contraseña.
        let v2 = Vault::new(&dir);
        assert_eq!(v2.unlock("mala-contraseña"), Err("vaultWrong".into()));
        v2.unlock("contraseña-larga").unwrap();
        let m = v2.matches("login.ejemplo.com").unwrap();
        assert_eq!(m.len(), 1);
        assert!(v2.matches("ejemplo.com.malo.net").unwrap().is_empty());
        assert!(same_site("login.ejemplo.com", "ejemplo.com"));
        assert!(!same_site("ana.github.io", "luis.github.io"));
        assert!(!same_site("ejemplo.co.uk", "otro.co.uk"));
        let (u, p) = v2.for_fill(m[0]["id"].as_u64().unwrap(), "ejemplo.com").unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("ana", "secreta1"));
        v2.lock();

        // Recuperación sin tildes ni mayúsculas.
        let typed = strip_accents(&phrase.to_uppercase().to_lowercase());
        let v3 = Vault::new(&dir);
        assert_eq!(v3.recover("uno dos tres", "nueva-maestra", ""), Err("vaultPhrase".into()));
        v3.recover(&typed, "nueva-maestra", "otra").unwrap();
        v3.lock();
        let v4 = Vault::new(&dir);
        v4.unlock("nueva-maestra").unwrap();
        assert_eq!(v4.list("").unwrap()["items"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
