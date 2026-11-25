// Sombra - bloqueador de publicidad y rastreadores (adblock-rust, motor de Brave).
// Copyright (C) 2026 Sombra contributors. Licencia GPL-3.0-or-later.

use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use adblock::Engine;
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockKind {
    Ad,
    Tracker,
}

pub struct Blocker {
    ads: Engine,
    privacy: Engine,
}

fn engine_from(lists: &[&str]) -> Engine {
    let mut set = FilterSet::new(false);
    for l in lists {
        set.add_filter_list(l.to_string(), ParseOptions::default());
    }
    Engine::new_with_filter_set(set)
}

impl Blocker {
    pub fn new() -> Self {
        let ads = engine_from(&[
            include_str!("../filters/easylist.txt"),
            include_str!("../filters/easylistspanish.txt"),
            include_str!("../filters/cookies.txt"),
        ]);
        let privacy = engine_from(&[include_str!("../filters/easyprivacy.txt")]);
        Self { ads, privacy }
    }

    /// Decide si una conexión a `host` debe bloquearse.
    /// El proxy solo ve el nombre del servidor (no la URL completa), así que
    /// se evalúa como petición de terceros a la raíz del dominio.
    pub fn check_host(&self, host: &str) -> Option<BlockKind> {
        let url = format!("https://{host}/");
        let req = Request::new(&url, "https://sombra.invalid/", "other", "GET").ok()?;
        if self.privacy.check_network_request(&req).should_block() {
            return Some(BlockKind::Tracker);
        }
        if self.ads.check_network_request(&req).should_block() {
            return Some(BlockKind::Ad);
        }
        None
    }

    /// Selectores CSS a ocultar en una URL concreta (anuncios incrustados, avisos de cookies...).
    pub fn cosmetic_css(&self, url: &str) -> (String, bool, HashSet<String>) {
        let r = self.ads.url_cosmetic_resources(url);
        let mut sel: Vec<String> = r.hide_selectors.into_iter().collect();
        sel.sort();
        (join_css(&sel), r.generichide, r.exceptions)
    }

    /// Reglas genéricas que dependen de las clases e ids presentes en la página.
    pub fn generic_css(&self, classes: &[String], ids: &[String], exceptions: &HashSet<String>) -> String {
        let sel = self.ads.hidden_class_id_selectors(classes, ids, exceptions);
        join_css(&sel)
    }
}

fn join_css(sel: &[String]) -> String {
    if sel.is_empty() {
        return String::new();
    }
    // Se agrupan en bloques para que un selector inválido no anule todos los demás.
    sel.chunks(200)
        .map(|c| format!("{}{{display:none!important}}", c.join(",")))
        .collect::<Vec<_>>()
        .join("\n")
}
