fn main() {
    // Cada orden de Sombra necesita permiso explícito (capabilities/):
    //  - la interfaz ("ui") puede usar todas,
    //  - las webs de las pestañas, solo `cred_capture` (avisar de una contraseña enviada).
    const COMMANDS: &[&str] = &[
        "get_state",
        "new_tab",
        "close_tab",
        "activate_tab",
        "navigate",
        "nav_action",
        "set_content_rect",
        "set_country",
        "new_identity",
        "set_blocking",
        "add_bookmark",
        "remove_bookmark",
        "set_control",
        "cut_ai",
        "resolve_approval",
        "get_logs",
        "clear_logs",
        "page_privacy",
        "set_settings",
        "get_history",
        "remove_history",
        "clean",
        "vault_status",
        "vault_create",
        "vault_unlock",
        "vault_recover",
        "vault_lock",
        "vault_list",
        "vault_reveal",
        "vault_delete",
        "vault_never_remove",
        "vault_matches",
        "vault_fill",
        "cred_answer",
        "cred_capture",
    ];
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)))
        .expect("tauri build");
}
