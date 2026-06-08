//! Tauri backend for Firma CR — the all-in-one GAUDI + Firmador replacement.
//!
//! On launch it embeds the `firma-cr-agent` `/dyn` web-signing server (GAUDI's
//! browser-bridge role) on `127.0.0.1:41231`, and exposes two GUI commands:
//!
//!   * `card_info` — token + signing-certificate info (no PIN).
//!   * `sign_pdf`  — PAdES-B-B sign a PDF with the card.
//!
//! The agent and both commands share ONE card session (`firma_cr_agent`
//! `AppState` behind `Arc<Mutex<…>>`), because crfirma's `C_Initialize` is a
//! process-global singleton — there must be exactly one `CardClient` per
//! process. The card is reached through the system PKCS#11 module
//! (`libfirma_cr_pkcs11.so`) via `firma-cr-pades`; no PKCS#11 shim.

use std::sync::{Arc, Mutex};

use firma_cr_agent::http::{AppState, Shared};
use tauri::State;

/// Report token + signing-certificate details. No PIN required — the "is the
/// card readable?" probe the UI runs first. Uses the one shared card session
/// (the same one the embedded /dyn agent uses).
#[tauri::command]
fn card_info(state: State<Shared>) -> Result<String, String> {
    let mut g = state.lock().map_err(|_| "card state poisoned".to_string())?;
    let card = g.ensure_card()?;
    card.info().map_err(|e| e.to_string())
}

/// Sign `input_path` (a PDF) into `output_path` with a PAdES-B-B signature.
///
/// `method` selects the signer: `"pkcs11"` uses the card via the module;
/// `"pkcs12"` is accepted by the UI but **not yet implemented** in the
/// backend — `firma-cr-pades` has no PKCS#12 reader, so we return a clear
/// error rather than pretend. `password` is the card PIN (or, once wired,
/// the .p12 password). `reason`/`location` are optional signature metadata.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn sign_pdf(
    state: State<Shared>,
    method: String,
    pkcs12_path: Option<String>,
    input_path: String,
    output_path: String,
    password: String,
    reason: Option<String>,
    location: Option<String>,
) -> Result<String, String> {
    if method == "pkcs12" || pkcs12_path.is_some() {
        return Err(
            "PKCS#12 signing is not implemented yet: firma-cr-pades has no .p12 \
             backend (only the card/PKCS#11 path and a test-only PEM/DER signer). \
             Use the Smart card (PKCS#11) method, or wire a p12 signer first."
                .to_string(),
        );
    }

    let input = std::fs::read(&input_path).map_err(|e| format!("read input PDF: {e}"))?;

    // PAdES-B-B sign over the one shared card session (same one the embedded
    // /dyn agent uses). PIN is used transiently for login and never stored.
    let signed = {
        let mut g = state.lock().map_err(|_| "card state poisoned".to_string())?;
        let card = g.ensure_card()?;
        card.login(&password).map_err(|e| e.to_string())?;
        card.sign_pdf(
            &input,
            reason.as_deref().filter(|s| !s.is_empty()),
            location.as_deref().filter(|s| !s.is_empty()),
        )
        .map_err(|e| e.to_string())?
    };

    std::fs::write(&output_path, &signed).map_err(|e| format!("write signed PDF: {e}"))?;

    Ok(format!(
        "Signed: {} ({} B) → {} ({} B).\nVerify with:  pdfsig \"{}\"",
        input_path,
        input.len(),
        output_path,
        signed.len(),
        output_path,
    ))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // ONE shared card session for the whole process: the embedded /dyn agent
    // AND the GUI commands use it. crfirma's C_Initialize is a process-global
    // singleton, so there must be exactly one CardClient per process.
    let module = firma_cr_agent::token::default_module_path();
    eprintln!("firma-cr: crfirma module = {}", module.display());
    let state: Shared = Arc::new(Mutex::new(AppState::new(module)));
    let agent_state = state.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(move |app| {
            // System-tray presence (GAUDI-style background agent).
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::TrayIconBuilder;
            use tauri::Manager;
            let show = MenuItem::with_id(app, "show", "Abrir Firma CR", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::with_id("firma-cr")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Firma CR — agente en http://127.0.0.1:41231")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            // Embed the firma-cr-agent /dyn server (GAUDI's web-bridge role) on
            // 127.0.0.1:41231, sharing the same card session as the GUI commands.
            tauri::async_runtime::spawn(async move {
                eprintln!("firma-cr: /dyn agent on http://127.0.0.1:41231");
                if let Err(e) = firma_cr_agent::http::serve_with_state(agent_state).await {
                    eprintln!("firma-cr: agent server error: {e}");
                }
            });
            Ok(())
        })
        // Closing the window hides to tray; the agent keeps serving.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![card_info, sign_pdf])
        .run(tauri::generate_context!())
        .expect("error while running Firma CR tauri application");
}
