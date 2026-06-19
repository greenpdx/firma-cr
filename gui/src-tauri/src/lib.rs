// SPDX-License-Identifier: GPL-3.0-or-later
//! Tauri backend for Firma CR — the all-in-one GAUDI + Firmador replacement.
//!
//! On launch it embeds the firma-cr-core `agent` `/dyn` web-signing server (GAUDI's
//! browser-bridge role) on `127.0.0.1:41231`, and exposes two GUI commands:
//!
//!   * `card_info` — token + signing-certificate info (no PIN).
//!   * `sign_pdf`  — PAdES-B-B sign a PDF with the card.
//!
//! The agent and both commands share ONE card session (`firma_cr_core::agent`
//! `AppState` behind `Arc<Mutex<…>>`), because crfirma's `C_Initialize` is a
//! process-global singleton — there must be exactly one `CardClient` per
//! process. The card is reached through the system PKCS#11 module
//! (`libfirma_cr_pkcs11.so`) via `firma-cr-core`; no PKCS#11 shim.

use std::sync::{Arc, Mutex};

use firma_cr_core::agent::http::{AppState, Shared};
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
/// backend — `firma-cr-core` has no PKCS#12 reader, so we return a clear
/// error rather than pretend. `password` is the card PIN (or, once wired,
/// the .p12 password). `reason`/`location` are optional signature metadata.
/// Optional visible-stamp placement from the GUI (PDF points + font + page),
/// mirroring the web flow's `vrect`/`vfont`/`vpage`.
#[derive(serde::Deserialize)]
struct PlacementArg {
    rect: [f32; 4],
    #[serde(rename = "fontSize")]
    font_size: f32,
    page: usize,
}

/// Defense-in-depth validation of the webview-supplied input/output paths before
/// they reach `std::fs`. The native file dialog already constrains interactive
/// selection, but the command is reachable from the webview directly, so we
/// re-check here: the input must be an existing regular `.pdf` file, and the
/// output must name a `.pdf` under an existing directory (not a directory itself).
/// This blocks reading non-regular files (devices/FIFOs) and writing into a
/// non-existent/garbage location if a compromised webview invokes `sign_pdf`.
fn validate_pdf_io(input_path: &str, output_path: &str) -> Result<(), String> {
    let has_pdf_ext = |p: &str| {
        std::path::Path::new(p)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
    };

    if input_path.trim().is_empty() {
        return Err("input path is empty".into());
    }
    if !has_pdf_ext(input_path) {
        return Err("input must be a .pdf file".into());
    }
    let meta = std::fs::metadata(input_path).map_err(|e| format!("input PDF not readable: {e}"))?;
    if !meta.is_file() {
        return Err("input path is not a regular file".into());
    }

    if output_path.trim().is_empty() {
        return Err("output path is empty".into());
    }
    if !has_pdf_ext(output_path) {
        return Err("output must be a .pdf file".into());
    }
    let parent = std::path::Path::new(output_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "output path has no directory".to_string())?;
    if !parent.is_dir() {
        return Err(format!("output directory does not exist: {}", parent.display()));
    }
    if std::path::Path::new(output_path).is_dir() {
        return Err("output path is a directory".into());
    }
    Ok(())
}

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
    placement: Option<PlacementArg>,
    tsa_url: Option<String>,
) -> Result<String, String> {
    if method == "pkcs12" || pkcs12_path.is_some() {
        return Err(
            "PKCS#12 signing is not implemented yet: firma-cr-core has no .p12 \
             backend (only the card/PKCS#11 path and a test-only PEM/DER signer). \
             Use the Smart card (PKCS#11) method, or wire a p12 signer first."
                .to_string(),
        );
    }

    validate_pdf_io(&input_path, &output_path)?;

    let input = std::fs::read(&input_path).map_err(|e| format!("read input PDF: {e}"))?;

    // TSA for a PAdES-T signature timestamp: explicit arg, else FIRMA_CR_TSA_URL.
    // Absent both, sign PAdES-B-B.
    let tsa = tsa_url
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("FIRMA_CR_TSA_URL").ok())
        .filter(|s| !s.is_empty());

    // Sign over the one shared card session (same one the embedded /dyn agent
    // uses). PIN is used transiently for login and never stored.
    let signed = {
        let mut g = state.lock().map_err(|_| "card state poisoned".to_string())?;
        let card = g.ensure_card()?;
        card.login(&password).map_err(|e| e.to_string())?;
        card.sign_pdf(
            &input,
            reason.as_deref().filter(|s| !s.is_empty()),
            location.as_deref().filter(|s| !s.is_empty()),
            placement.map(|p| firma_cr_core::agent::sign::StampPlacement {
                rect: (p.rect[0], p.rect[1], p.rect[2], p.rect[3]),
                font_size: p.font_size,
                page: p.page,
            }),
            tsa.as_deref(),
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

/// Quit the whole process (the embedded /dyn agent stops with it). Wired to the
/// window's "Salir" button so there is always an in-window way to exit, not only
/// the tray menu (which may be invisible on some desktops).
#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // WebKitGTK on several Linux GPU stacks (Raspberry Pi / VC4, some Mesa and
    // NVIDIA setups) paints the webview as corrupted horizontal scan-lines under
    // its DMABUF-backed renderer — the page itself is fine (it renders correctly
    // in a browser). Disabling the DMABUF renderer fixes it with negligible cost.
    // Must be set before WebKitGTK initializes, i.e. before the Tauri builder
    // creates the window. Linux-only; honor an explicit override if the operator
    // already set the variable. If scan-lines persist on some hardware, also try
    // WEBKIT_DISABLE_COMPOSITING_MODE=1 (heavier — disables GPU compositing).
    #[cfg(target_os = "linux")]
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        // SAFETY: first line of run(), before any thread is spawned or WebKitGTK
        // initializes — no concurrent env access. (env::set_var is unsafe in
        // edition 2024.)
        unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
    }

    // ONE shared card session for the whole process: the embedded /dyn agent
    // AND the GUI commands use it. crfirma's C_Initialize is a process-global
    // singleton, so there must be exactly one CardClient per process.
    let module = firma_cr_core::agent::token::default_module_path();
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

            // Embed the firma-cr-core agent /dyn server (GAUDI's web-bridge role) on
            // 127.0.0.1:41231, sharing the same card session as the GUI commands.
            tauri::async_runtime::spawn(async move {
                eprintln!("firma-cr: /dyn agent on http://127.0.0.1:41231");
                if let Err(e) = firma_cr_core::agent::http::serve_with_state(agent_state).await {
                    eprintln!("firma-cr: agent server error: {e}");
                }
            });
            Ok(())
        })
        // Closing the window quits the whole process (the embedded /dyn agent
        // stops with it). The tray "Salir" item and the in-window "Salir" button
        // both call quit_app for the same effect.
        .invoke_handler(tauri::generate_handler![card_info, sign_pdf, quit_app])
        .run(tauri::generate_context!())
        .expect("error while running Firma CR tauri application");
}
