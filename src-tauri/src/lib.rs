//! Tauri backend for the Firma CR PDF signer (Phase 1).
//!
//! Two commands, both synchronous so the `cryptoki` session never crosses a
//! thread boundary (Tauri runs non-async commands on the main thread):
//!
//!   * `card_info` — open the PKCS#11 module, return token + certificate info.
//!   * `sign_pdf`  — login, read the signing key + cert, embed a PAdES-B-B
//!     signature into a PDF via `firma_cr_pades::pades::sign_pdf`.
//!
//! The native backend reuses the document-signing library directly — no
//! PKCS#11 re-implementation and no WASM. The card is reached through the
//! system PKCS#11 module (our `libfirma_cr_pkcs11.so`), exactly as the CLI
//! does it.

use std::path::Path;
use std::time::SystemTime;

use firma_cr_pades::signer::CardSigner;
use firma_cr_pades::{CardClient, HashAlgo, SignerCert};

/// Default install path of our PKCS#11 module (matches the CLI default and
/// `install.sh`). The UI can override it.
const DEFAULT_MODULE: &str = "/usr/lib/firma-cr/libfirma_cr_pkcs11.so";

fn module_path(module: Option<String>) -> String {
    module
        .filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MODULE.to_string())
}

/// Open the module and report token + signing-certificate details. No PIN
/// required — this is the "is the card readable?" probe the UI runs first.
#[tauri::command]
fn card_info(module: Option<String>, slot: Option<usize>) -> Result<String, String> {
    let module = module_path(module);
    let client = CardClient::open(Path::new(&module), slot).map_err(|e| e.to_string())?;
    let mut out = client.info().map_err(|e| e.to_string())?;

    if let Ok(der) = client.read_certificate() {
        if let Ok(cert) = SignerCert::from_der(der) {
            let (not_before, not_after) = cert.validity_window();
            out.push_str(&format!(
                "\n\nSigning certificate\n  subject: {}\n  issuer:  {}\n  serial:  {}\n  valid:   {} .. {}",
                cert.subject_string(),
                cert.issuer_string(),
                cert.serial_hex(),
                not_before,
                not_after,
            ));
        }
    }
    Ok(out)
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
    method: String,
    module: Option<String>,
    pkcs12_path: Option<String>,
    slot: Option<usize>,
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

    let module = module_path(module);

    let mut client = CardClient::open(Path::new(&module), slot).map_err(|e| e.to_string())?;
    client.login(&password).map_err(|e| e.to_string())?;
    let key = client.read_signing_key().map_err(|e| e.to_string())?;
    let cert = SignerCert::from_der(client.read_certificate().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let signer = CardSigner::new(&client, &key);

    let input = std::fs::read(&input_path).map_err(|e| format!("read input PDF: {e}"))?;

    // Phase 1 = PAdES-B-B: no additional certs, SHA-256, no timestamp (None),
    // no visible appearance, do not re-sign an already-signed PDF.
    let signed = firma_cr_pades::pades::sign_pdf(
        &input,
        &cert,
        &[],
        HashAlgo::Sha256,
        reason.as_deref().filter(|s| !s.is_empty()),
        location.as_deref().filter(|s| !s.is_empty()),
        None,                // contact_info
        SystemTime::now(),   // native clock is fine; the WASM path needs a Clock port
        &signer,
        None,                // timestamp_fn (B-T+ profiles — Phase 2+)
        None,                // visible appearance
        false,               // allow_resign
    )
    .map_err(|e| e.to_string())?;

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
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|_app| {
            // Embed the firma-cr-agent /dyn server (GAUDI's web-bridge role) so
            // this single app is the desktop signer AND the local browser bridge
            // on 127.0.0.1:41231. It touches the card only lazily (on a /dyn
            // request), so it does not clash with the direct card_info/sign_pdf
            // commands at startup. (Next: unify the card session between the two.)
            tauri::async_runtime::spawn(async {
                let module = firma_cr_agent::token::default_module_path();
                eprintln!(
                    "firma-cr: /dyn agent on http://127.0.0.1:41231 (module {})",
                    module.display()
                );
                if let Err(e) = firma_cr_agent::http::serve(module).await {
                    eprintln!("firma-cr: agent server error: {e}");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![card_info, sign_pdf])
        .run(tauri::generate_context!())
        .expect("error while running Firma CR tauri application");
}
