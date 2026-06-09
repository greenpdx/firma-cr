//! firma-cr-agent binary — runs the local `/dyn` HTTP server (the Pi-native
//! GAUDI replacement). The crfirma PKCS#11 module path comes from
//! `CRFIRMA_MODULE` or the default (see `token::default_module_path`).

use firma_cr_core::agent::token::default_module_path;

#[tokio::main]
async fn main() {
    let module = default_module_path();
    eprintln!(
        "firma-cr-agent: /dyn server on http://127.0.0.1:41231  (crfirma module: {})",
        module.display()
    );
    if let Err(e) = firma_cr_core::agent::http::serve(module).await {
        eprintln!("firma-cr-agent: server error: {e}");
        std::process::exit(1);
    }
}
