// SPDX-License-Identifier: GPL-3.0-or-later
//! Fuzz the detached-CMS (CAdES/`.p7s`) verifier's parser.
//!
//! The `p7s` bytes are fully attacker-controlled (they arrive alongside a document
//! to verify). Verification must always terminate with a clean `Err` or a verdict
//! of `ok == false` — never a panic, unbounded allocation, or hang. A fixed
//! bundled trust root is enough to drive every parse/validation branch.
#![no_main]

use std::sync::OnceLock;

use firma_cr_core::cert::SignerCert;
use firma_cr_core::verify::cms;
use firma_cr_core::verify::VerifyOptions;
use libfuzzer_sys::fuzz_target;

fn trust_root() -> &'static SignerCert {
    static ROOT: OnceLock<SignerCert> = OnceLock::new();
    ROOT.get_or_init(|| {
        // Reuse the workspace test CA root; we only need a well-formed anchor so
        // the verifier reaches its parse/chain/attribute logic.
        SignerCert::from_pem_str(include_str!(
            "../../crates/firma-cr-core/tests/test_ca/out/test-root.crt"
        ))
        .expect("bundled test root parses")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = cms::verify_detached(
        data,
        b"firma-cr fuzz content",
        trust_root(),
        VerifyOptions::default(),
    );
});
