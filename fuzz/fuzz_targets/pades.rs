// SPDX-License-Identifier: GPL-3.0-or-later
//! Fuzz the PAdES PDF verifier (`verify::pades::verify_pdf`).
//!
//! Targets the `/ByteRange` + `/Contents` structural parser that the C1 fix
//! hardened: a hostile PDF must be rejected cleanly, never panic or overflow.
//! The whole `pdf` slice is attacker-controlled; a fixed bundled trust root lets
//! the parser run to its coverage/arithmetic checks.
#![no_main]

use std::sync::OnceLock;

use firma_cr_core::cert::SignerCert;
use firma_cr_core::verify::pades;
use firma_cr_core::verify::VerifyOptions;
use libfuzzer_sys::fuzz_target;

fn trust_root() -> &'static SignerCert {
    static ROOT: OnceLock<SignerCert> = OnceLock::new();
    ROOT.get_or_init(|| {
        SignerCert::from_pem_str(include_str!(
            "../../crates/firma-cr-core/tests/test_ca/out/test-root.crt"
        ))
        .expect("bundled test root parses")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = pades::verify_pdf(data, trust_root(), VerifyOptions::default());
});
