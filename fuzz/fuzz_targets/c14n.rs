// SPDX-License-Identifier: GPL-3.0-or-later
//! Fuzz the Exclusive XML Canonicalization path (`c14n::excl_c14n`).
//!
//! This parser sees fully untrusted XML — it canonicalizes signed-document input
//! during XAdES verification — so it must never panic, overrun, or hang. When it
//! *accepts* an input we additionally assert idempotency (`c14n(c14n(x)) == c14n(x)`),
//! the defining correctness property of a canonical form: a crash there is a real
//! bug even on valid XML.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(canon) = firma_cr_core::c14n::excl_c14n(data) {
        if let Ok(canon2) = firma_cr_core::c14n::excl_c14n(&canon) {
            assert_eq!(canon, canon2, "excl_c14n is not idempotent");
        }
    }
});
