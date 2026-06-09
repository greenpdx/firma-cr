// SPDX-License-Identifier: GPL-3.0-or-later
//! firma-cr-core — ETSI digital signature library + CLI.
//!
//! Three signature families are produced, all driven from the same
//! PKCS#11 module (`libfirma_cr_pkcs11.so`):
//!
//!   * **CAdES** — detached CMS SignedData over arbitrary bytes
//!     (output is a `.p7s` file).
//!   * **PAdES** — CAdES detached signature embedded in a PDF's
//!     `/Contents` field (output is the original PDF with a
//!     signature dictionary appended via incremental update).
//!   * **XAdES** — XMLDSig + ETSI properties, enveloped /
//!     enveloping / detached.
//!
//! Profile depth: B-B (basic), B-T (timestamp), B-LT (long-term,
//! with embedded revocation data), B-LTA (archive timestamp). Each
//! profile is selectable per call.

pub mod c14n;
pub mod cades;
pub mod cert;
pub mod error;
pub mod pades;
pub mod signer;
pub mod revocation;
pub mod tsa;
pub mod xades;
pub mod verify;

#[cfg(feature = "agent")]
pub mod agent;

// Card-access layer now lives in the shared `firma-cr-card` crate. Re-export
// its modules under the original paths so `crate::digest` / `crate::pkcs11_client`
// keep resolving across this crate.
pub use firma_cr_card::{digest, pkcs11_client};

pub use crate::error::{Error, Result};
pub use crate::digest::HashAlgo;
pub use crate::pkcs11_client::{CardClient, CardKey};
pub use crate::cert::SignerCert;
