//! firma-cr-card — shared PKCS#11 card-access layer for the Costa Rica
//! BCCR Firma Digital stack.
//!
//! Loads any conformant PKCS#11 module by path (typically our own
//! `libfirma_cr_pkcs11.so`, but the official Idopte/Athena driver or
//! OpenSC work too) and exposes cert read, signing-key lookup, and a
//! single `sign()` over a pre-built DigestInfo (`CKM_RSA_PKCS`).
//!
//! Consumed by `firma-cr-core` (the ETSI signer lib) and, in time, the
//! engine and CLI — one card client, not three.
//!
//! (PKCS#15 / probe-based discovery — currently in firma-cr-server's
//! `probe.rs` — will move in here next; see report 33 Phase 1.)

pub mod digest;
pub mod error;
pub mod pkcs11_client;

/// PC/SC-direct card probe + PKCS#15 discovery (feature `probe`).
#[cfg(feature = "probe")]
pub mod probe;

pub use crate::digest::HashAlgo;
pub use crate::error::{Error as CardError, Result};
pub use crate::pkcs11_client::{build_digest_info, CardClient, CardKey};
