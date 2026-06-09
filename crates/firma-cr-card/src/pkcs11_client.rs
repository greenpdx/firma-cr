// SPDX-License-Identifier: GPL-3.0-or-later
//! Thin façade over the `cryptoki` crate. Loads any PKCS#11 module
//! by path (typically our own `libfirma_cr_pkcs11.so` but any
//! conformant module works), opens a session against a token, exposes
//! cert read, signing-key lookup, and a single `sign()` over a
//! pre-built `DigestInfo`.
//!
//! The signing operation is **`CKM_RSA_PKCS`** — the caller supplies
//! the full DigestInfo (`SEQUENCE { AlgorithmIdentifier, OCTET STRING
//! digest }`), the token signs it RSA-PKCS1v1.5. This is the most
//! flexible mechanism: the same `sign()` works for SHA-256 /-384/-512
//! and the same code path produces CAdES / PAdES / XAdES signatures.

use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::digest::HashAlgo;
use crate::error::{Error, Result};

/// Handle to a CKK_RSA, CKA_SIGN-capable private key on the token.
/// Carried separately from the cert so callers can use a different
/// cert source (e.g. `--cert-file`) while still signing with the
/// on-card key.
#[derive(Clone, Debug)]
pub struct CardKey {
    pub handle: ObjectHandle,
    pub label: Option<String>,
    pub modulus_bits: u32,
}

pub struct CardClient {
    ctx: Pkcs11,
    pub slot: Slot,
    session: Session,
}

impl CardClient {
    /// Load the PKCS#11 module at `module_path`, initialise it, find
    /// the requested slot (or the first one with a present token if
    /// `slot_idx` is `None`), and open a serial session.
    pub fn open(module_path: &Path, slot_idx: Option<usize>) -> Result<Self> {
        log::info!("pkcs11: loading module {}", module_path.display());
        let ctx = Pkcs11::new(module_path)?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        let slots = ctx.get_slots_with_token()?;
        if slots.is_empty() {
            return Err(Error::Pkcs11("no slot has a present token".into()));
        }
        let slot = match slot_idx {
            Some(i) => *slots.get(i).ok_or_else(|| {
                Error::Pkcs11(format!(
                    "slot index {} out of range ({} slots with tokens)",
                    i,
                    slots.len()
                ))
            })?,
            None => slots[0],
        };
        log::info!("pkcs11: opening RW session on slot {:?}", slot);
        // One RW session for the whole lifecycle (read + login + sign). Opening
        // a second session for login (the old RO->RW swap) makes some PC/SC
        // stacks power-cycle the card, which resets in-progress Secure Messaging
        // (observed against the card-sim / crfirma -> ResetCard during CA). A
        // single RW session avoids that and is accepted for Login by crfirma.
        let session = ctx.open_rw_session(slot)?;
        Ok(Self { ctx, slot, session })
    }

    /// Print library + slot + token info for diagnostics.
    pub fn info(&self) -> Result<String> {
        let lib = self.ctx.get_library_info()?;
        let tinfo = self.ctx.get_token_info(self.slot)?;
        let sinfo = self.ctx.get_slot_info(self.slot)?;
        Ok(format!(
            "PKCS#11 library: manufacturer={:?}\n\
             cryptoki version: {}.{}\n\
             slot:  description={:?}\n\
             slot:  manufacturer={:?}\n\
             token: label={:?}\n\
             token: manufacturer={:?}\n\
             token: model={:?}\n\
             token: serial={:?}\n\
             token: login_required={} write_protected={} token_initialized={} \
             user_pin_initialized={} user_pin_count_low={} user_pin_locked={}",
            lib.manufacturer_id(),
            lib.cryptoki_version().major(),
            lib.cryptoki_version().minor(),
            sinfo.slot_description(),
            sinfo.manufacturer_id(),
            tinfo.label(),
            tinfo.manufacturer_id(),
            tinfo.model(),
            tinfo.serial_number(),
            tinfo.login_required(),
            tinfo.write_protected(),
            tinfo.token_initialized(),
            tinfo.user_pin_initialized(),
            tinfo.user_pin_count_low(),
            tinfo.user_pin_locked(),
        ))
    }

    /// Authenticate as the token user on the (already RW) session.
    pub fn login(&mut self, pin: &str) -> Result<()> {
        // Log in on the single RW session opened in `open` — no session reopen
        // (that power-cycled the card and reset Secure Messaging; see `open`).
        let pin = AuthPin::new(pin.to_string().into());
        self.session.login(UserType::User, Some(&pin))?;
        log::info!("pkcs11: C_Login OK");
        Ok(())
    }

    /// Read the first CKO_CERTIFICATE on the token, return raw DER.
    pub fn read_certificate(&self) -> Result<Vec<u8>> {
        let template = [Attribute::Class(ObjectClass::CERTIFICATE)];
        let objects = self.session.find_objects(&template)?;
        if objects.is_empty() {
            return Err(Error::NoCertificate);
        }
        let attrs = self.session.get_attributes(
            objects[0],
            &[AttributeType::Value, AttributeType::Label],
        )?;
        for attr in attrs {
            if let Attribute::Value(bytes) = attr {
                if bytes.is_empty() {
                    return Err(Error::NoCertificate);
                }
                log::info!("pkcs11: read certificate ({} bytes DER)", bytes.len());
                return Ok(bytes);
            }
        }
        Err(Error::NoCertificate)
    }

    /// Find the first CKK_RSA private key with CKA_SIGN=true and
    /// return a `CardKey` capturing its handle + modulus size.
    pub fn read_signing_key(&self) -> Result<CardKey> {
        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Sign(true),
        ];
        let objects = self.session.find_objects(&template)?;
        if objects.is_empty() {
            return Err(Error::NoSigningKey);
        }
        let handle = objects[0];
        let attrs = self.session.get_attributes(
            handle,
            &[AttributeType::ModulusBits, AttributeType::Label],
        )?;
        let mut modulus_bits: u32 = 0;
        let mut label: Option<String> = None;
        for attr in attrs {
            match attr {
                Attribute::ModulusBits(n) => {
                    let bits_u64: u64 = n.into();
                    modulus_bits = bits_u64 as u32;
                }
                Attribute::Label(bytes) => {
                    label = Some(String::from_utf8_lossy(&bytes).to_string())
                }
                _ => {}
            }
        }
        if modulus_bits == 0 {
            // BCCR ChipDoc doesn't always expose CKA_MODULUS_BITS;
            // fall back to reading CKA_MODULUS and counting bytes.
            let m = self.session.get_attributes(handle, &[AttributeType::Modulus])?;
            for attr in m {
                if let Attribute::Modulus(bytes) = attr {
                    modulus_bits = (bytes.len() as u32) * 8;
                }
            }
        }
        log::info!(
            "pkcs11: signing key found (modulus_bits={}, label={:?})",
            modulus_bits, label,
        );
        Ok(CardKey { handle, label, modulus_bits })
    }

    /// Sign a pre-built DigestInfo with `CKM_RSA_PKCS`. The caller is
    /// responsible for wrapping the raw digest in the DigestInfo
    /// (`SEQUENCE { AlgorithmIdentifier, OCTET STRING digest }`) —
    /// see `build_digest_info()` below for the helper.
    pub fn sign(&self, key: &CardKey, digest_info: &[u8]) -> Result<Vec<u8>> {
        log::info!(
            "pkcs11: signing DigestInfo ({} bytes) with CKM_RSA_PKCS",
            digest_info.len()
        );
        let sig = self.session.sign(&Mechanism::RsaPkcs, key.handle, digest_info)?;
        log::info!("pkcs11: signature {} bytes", sig.len());
        Ok(sig)
    }
}

impl Drop for CardClient {
    fn drop(&mut self) {
        // Best-effort logout; ignore errors so a panic in the user
        // doesn't get masked by a logout failure.
        let _ = self.session.logout();
    }
}

/// DER-encode a PKCS#1 `DigestInfo` for the given hash algorithm
/// and raw digest. Output is fed straight to `CardClient::sign()`.
///
///   DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest          OCTET STRING
///   }
pub fn build_digest_info(algo: HashAlgo, digest: &[u8]) -> Vec<u8> {
    assert_eq!(
        digest.len(),
        algo.output_bytes(),
        "digest length ({}) != algo output bytes ({})",
        digest.len(),
        algo.output_bytes(),
    );
    // Hard-coded DER prefixes per RFC 8017 §9.2 Notes. These are the
    // SHA-2 OID-with-null-params + OCTET STRING tag bytes; we append
    // the raw digest.
    let prefix: &[u8] = match algo {
        HashAlgo::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        ],
        HashAlgo::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        ],
        HashAlgo::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        ],
    };
    let mut out = Vec::with_capacity(prefix.len() + digest.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(digest);
    out
}

/// Library-level info (manufacturer / versions) — no token required.
/// Used by diagnostic CLIs (`firma-cr info`).
pub fn library_info(module_path: &Path) -> Result<String> {
    let ctx = Pkcs11::new(module_path)?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let info = ctx.get_library_info()?;
    Ok(format!(
        "Cryptoki:     {}\nLibrary ver:  {}\nManufacturer: {}\nDescription:  {}",
        info.cryptoki_version(),
        info.library_version(),
        info.manufacturer_id(),
        info.library_description(),
    ))
}

/// One descriptive line per slot that currently has a token present.
/// Used by diagnostic CLIs (`firma-cr list`).
pub fn list_tokens(module_path: &Path) -> Result<Vec<String>> {
    let ctx = Pkcs11::new(module_path)?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let mut out = Vec::new();
    for slot in ctx.get_slots_with_token()? {
        let info = ctx.get_token_info(slot)?;
        out.push(format!(
            "Slot {}: label={:?} model={:?}",
            slot.id(),
            info.label(),
            info.model()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_info_sha256_shape() {
        let d = [0xAAu8; 32];
        let di = build_digest_info(HashAlgo::Sha256, &d);
        // SEQUENCE(0x30) of total length 0x31 = 49 bytes after the
        // 2-byte SEQUENCE header. 49 + 2 = 51 bytes total.
        assert_eq!(di.len(), 51);
        assert_eq!(di[0], 0x30);
        assert_eq!(di[1], 0x31);
        // Last 32 bytes are the digest.
        assert_eq!(&di[di.len() - 32..], &d);
    }

    #[test]
    fn digest_info_sha512_shape() {
        let d = [0xBBu8; 64];
        let di = build_digest_info(HashAlgo::Sha512, &d);
        assert_eq!(di.len(), 83);
        assert_eq!(&di[di.len() - 64..], &d);
    }

    #[test]
    #[should_panic]
    fn digest_info_panics_on_wrong_length() {
        let _ = build_digest_info(HashAlgo::Sha256, &[0u8; 31]);
    }
}
