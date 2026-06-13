// SPDX-License-Identifier: GPL-3.0-or-later
//! Card access façade with two backends behind one API:
//!
//!   * **Macro** — the driver's vendor `fcr_*` FFI (atomic, order-safe). The
//!     driver performs `ChipAuth → VERIFY → MSE → PSO` in one call, so the open
//!     side never sequences card protocol (the source of the `SW=6985` class of
//!     bug). Used automatically when the loaded module exports `fcr_abi_version`.
//!   * **Pkcs11** — the standard `cryptoki` path (any conformant module). Used as
//!     a fallback when the macro symbols are absent (OpenSC, old driver builds).
//!
//! The signing input is a pre-built PKCS#1 `DigestInfo` (see `build_digest_info`);
//! `CKM_RSA_PKCS` on the cryptoki path, and on the macro path the driver strips it
//! to the bare hash itself. The public API is identical for both backends.

use std::os::raw::c_ulong;
use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use zeroize::Zeroizing;

use crate::digest::HashAlgo;
use crate::error::{Error, Result};

/// Handle to a CKK_RSA, CKA_SIGN-capable private key on the token.
/// Carried separately from the cert so callers can use a different
/// cert source (e.g. `--cert-file`) while still signing with the
/// on-card key.
#[derive(Clone, Debug)]
pub struct CardKey {
    /// PKCS#11 object handle on the cryptoki path; `None` on the macro path
    /// (the vendor FFI selects the signing key itself).
    pub handle: Option<ObjectHandle>,
    pub label: Option<String>,
    pub modulus_bits: u32,
}

// ---------------------------------------------------------------------------
// Vendor macro FFI (fcr_*) — see firma-cr-pkcs11/src/macro_ffi.rs
// ---------------------------------------------------------------------------

type CkRv = c_ulong;
const CKR_OK: CkRv = 0;
const CKR_BUFFER_TOO_SMALL: CkRv = 0x0000_0150;

type FcrAbiVersion = unsafe extern "C" fn() -> u32;
type FcrOpen = unsafe extern "C" fn(c_ulong, *mut c_ulong) -> CkRv;
type FcrClose = unsafe extern "C" fn(c_ulong) -> CkRv;
type FcrLogin = unsafe extern "C" fn(c_ulong, *const u8, c_ulong) -> CkRv;
type FcrReadCert = unsafe extern "C" fn(c_ulong, *mut u8, *mut c_ulong) -> CkRv;
type FcrModulusBits = unsafe extern "C" fn(c_ulong, *mut c_ulong) -> CkRv;
#[allow(clippy::type_complexity)]
type FcrSign = unsafe extern "C" fn(
    c_ulong,
    *const u8,
    c_ulong,
    *const u8,
    c_ulong,
    c_ulong,
    *mut u8,
    *mut c_ulong,
) -> CkRv;

/// Warn (don't fail) if the module to be `dlopen`ed is group/world-writable —
/// a local attacker who can replace it gets code execution in the signing process
/// next to the PIN. Install the driver root-owned (e.g. 0644 under /usr/lib).
#[cfg(unix)]
fn warn_if_module_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 {
            log::warn!(
                "pkcs11: module {} is group/world-writable (mode {:o}); a local attacker \
                 could replace the signing driver — install it root-owned (0644/0755)",
                path.display(),
                mode & 0o777
            );
        }
    }
}
#[cfg(not(unix))]
fn warn_if_module_writable(_path: &Path) {}

fn ck(rv: CkRv, what: &str) -> Result<()> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(Error::Pkcs11(format!("{what}: CK_RV 0x{rv:08X}")))
    }
}

/// The vendor macro backend: drives the driver's atomic `fcr_*` entry points.
struct MacroState {
    lib: libloading::Library,
    session: c_ulong,
    /// PIN cached (zeroized) at login so each atomic `fcr_sign` can re-VERIFY.
    pin: Option<Zeroizing<Vec<u8>>>,
    modulus_bits: u32,
}

impl MacroState {
    /// `Ok(Some)` if the module exports the macro FFI and a session opened;
    /// `Ok(None)` if the symbols are absent (caller falls back to PKCS#11);
    /// `Err` if the symbols exist but the card operation failed.
    fn try_open(module_path: &Path, slot_idx: Option<usize>) -> Result<Option<Self>> {
        let lib = unsafe { libloading::Library::new(module_path) }
            .map_err(|e| Error::Pkcs11(format!("dlopen {}: {e}", module_path.display())))?;
        let abi = match unsafe { lib.get::<FcrAbiVersion>(b"fcr_abi_version\0") } {
            Ok(f) => unsafe { f() },
            Err(_) => return Ok(None), // not our macro-capable driver
        };
        if abi == 0 {
            return Ok(None);
        }
        log::info!("pkcs11: driver exports vendor macro FFI v{abi}; using it");
        let open = unsafe { lib.get::<FcrOpen>(b"fcr_open\0") }
            .map_err(|e| Error::Pkcs11(format!("fcr_open symbol: {e}")))?;
        let mut session: c_ulong = 0;
        ck(unsafe { open(slot_idx.unwrap_or(0) as c_ulong, &mut session) }, "fcr_open")?;
        // Query the real RSA key size (2048/4096) when the driver supports it
        // (ABI v2+); else assume 2048 (BCCR's current cards). The PAdES /Contents
        // reservation is sized from this; the post-build guard catches a mismatch.
        let modulus_bits = unsafe { lib.get::<FcrModulusBits>(b"fcr_modulus_bits\0") }
            .ok()
            .and_then(|f| {
                let mut bits: c_ulong = 0;
                (unsafe { f(session, &mut bits) } == CKR_OK && bits > 0).then_some(bits as u32)
            })
            .unwrap_or(2048);
        log::info!("pkcs11: macro backend, modulus_bits={modulus_bits}");
        Ok(Some(Self { lib, session, pin: None, modulus_bits }))
    }

    fn sym<T>(&self, name: &[u8]) -> Result<libloading::Symbol<'_, T>> {
        unsafe { self.lib.get::<T>(name) }.map_err(|e| {
            Error::Pkcs11(format!("macro symbol {}: {e}", String::from_utf8_lossy(name)))
        })
    }

    fn login(&mut self, pin: &str) -> Result<()> {
        let pin = Zeroizing::new(pin.as_bytes().to_vec());
        let f = self.sym::<FcrLogin>(b"fcr_login\0")?;
        ck(unsafe { f(self.session, pin.as_ptr(), pin.len() as c_ulong) }, "fcr_login")?;
        log::info!("pkcs11: fcr_login OK");
        self.pin = Some(pin);
        Ok(())
    }

    fn read_certificate(&self) -> Result<Vec<u8>> {
        let f = self.sym::<FcrReadCert>(b"fcr_read_cert\0")?;
        // Read in one SM round-trip with a generous buffer (BCCR certs ~1.5 KB);
        // grow only if the driver reports it was too small.
        let mut len: c_ulong = 8192;
        let mut buf = vec![0u8; len as usize];
        let rv = unsafe { f(self.session, buf.as_mut_ptr(), &mut len) };
        if rv == CKR_BUFFER_TOO_SMALL {
            buf = vec![0u8; len as usize];
            ck(unsafe { f(self.session, buf.as_mut_ptr(), &mut len) }, "fcr_read_cert")?;
        } else {
            ck(rv, "fcr_read_cert")?;
        }
        buf.truncate(len as usize);
        if buf.is_empty() {
            return Err(Error::NoCertificate);
        }
        log::info!("pkcs11: fcr_read_cert -> {} bytes DER", buf.len());
        Ok(buf)
    }

    fn sign(&self, digest_info: &[u8]) -> Result<Vec<u8>> {
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| Error::Pkcs11("macro sign before login".into()))?;
        let f = self.sym::<FcrSign>(b"fcr_sign\0")?;
        let mut len: c_ulong = (self.modulus_bits / 8) as c_ulong;
        let mut sig = vec![0u8; len as usize];
        // hashAlgo = 0: the driver strips the DigestInfo to the bare hash itself.
        let call = |buf: &mut [u8], len: &mut c_ulong| unsafe {
            f(
                self.session,
                pin.as_ptr(),
                pin.len() as c_ulong,
                digest_info.as_ptr(),
                digest_info.len() as c_ulong,
                0,
                buf.as_mut_ptr(),
                len,
            )
        };
        let rv = call(&mut sig, &mut len);
        if rv == CKR_BUFFER_TOO_SMALL {
            sig = vec![0u8; len as usize];
            ck(call(&mut sig, &mut len), "fcr_sign")?;
        } else {
            ck(rv, "fcr_sign")?;
        }
        sig.truncate(len as usize);
        log::info!("pkcs11: fcr_sign -> {} byte signature", sig.len());
        Ok(sig)
    }
}

impl Drop for MacroState {
    fn drop(&mut self) {
        if let Ok(f) = unsafe { self.lib.get::<FcrClose>(b"fcr_close\0") } {
            let _ = unsafe { f(self.session) };
        }
    }
}

// ---------------------------------------------------------------------------
// CardClient: one API over both backends
// ---------------------------------------------------------------------------

enum Backend {
    Pkcs11 { ctx: Pkcs11, slot: Slot, session: Session },
    Macro(MacroState),
}

pub struct CardClient {
    backend: Backend,
}

impl CardClient {
    /// Load the PKCS#11 module at `module_path`. If it exports the vendor macro
    /// FFI, use that (atomic, order-safe); otherwise use the standard cryptoki
    /// path. `slot_idx` selects the slot (first present token if `None`).
    pub fn open(module_path: &Path, slot_idx: Option<usize>) -> Result<Self> {
        log::info!("pkcs11: loading module {}", module_path.display());
        warn_if_module_writable(module_path);
        if let Some(m) = MacroState::try_open(module_path, slot_idx)? {
            return Ok(Self { backend: Backend::Macro(m) });
        }
        log::info!("pkcs11: no vendor macro FFI; using standard PKCS#11");

        let ctx = Pkcs11::new(module_path)?;
        // The crfirma driver is a process-global singleton (one C_Initialize per
        // process). Re-opening after a previous session was dropped (e.g. the
        // agent's self-recovery) returns ALREADY_INITIALIZED — that's fine, the
        // library is up; we just need a fresh session, not a re-init.
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {}
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::CryptokiAlreadyInitialized,
                _,
            )) => {
                log::info!("pkcs11: library already initialized; reusing context");
            }
            Err(e) => return Err(e.into()),
        }

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
        Ok(Self { backend: Backend::Pkcs11 { ctx, slot, session } })
    }

    /// Print library + slot + token info for diagnostics.
    pub fn info(&self) -> Result<String> {
        let (ctx, slot) = match &self.backend {
            Backend::Pkcs11 { ctx, slot, .. } => (ctx, slot),
            Backend::Macro(_) => {
                return Ok("PKCS#11 vendor macro backend (fcr_*); token details \
                           are reported via the signing certificate."
                    .to_string());
            }
        };
        let lib = ctx.get_library_info()?;
        let tinfo = ctx.get_token_info(*slot)?;
        let sinfo = ctx.get_slot_info(*slot)?;
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

    /// Authenticate as the token user.
    pub fn login(&mut self, pin: &str) -> Result<()> {
        match &mut self.backend {
            Backend::Macro(m) => m.login(pin),
            Backend::Pkcs11 { session, .. } => {
                // PIN hygiene: hand `AuthPin` (secrecy::SecretString, which zeroizes
                // on drop) a single freshly-allocated copy and keep no other. The
                // previous `Zeroizing::new(pin.to_string())` + `.as_str().into()`
                // made a *second*, un-zeroized `String`/`Box<str>` via reallocation.
                let auth = AuthPin::new(Box::<str>::from(pin));
                session.login(UserType::User, Some(&auth))?;
                log::info!("pkcs11: C_Login OK");
                Ok(())
            }
        }
    }

    /// Read the signing certificate, return raw DER.
    pub fn read_certificate(&self) -> Result<Vec<u8>> {
        let session = match &self.backend {
            Backend::Macro(m) => return m.read_certificate(),
            Backend::Pkcs11 { session, .. } => session,
        };
        let template = [Attribute::Class(ObjectClass::CERTIFICATE)];
        let objects = session.find_objects(&template)?;
        if objects.is_empty() {
            return Err(Error::NoCertificate);
        }
        let attrs =
            session.get_attributes(objects[0], &[AttributeType::Value, AttributeType::Label])?;
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

    /// Find the signing key and return a `CardKey` capturing its handle (cryptoki
    /// path) and modulus size.
    pub fn read_signing_key(&self) -> Result<CardKey> {
        let session = match &self.backend {
            Backend::Macro(m) => {
                // The macro FFI selects the key itself; no handle to carry.
                return Ok(CardKey {
                    handle: None,
                    label: Some("Firma Digital".to_string()),
                    modulus_bits: m.modulus_bits,
                });
            }
            Backend::Pkcs11 { session, .. } => session,
        };
        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Sign(true),
        ];
        let objects = session.find_objects(&template)?;
        if objects.is_empty() {
            return Err(Error::NoSigningKey);
        }
        let handle = objects[0];
        let attrs =
            session.get_attributes(handle, &[AttributeType::ModulusBits, AttributeType::Label])?;
        let mut modulus_bits: u32 = 0;
        let mut label: Option<String> = None;
        for attr in attrs {
            match attr {
                Attribute::ModulusBits(n) => {
                    let bits_u64: u64 = n.into();
                    modulus_bits = bits_u64 as u32;
                }
                Attribute::Label(bytes) => label = Some(String::from_utf8_lossy(&bytes).to_string()),
                _ => {}
            }
        }
        if modulus_bits == 0 {
            // BCCR ChipDoc doesn't always expose CKA_MODULUS_BITS;
            // fall back to reading CKA_MODULUS and counting bytes.
            let m = session.get_attributes(handle, &[AttributeType::Modulus])?;
            for attr in m {
                if let Attribute::Modulus(bytes) = attr {
                    modulus_bits = (bytes.len() as u32) * 8;
                }
            }
        }
        log::info!("pkcs11: signing key found (modulus_bits={}, label={:?})", modulus_bits, label);
        Ok(CardKey { handle: Some(handle), label, modulus_bits })
    }

    /// Sign a pre-built `DigestInfo`. On the cryptoki path this is `CKM_RSA_PKCS`
    /// over `key.handle`; on the macro path the driver strips the DigestInfo to
    /// the bare hash and signs atomically with the cached PIN.
    pub fn sign(&self, key: &CardKey, digest_info: &[u8]) -> Result<Vec<u8>> {
        match &self.backend {
            Backend::Macro(m) => m.sign(digest_info),
            Backend::Pkcs11 { session, .. } => {
                let handle = key
                    .handle
                    .ok_or_else(|| Error::Pkcs11("cryptoki sign requires a key handle".into()))?;
                log::info!(
                    "pkcs11: signing DigestInfo ({} bytes) with CKM_RSA_PKCS",
                    digest_info.len()
                );
                let sig = session.sign(&Mechanism::RsaPkcs, handle, digest_info)?;
                log::info!("pkcs11: signature {} bytes", sig.len());
                Ok(sig)
            }
        }
    }
}

impl Drop for CardClient {
    fn drop(&mut self) {
        // Best-effort logout on the cryptoki path; ignore errors so a panic in the
        // user doesn't get masked by a logout failure. The macro backend cleans up
        // its session in `MacroState::drop`.
        if let Backend::Pkcs11 { session, .. } = &self.backend {
            let _ = session.logout();
        }
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
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        HashAlgo::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        HashAlgo::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
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
        out.push(format!("Slot {}: label={:?} model={:?}", slot.id(), info.label(), info.model()));
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
