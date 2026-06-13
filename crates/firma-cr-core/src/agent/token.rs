// SPDX-License-Identifier: GPL-3.0-or-later
//! The `/dyn` "token" verbs (connect / login / get_certs / sign) mapped onto
//! firma-cr-core's `CardClient` — the agent's binding to the card via crfirma
//! (PKCS#11). Integration-tested against the card simulator (no hardware).

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use crate::cert::SignerCert;
use crate::{CardClient, CardKey};

use crate::agent::api::Certificate;

/// Agent-assigned handle for the single signing key/cert. The web app reads it
/// from `get_certstore_certificates` and passes it back as
/// `cryptoshell_build`'s `sign_cert`/`sign_key`.
pub const FIRMA_HANDLE: &str = "1";

#[derive(Debug)]
pub enum TokenError {
    Connect(String),
    Login(String),
    NotLoggedIn,
    UnknownHandle,
    Card(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Connect(e) => write!(f, "connect failed: {e}"),
            TokenError::Login(e) => write!(f, "login failed: {e}"),
            TokenError::NotLoggedIn => write!(f, "not logged in"),
            TokenError::UnknownHandle => write!(f, "unknown key handle"),
            TokenError::Card(e) => write!(f, "card error: {e}"),
        }
    }
}
impl std::error::Error for TokenError {}

/// One card session: the open PKCS#11 client plus, after login, the signing
/// cert + key.
pub struct TokenSession {
    client: CardClient,
    cert_der: Option<Vec<u8>>,
    cert: Option<SignerCert>,
    key: Option<CardKey>,
}

impl TokenSession {
    /// `connect` / `begin_session`: open the PKCS#11 module + the card session,
    /// and read the (public) signing certificate — BEFORE any PIN/VERIFY.
    pub fn connect(module_path: &Path) -> Result<Self, TokenError> {
        let client =
            CardClient::open(module_path, None).map_err(|e| TokenError::Connect(e.to_string()))?;
        // Read the cert here, before login. It is public (no PIN), and doing it now
        // keeps the post-VERIFY card sequence down to read_signing_key → C_Sign,
        // exactly like the working CLI. A find_objects(CERTIFICATE) *after* VERIFY
        // re-SELECTs the applet and clears the card's PIN security status, which
        // made PSO:CDS fail with SW=6985 ("conditions of use not satisfied"). The
        // clean-room spec also reads the cert (step 5) before the VERIFY (step 6).
        let der = client
            .read_certificate()
            .map_err(|e| TokenError::Card(e.to_string()))?;
        let cert = SignerCert::from_der(der.clone()).map_err(|e| TokenError::Card(e.to_string()))?;
        Ok(Self { client, cert_der: Some(der), cert: Some(cert), key: None })
    }

    /// `login`: verify the PIN, then read the signing key — and nothing else
    /// touches the card before C_Sign, so the PIN status holds at PSO:CDS.
    pub fn login(&mut self, pin: &str) -> Result<(), TokenError> {
        self.client.login(pin).map_err(|e| TokenError::Login(e.to_string()))?;
        let key = self
            .client
            .read_signing_key()
            .map_err(|e| TokenError::Card(e.to_string()))?;
        self.key = Some(key);
        Ok(())
    }

    pub fn logged_in(&self) -> bool {
        self.key.is_some()
    }

    /// Card + signing-cert info WITHOUT logging in (the "is the card readable?"
    /// probe a GUI runs first). The cert reads over the SM channel (CA, no PIN).
    pub fn info(&self) -> Result<String, TokenError> {
        let mut out = self.client.info().map_err(|e| TokenError::Card(e.to_string()))?;
        // Prefer the cert cached at connect-time; only read from the card if we
        // don't have it. Avoids a redundant find_objects(CERTIFICATE) that, run
        // after VERIFY, would clear the card's PIN status (see `connect`).
        let cert = match &self.cert {
            Some(c) => Some(c.clone()),
            None => self
                .client
                .read_certificate()
                .ok()
                .and_then(|der| SignerCert::from_der(der).ok()),
        };
        if let Some(cert) = cert {
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
        Ok(out)
    }

    /// `get_certstore_certificates`: the signing cert as an [`api::Certificate`].
    pub fn certificates(&self) -> Vec<Certificate> {
        match (&self.cert, &self.cert_der, &self.key) {
            (Some(cert), Some(der), Some(key)) => vec![Certificate {
                handle: FIRMA_HANDLE.to_string(),
                label: key.label.clone().unwrap_or_else(|| "Firma Digital".to_string()),
                subject_dn: cert.subject_string(),
                issuer_dn: cert.issuer_string(),
                serial: cert.serial_hex(),
                cert_b64: STANDARD.encode(der),
            }],
            _ => Vec::new(),
        }
    }

    /// The signing cert (for the `sign` module to build the PAdES signature).
    pub fn signer_cert(&self) -> Option<&SignerCert> {
        self.cert.as_ref()
    }

    /// Raw sign: a DigestInfo block → RSA signature. `handle` must be the one
    /// from [`Self::certificates`].
    pub fn sign(&self, handle: &str, digest_info: &[u8]) -> Result<Vec<u8>, TokenError> {
        if handle != FIRMA_HANDLE {
            return Err(TokenError::UnknownHandle);
        }
        let key = self.key.as_ref().ok_or(TokenError::NotLoggedIn)?;
        self.client
            .sign(key, digest_info)
            .map_err(|e| TokenError::Card(e.to_string()))
    }

    /// PAdES-B-B sign a PDF with the logged-in firma key (used by the `sign`
    /// module for `cryptoshell_build type=SIGN`). The card does the RSA via
    /// firma-cr-core's `CardSigner`.
    pub fn sign_pdf(
        &self,
        input_pdf: &[u8],
        reason: Option<&str>,
        location: Option<&str>,
        placement: Option<crate::agent::sign::StampPlacement>,
        tsa_url: Option<&str>,
    ) -> Result<Vec<u8>, TokenError> {
        use crate::digest::HashAlgo;
        use crate::signer::CardSigner;

        let cert = self.cert.as_ref().ok_or(TokenError::NotLoggedIn)?;
        let key = self.key.as_ref().ok_or(TokenError::NotLoggedIn)?;
        let signer = CardSigner::new(&self.client, key);
        let now = std::time::SystemTime::now();

        // Visible signature stamp (bottom-left of page 1): signer + date + reason.
        let subject = cert.subject_string();
        let cn = subject
            .split(',')
            .find_map(|p| p.trim().strip_prefix("CN="))
            .unwrap_or(subject.as_str());
        let secs = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (yy, mo, dd, hh, mi, _) = crate::pades::secs_to_utc_pub(secs);
        let mut label = format!(
            "Firmado digitalmente por\n{cn}\nFecha: {yy:04}-{mo:02}-{dd:02} {hh:02}:{mi:02} UTC"
        );
        if let Some(r) = reason {
            label.push('\n');
            label.push_str(&format!("Razon: {r}"));
        }
        // Caller-chosen placement (interactive box), or a default bottom-left box.
        let (rect, font_size, page) = match placement {
            Some(p) => (p.rect, Some(p.font_size), p.page),
            None => ((36.0, 42.0, 336.0, 132.0), None, 1),
        };
        let visible = Some(crate::pades::VisibleAppearance { rect, page, font_size, label });

        // PAdES-T: if a TSA URL is configured, embed an RFC 3161 signature
        // timestamp (signed over the CMS signature value). Without it we produce
        // PAdES-B-B as before.
        let timestamp_fn: Option<crate::cades::TimestampFn> = tsa_url.map(|url| {
            let url = url.to_string();
            Box::new(move |sig: &[u8]| {
                let req = crate::tsa::TimestampRequest::new(sig, HashAlgo::Sha256);
                let req_der = req.to_der()?;
                Ok(crate::tsa::request_token(&url, &req_der)?.token_der)
            }) as crate::cades::TimestampFn
        });

        crate::pades::sign_pdf(
            input_pdf,
            cert,
            &[],
            HashAlgo::Sha256,
            reason,
            location,
            None,
            now,
            &signer,
            timestamp_fn,
            visible,
            false,
            None,
        )
        .map_err(|e| TokenError::Card(e.to_string()))
    }
}

/// Resolve the crfirma PKCS#11 module (`.so`). Resolution order:
///   1. `CRFIRMA_MODULE` env var (explicit override),
///   2. the installed system module,
///   3. a dev build path under `$HOME` (last resort).
/// The upper layer must not assume a `digitalfirma/` source-tree layout.
pub fn default_module_path() -> PathBuf {
    if let Ok(p) = std::env::var("CRFIRMA_MODULE") {
        return PathBuf::from(p);
    }
    // Installed location (matches the firma-cr-core CLI default).
    let system = PathBuf::from("/usr/lib/firma-cr/libfirma_cr_pkcs11.so");
    if system.exists() {
        return system;
    }
    // Dev fallback: a sibling firma-cr-pkcs11 release build.
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!(
        "{home}/digitalfirma/firma-cr-pkcs11/target/release/libfirma_cr_pkcs11.so"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The card test drives the WHOLE flow in one test: crfirma's PKCS#11 module
    // is a process-global singleton (one C_Initialize / one card session), so
    // splitting it across concurrently-run tests trips ALREADY_INITIALIZED /
    // ResetCard. Run with the sim up:
    //   cd firma-cr-analysis/tools/card-sim && ./target/release/card-sim &
    //   cargo test -p firma-cr-agent token -- --ignored
    #[test]
    #[ignore = "needs the card-sim running + crfirma module (run with --ignored)"]
    fn connect_login_cert_and_sign_against_sim() {
        use crate::digest::HashAlgo;
        use crate::pkcs11_client::build_digest_info;

        let mut t = TokenSession::connect(&default_module_path()).expect("connect");
        t.login("1234").expect("login");
        assert!(t.logged_in());

        // get_certstore_certificates → one firma cert with a usable handle.
        let certs = t.certificates();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].handle, FIRMA_HANDLE);
        assert!(certs[0].subject_dn.to_uppercase().contains("FIRMA"));
        assert!(!certs[0].cert_b64.is_empty());

        // sign a SHA-256 DigestInfo → RSA-2048 signature.
        let di = build_digest_info(HashAlgo::Sha256, &[0u8; 32]);
        let sig = t.sign(FIRMA_HANDLE, &di).expect("sign");
        assert_eq!(sig.len(), 256);

        // wrong handle is rejected.
        assert!(matches!(t.sign("99", &di), Err(TokenError::UnknownHandle)));
    }
}
