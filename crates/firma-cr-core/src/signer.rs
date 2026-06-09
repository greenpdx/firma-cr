//! `Signer` trait — abstracts the RSA-PKCS#1-v1.5 over-DigestInfo
//! operation so the builders don't hard-couple to PKCS#11.
//!
//! Two implementations:
//!
//! * `CardSigner` — production path. Holds references to a
//!   `CardClient` + `CardKey` and forwards each `sign_digest_info`
//!   to `CardClient::sign()` (which drives `CKM_RSA_PKCS` on the
//!   token).
//! * `SoftwareSigner` — test path, gated behind the `test-signer`
//!   cargo feature. Holds an in-memory `rsa::RsaPrivateKey` (loaded
//!   from a PEM/DER on disk) and signs with `rsa` crate primitives.
//!   Lets us run round-trip integration tests against a test CA
//!   hierarchy without a card.

use crate::error::Result;

pub trait Signer {
    /// Sign a pre-built PKCS#1 DigestInfo (the caller has already
    /// hashed the to-be-signed bytes and wrapped them via
    /// `build_digest_info`). Returns the RSA-PKCS#1-v1.5 signature.
    fn sign_digest_info(&self, digest_info: &[u8]) -> Result<Vec<u8>>;

    /// Modulus size in bits. Used by the builders that need to
    /// know the signature length up-front (e.g. PAdES /Contents
    /// reservation).
    fn modulus_bits(&self) -> u32;
}

// -------------------------------------------------------------- card

use crate::pkcs11_client::{CardClient, CardKey};

pub struct CardSigner<'a> {
    pub client: &'a CardClient,
    pub key: &'a CardKey,
}

impl<'a> CardSigner<'a> {
    pub fn new(client: &'a CardClient, key: &'a CardKey) -> Self {
        Self { client, key }
    }
}

impl<'a> Signer for CardSigner<'a> {
    fn sign_digest_info(&self, digest_info: &[u8]) -> Result<Vec<u8>> {
        self.client.sign(self.key, digest_info).map_err(Into::into)
    }
    fn modulus_bits(&self) -> u32 {
        self.key.modulus_bits
    }
}

// -------------------------------------------------------- software

#[cfg(feature = "test-signer")]
pub use software::SoftwareSigner;

#[cfg(feature = "test-signer")]
mod software {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};
    use std::path::Path;

    use crate::error::{Error, Result};
    use crate::signer::Signer;

    pub struct SoftwareSigner {
        key: RsaPrivateKey,
    }

    impl SoftwareSigner {
        /// Load an RSA private key from a PEM or DER file. Supports
        /// both PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8
        /// (`PRIVATE KEY`) blocks.
        pub fn from_file(path: &Path) -> Result<Self> {
            let bytes = std::fs::read(path)?;
            let key = if bytes.starts_with(b"-----BEGIN") {
                let s = std::str::from_utf8(&bytes)
                    .map_err(|_| Error::CertParse("PEM not UTF-8".into()))?;
                if s.contains("BEGIN RSA PRIVATE KEY") {
                    RsaPrivateKey::from_pkcs1_pem(s)
                        .map_err(|e| Error::CertParse(format!("PKCS#1 PEM: {e}")))?
                } else {
                    RsaPrivateKey::from_pkcs8_pem(s)
                        .map_err(|e| Error::CertParse(format!("PKCS#8 PEM: {e}")))?
                }
            } else {
                RsaPrivateKey::from_pkcs8_der(&bytes)
                    .or_else(|_| RsaPrivateKey::from_pkcs1_der(&bytes))
                    .map_err(|e| Error::CertParse(format!("DER key: {e}")))?
            };
            Ok(Self { key })
        }
    }

    impl Signer for SoftwareSigner {
        fn sign_digest_info(&self, digest_info: &[u8]) -> Result<Vec<u8>> {
            // The caller already wrapped the digest in a PKCS#1
            // DigestInfo. `Pkcs1v15Sign::new_unprefixed()` produces
            // a scheme that signs raw bytes (no extra wrapping),
            // which is exactly what we want.
            let scheme = Pkcs1v15Sign::new_unprefixed();
            self.key
                .sign(scheme, digest_info)
                .map_err(|e| Error::Pkcs11(format!("software sign: {e}")))
        }
        fn modulus_bits(&self) -> u32 {
            (self.key.size() * 8) as u32
        }
    }
}

#[cfg(all(test, feature = "test-signer"))]
mod tests {
    use super::*;
    use crate::digest::HashAlgo;
    use crate::pkcs11_client::build_digest_info;

    /// 2048-bit test key generated once with:
    ///   openssl genrsa -out /tmp/k.pem 2048 && cat /tmp/k.pem
    /// Trimmed to the BEGIN/END markers below. Not used for any
    /// production cert; lives here as a self-contained sign test.
    const TEST_PRIV_KEY_PEM: &str = include_str!("../tests/test_signer_key.pem");

    #[test]
    fn software_signer_round_trip() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        tmp.write_all(TEST_PRIV_KEY_PEM.as_bytes()).unwrap();
        tmp.flush().unwrap();
        let s = SoftwareSigner::from_file(tmp.path()).unwrap();
        let msg = b"sample to sign";
        let digest = HashAlgo::Sha256.hash(msg);
        let di = build_digest_info(HashAlgo::Sha256, &digest);
        let sig = s.sign_digest_info(&di).unwrap();
        // Signature length matches modulus size (in bytes).
        assert_eq!(sig.len(), (s.modulus_bits() / 8) as usize);
    }
}
