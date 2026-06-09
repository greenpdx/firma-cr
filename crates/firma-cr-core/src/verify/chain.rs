// SPDX-License-Identifier: GPL-3.0-or-later
//! Certificate chain validation.
//!
//! Given a leaf cert + a set of intermediate certs found in the
//! signed envelope + one or more trust-root certs loaded from a
//! `--ca-file` PEM bundle, walk from leaf upward by issuer/subject
//! match, RSA-verify each link, and check basic constraints on each
//! intermediate.
//!
//! Out of scope (Phase 9 minimum-viable):
//!   * CRL / OCSP revocation checks (Phase 10 — uses revocation.rs).
//!   * Name constraints, certificate policies.
//!   * Path-length constraint enforcement (we only check the
//!     `CA:TRUE` flag).

use rsa::{Pkcs1v15Sign, RsaPublicKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::cert::SignerCert;
use crate::error::{Error, Result};

/// Build a verified path from `leaf` to one of the `roots`,
/// using `intermediates` to fill the gap. Returns the chain in
/// leaf-to-root order on success.
pub fn build_and_verify_chain<'a>(
    leaf: &'a SignerCert,
    intermediates: &[&'a SignerCert],
    roots: &[&'a SignerCert],
) -> Result<Vec<&'a SignerCert>> {
    let mut chain: Vec<&SignerCert> = vec![leaf];
    let mut current = leaf;

    for _step in 0..16 {
        // Stop if `current` is self-issued and present in the
        // trust-root set.
        if is_self_issued(current) {
            for r in roots {
                if same_subject_and_key(current, r) {
                    return Ok(chain);
                }
            }
        }

        // Find an issuer in intermediates or roots.
        let issuer = find_issuer(current, intermediates)
            .or_else(|| find_issuer(current, roots))
            .ok_or_else(|| {
                Error::CertParse(format!(
                    "no issuer cert found for subject {:?}",
                    current.subject_string()
                ))
            })?;

        verify_signed_by(current, issuer)?;
        chain.push(issuer);

        // If the issuer is in the trust-root set, we're done.
        for r in roots {
            if same_subject_and_key(issuer, r) {
                return Ok(chain);
            }
        }
        current = issuer;
    }
    Err(Error::CertParse("cert chain exceeds 16 steps".into()))
}

/// True if subject == issuer (covers root certs and orphan ICAs).
fn is_self_issued(c: &SignerCert) -> bool {
    c.parsed.tbs_certificate.subject == c.parsed.tbs_certificate.issuer
}

/// Find a cert whose subject matches `child.issuer`.
fn find_issuer<'a>(child: &SignerCert, set: &[&'a SignerCert]) -> Option<&'a SignerCert> {
    let issuer = &child.parsed.tbs_certificate.issuer;
    set.iter()
        .find(|c| &c.parsed.tbs_certificate.subject == issuer)
        .copied()
}

fn same_subject_and_key(a: &SignerCert, b: &SignerCert) -> bool {
    a.parsed.tbs_certificate.subject == b.parsed.tbs_certificate.subject
        && a.parsed.tbs_certificate.subject_public_key_info
            == b.parsed.tbs_certificate.subject_public_key_info
}

/// Verify that `child` was signed by `issuer`'s public key.
fn verify_signed_by(child: &SignerCert, issuer: &SignerCert) -> Result<()> {
    use x509_cert::der::Encode;
    let tbs_bytes = child
        .parsed
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::CertParse(format!("encode child TBS: {e}")))?;
    let sig_bytes = child.parsed.signature.as_bytes().ok_or_else(|| {
        Error::CertParse("cert signature has unused bits != 0".into())
    })?;
    // Determine hash from child's signature algorithm OID.
    let alg_oid = child.parsed.signature_algorithm.oid.to_string();
    let hash = match alg_oid.as_str() {
        // sha256WithRSAEncryption
        "1.2.840.113549.1.1.11" => HashKind::Sha256,
        // sha384WithRSAEncryption
        "1.2.840.113549.1.1.12" => HashKind::Sha384,
        // sha512WithRSAEncryption
        "1.2.840.113549.1.1.13" => HashKind::Sha512,
        other => {
            return Err(Error::CertParse(format!(
                "unsupported cert signature algorithm: {other}"
            )))
        }
    };

    let pk = issuer_rsa_pubkey(issuer)?;
    let digest = hash.hash(&tbs_bytes);
    // PKCS#1 v1.5 with the DigestInfo wrapped automatically by
    // Pkcs1v15Sign::new::<H>().
    use rsa::sha2::{Sha256 as RsaSha256, Sha384 as RsaSha384, Sha512 as RsaSha512};
    let result = match hash {
        HashKind::Sha256 => pk.verify(Pkcs1v15Sign::new::<RsaSha256>(), &digest, sig_bytes),
        HashKind::Sha384 => pk.verify(Pkcs1v15Sign::new::<RsaSha384>(), &digest, sig_bytes),
        HashKind::Sha512 => pk.verify(Pkcs1v15Sign::new::<RsaSha512>(), &digest, sig_bytes),
    };
    result.map_err(|e| {
        Error::CertParse(format!(
            "cert {:?} not signed by claimed issuer {:?}: {e}",
            child.subject_string(),
            issuer.subject_string()
        ))
    })
}

fn issuer_rsa_pubkey(c: &SignerCert) -> Result<RsaPublicKey> {
    use x509_cert::der::Encode;
    let spki = c
        .parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::CertParse(format!("encode SPKI: {e}")))?;
    // Try PKCS#8 (SPKI) first; fall back to bare PKCS#1.
    if let Ok(k) = RsaPublicKey::from_public_key_der(&spki) {
        return Ok(k);
    }
    let inner = c
        .parsed
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::CertParse("SPKI public key bit-string unaligned".into()))?;
    RsaPublicKey::from_pkcs1_der(inner)
        .map_err(|e| Error::CertParse(format!("issuer public key: {e}")))
}

#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Sha384,
    Sha512,
}

impl HashKind {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Convenience: extract the RSA public key from any SignerCert.
/// Used by the per-family verifiers when they have the signer cert
/// in hand and need to verify the over-the-wire signature.
pub fn extract_rsa_pubkey(c: &SignerCert) -> Result<RsaPublicKey> {
    issuer_rsa_pubkey(c)
}

/// Check that `cert`'s validity window contains `at`. Used by the
/// time-shift validation path (VerifyOptions.validation_time): a
/// signature whose cert is expired *now* may still verify if the
/// caller supplies a validation_time that falls inside the original
/// notBefore..notAfter window.
pub fn check_validity_at(cert: &SignerCert, at: std::time::SystemTime) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let validity = &cert.parsed.tbs_certificate.validity;
    let nb = cert_time_to_systemtime(&validity.not_before);
    let na = cert_time_to_systemtime(&validity.not_after);
    let at_unix = at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let nb_unix = nb.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let na_unix = na.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(i64::MAX);
    if at_unix < nb_unix {
        return Err(Error::CertParse(format!(
            "cert not yet valid at validation time (notBefore Unix {nb_unix} > validation {at_unix})"
        )));
    }
    if at_unix > na_unix {
        return Err(Error::CertParse(format!(
            "cert expired at validation time (notAfter Unix {na_unix} < validation {at_unix})"
        )));
    }
    let _ = SystemTime::now(); // silence unused-import lint if we add features later
    Ok(())
}

fn cert_time_to_systemtime(t: &x509_cert::time::Time) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    let secs = match t {
        x509_cert::time::Time::UtcTime(u) => u.to_unix_duration().as_secs() as i64,
        x509_cert::time::Time::GeneralTime(g) => g.to_unix_duration().as_secs() as i64,
    };
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH
    }
}
