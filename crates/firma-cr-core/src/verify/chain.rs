// SPDX-License-Identifier: GPL-3.0-or-later
//! Certificate chain validation.
//!
//! Given a leaf cert + a set of intermediate certs found in the
//! signed envelope + one or more trust-root certs loaded from a
//! `--ca-file` PEM bundle, walk from leaf upward by issuer/subject
//! match, RSA-verify each link, and check basic constraints on each
//! intermediate.
//!
//! For each cert used as an *issuer* (it signed the cert below it) we enforce the
//! RFC 5280 CA constraints: `basicConstraints` must be present with `cA = TRUE`,
//! any `pathLenConstraint` must permit the number of intermediate CAs below it,
//! and a present `keyUsage` must assert `keyCertSign`. This stops an end-entity
//! cert (issued under the trust root for some other purpose) from validating as a
//! CA.
//!
//! Out of scope (Phase 9 minimum-viable):
//!   * CRL / OCSP revocation checks (Phase 10 — uses revocation.rs).
//!   * Name constraints, certificate policies.

use der::Decode;
use der::oid::ObjectIdentifier;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use crate::cert::SignerCert;
use crate::error::{Error, Result};

// Use `der::oid` constants so the type matches `extension.extn_id` (the crate
// pulls in two const_oid versions; this is the one x509-cert exposes here).
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

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
    // Number of non-self-issued CA certs already placed below the issuer we are
    // about to validate — used to enforce each CA's pathLenConstraint.
    let mut intermediate_cas_below = 0usize;

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

        // Candidate issuers: every cert (intermediates first, then roots) whose
        // subject matches `current`'s issuer DN. Multiple CAs can share a subject
        // DN with different keys (re-keyed / cross-signed CAs — BCCR has these),
        // so try each and keep the one whose key ACTUALLY signed `current`.
        let want = &current.parsed.tbs_certificate.issuer;
        let mut issuer: Option<&SignerCert> = None;
        let mut saw_candidate = false;
        let mut last_err: Option<Error> = None;
        for c in intermediates.iter().chain(roots.iter()).copied() {
            if &c.parsed.tbs_certificate.subject != want {
                continue;
            }
            saw_candidate = true;
            match verify_signed_by(current, c) {
                Ok(()) => {
                    issuer = Some(c);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let issuer = match issuer {
            Some(c) => c,
            None if saw_candidate => {
                return Err(last_err.unwrap_or_else(|| {
                    Error::CertParse(format!("no issuer verified {:?}", current.subject_string()))
                }));
            }
            None => {
                return Err(Error::CertParse(format!(
                    "no issuer cert found for subject {:?}",
                    current.subject_string()
                )));
            }
        };

        // `issuer` verified `current` above; it must be a valid CA per RFC 5280.
        enforce_ca_constraints(issuer, intermediate_cas_below)?;
        chain.push(issuer);

        // If the issuer is in the trust-root set, we're done.
        for r in roots {
            if same_subject_and_key(issuer, r) {
                return Ok(chain);
            }
        }
        // A non-self-issued issuer is an intermediate CA below the next issuer.
        if !is_self_issued(issuer) {
            intermediate_cas_below += 1;
        }
        current = issuer;
    }
    Err(Error::CertParse("cert chain exceeds 16 steps".into()))
}

/// True if subject == issuer (covers root certs and orphan ICAs).
fn is_self_issued(c: &SignerCert) -> bool {
    c.parsed.tbs_certificate.subject == c.parsed.tbs_certificate.issuer
}

/// Enforce RFC 5280 CA constraints on a cert acting as an issuer (it signed the
/// cert below it in the path). `intermediate_cas_below` is the number of
/// non-self-issued CA certs already placed between this issuer and the leaf.
///
/// Rules:
///   * `basicConstraints` must be present with `cA = TRUE` — a cert without it,
///     or with `cA = FALSE`, is an end-entity cert and must not validate as a CA.
///   * a present `pathLenConstraint` must be >= `intermediate_cas_below`.
///   * a present `keyUsage` must assert `keyCertSign`.
fn enforce_ca_constraints(issuer: &SignerCert, intermediate_cas_below: usize) -> Result<()> {
    let exts = issuer
        .parsed
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| {
            Error::CertParse(format!(
                "issuer {:?} has no extensions; not a valid CA",
                issuer.subject_string()
            ))
        })?;

    // basicConstraints: required, cA must be TRUE.
    let bc_ext = exts
        .iter()
        .find(|e| e.extn_id == OID_BASIC_CONSTRAINTS)
        .ok_or_else(|| {
            Error::CertParse(format!(
                "issuer {:?} lacks basicConstraints; not a CA",
                issuer.subject_string()
            ))
        })?;
    let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .map_err(|e| Error::CertParse(format!("issuer basicConstraints parse: {e}")))?;
    if !bc.ca {
        return Err(Error::CertParse(format!(
            "issuer {:?} is not a CA (basicConstraints cA=FALSE)",
            issuer.subject_string()
        )));
    }
    if let Some(max) = bc.path_len_constraint
        && intermediate_cas_below > max as usize
    {
        return Err(Error::CertParse(format!(
            "pathLenConstraint violated for issuer {:?}: allows {max} intermediate CA(s), found {intermediate_cas_below}",
            issuer.subject_string()
        )));
    }

    // keyUsage: if present, keyCertSign must be set.
    if let Some(ku_ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE) {
        let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
            .map_err(|e| Error::CertParse(format!("issuer keyUsage parse: {e}")))?;
        if !ku.key_cert_sign() {
            return Err(Error::CertParse(format!(
                "issuer {:?} keyUsage lacks keyCertSign",
                issuer.subject_string()
            )));
        }
    }
    Ok(())
}

/// Enforce that the signing (leaf) cert's `keyUsage`, when present, permits
/// signing — `digitalSignature` or `nonRepudiation`/`contentCommitment`. A cert
/// issued only for e.g. key-encipherment should not produce an accepted document
/// signature. Absent keyUsage → no constraint (permissive, per RFC 5280).
pub fn check_leaf_key_usage(leaf: &SignerCert) -> Result<()> {
    let Some(exts) = leaf.parsed.tbs_certificate.extensions.as_ref() else {
        return Ok(());
    };
    if let Some(ku_ext) = exts.iter().find(|e| e.extn_id == OID_KEY_USAGE) {
        let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
            .map_err(|e| Error::CertParse(format!("leaf keyUsage parse: {e}")))?;
        if !ku.digital_signature() && !ku.non_repudiation() {
            return Err(Error::CertParse(
                "signer cert keyUsage permits neither digitalSignature nor nonRepudiation".into(),
            ));
        }
    }
    Ok(())
}

fn same_subject_and_key(a: &SignerCert, b: &SignerCert) -> bool {
    a.parsed.tbs_certificate.subject == b.parsed.tbs_certificate.subject
        && a.parsed.tbs_certificate.subject_public_key_info
            == b.parsed.tbs_certificate.subject_public_key_info
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ca_out() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_ca/out")
    }

    /// `enforce_ca_constraints` accepts the CA certs and rejects the end-entity
    /// leaf (basicConstraints cA=FALSE) and a pathLen overflow. Skips when the
    /// test CA hasn't been generated (run tests/test_ca/gen-test-ca.sh).
    #[test]
    fn ca_constraints_enforced() {
        let dir = ca_out();
        if !dir.join("test-leaf.crt").exists() {
            eprintln!("test CA absent — run tests/test_ca/gen-test-ca.sh; skipping");
            return;
        }
        let leaf = SignerCert::from_file(&dir.join("test-leaf.crt")).unwrap();
        let ica = SignerCert::from_file(&dir.join("test-intermediate.crt")).unwrap();
        let root = SignerCert::from_file(&dir.join("test-root.crt")).unwrap();

        // CA certs pass with no intermediates below them.
        assert!(enforce_ca_constraints(&ica, 0).is_ok());
        assert!(enforce_ca_constraints(&root, 0).is_ok());

        // The leaf is an end-entity (cA=FALSE) — must be rejected as an issuer.
        assert!(
            enforce_ca_constraints(&leaf, 0).is_err(),
            "end-entity leaf must not validate as a CA"
        );

        // The intermediate has pathLenConstraint:0 — one intermediate CA below it
        // is a violation.
        assert!(
            enforce_ca_constraints(&ica, 1).is_err(),
            "pathLenConstraint:0 must reject an intermediate CA below it"
        );
    }
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
