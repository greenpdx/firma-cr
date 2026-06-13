// SPDX-License-Identifier: GPL-3.0-or-later
//! CAdES / CMS verification — detached signatures.
//!
//! Inverse of `crate::cades`.
//!
//! Flow:
//!   1. Parse ContentInfo → SignedData → first SignerInfo.
//!   2. Locate the signer cert in `signedData.certificates` via the
//!      SignerIdentifier (we only handle IssuerAndSerial today).
//!   3. Extract SignedAttributes; serialize them as SET OF (the form
//!      RFC 5652 §5.4 says is signed).
//!   4. Hash that with the signer's declared DigestAlgorithm, wrap
//!      in a PKCS#1 DigestInfo, RSA-verify against the signer cert's
//!      public key.
//!   5. Confirm the `messageDigest` signed attribute equals
//!      `digest(detached_content)`.
//!   6. Build + verify the cert chain to the trust root.
//!   7. Report `signingTime`, presence of `signature-time-stamp`
//!      unsigned attribute.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{OctetString, SetOfVec};
use der::{Decode, Encode, oid::ObjectIdentifier};
use rsa::Pkcs1v15Sign;
use rsa::sha2::{Sha256 as RsaSha256, Sha384 as RsaSha384, Sha512 as RsaSha512};
use x509_cert::attr::Attribute;

use crate::cert::SignerCert;
use crate::digest::HashAlgo;
use crate::error::{Error, Result};
use crate::verify::{SignerVerdict, VerifyOptions, VerifyReport, chain, tsa};

const OID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const OID_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
const OID_REVOCATION_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");
const OID_ARCHIVE_TIMESTAMP_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.27");
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.14");

/// Verify a detached CMS (`.p7s` bytes) against the original
/// `content` and a trust-root cert. Iterates every SignerInfo in
/// the SignedData; the returned report's `signers` list carries one
/// entry per SignerInfo. Top-level `ok` is the AND of every
/// per-signer `ok`.
pub fn verify_detached(
    p7s: &[u8],
    content: &[u8],
    trust_root: &SignerCert,
    opts: VerifyOptions,
) -> Result<VerifyReport> {
    // 1. Parse.
    let ci = ContentInfo::from_der(p7s)
        .map_err(|e| Error::Cms(format!("ContentInfo decode: {e}")))?;
    if ci.content_type != OID_SIGNED_DATA {
        return Err(Error::Cms(format!(
            "expected id-signedData, got {}",
            ci.content_type
        )));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Cms(format!("SignedData decode: {e}")))?;

    if sd.signer_infos.0.as_slice().is_empty() {
        return Err(Error::Cms("SignedData has no SignerInfo".into()));
    }

    // 2. Build cert list once — every SignerInfo searches it.
    let certs: Vec<SignerCert> = sd
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .as_slice()
                .iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(x) => {
                        let der = x.to_der().ok()?;
                        Some(SignerCert {
                            der,
                            parsed: x.clone(),
                        })
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    // 3. Per-signer verification.
    let mut signers: Vec<SignerVerdict> = Vec::new();
    for si in sd.signer_infos.0.as_slice() {
        let verdict = verify_one_signer(si, &sd, &certs, content, trust_root, opts)?;
        signers.push(verdict);
    }

    let overall_ok = signers.iter().all(|s| s.ok);
    let first = signers.first().cloned().unwrap_or_else(|| SignerVerdict {
        ok: false,
        signer_subject: None,
        signing_time: None,
        has_timestamp: false,
        timestamp: None,
        revocation: None,
        archive_timestamp: None,
        warnings: Vec::new(),
    });
    // For single-signer CMS, mirror the per-signer warnings to the
    // top-level Vec so pre-12b callers that read `report.warnings`
    // still see them. For multi-signer CMS the equivalent lives in
    // `signers[i].warnings` and the top-level Vec stays empty.
    let top_warnings = if signers.len() == 1 {
        signers[0].warnings.clone()
    } else {
        Vec::new()
    };
    Ok(VerifyReport {
        ok: overall_ok,
        signer_subject: first.signer_subject.clone(),
        signing_time: first.signing_time.clone(),
        has_timestamp: first.has_timestamp,
        timestamp: first.timestamp.clone(),
        revocation: first.revocation.clone(),
        archive_timestamp: first.archive_timestamp.clone(),
        warnings: top_warnings,
        signers,
    })
}

/// Verify a single SignerInfo against the shared content + cert
/// pool. Steps mirror the original verify_detached body: locate
/// signer cert, RSA-verify signedAttrs, check messageDigest, chain,
/// timestamp, revocation, archive timestamp. Each failure produces
/// a SignerVerdict with `ok = false` rather than propagating an
/// Err — Err is reserved for fatal parsing problems that prevent
/// any meaningful verdict.
fn verify_one_signer(
    si: &cms::signed_data::SignerInfo,
    sd: &SignedData,
    certs: &[SignerCert],
    content: &[u8],
    trust_root: &SignerCert,
    opts: VerifyOptions,
) -> Result<SignerVerdict> {
    let signer = match locate_signer(&si.sid, certs) {
        Ok(s) => s,
        Err(e) => {
            return Ok(SignerVerdict {
                ok: false,
                signer_subject: None,
                signing_time: None,
                has_timestamp: false,
                timestamp: None,
                revocation: None,
                archive_timestamp: None,
                warnings: vec![format!("{e}")],
            });
        }
    };
    let mut warnings: Vec<String> = Vec::new();

    let signed_attrs = match si.signed_attrs.as_ref() {
        Some(s) => s,
        None => {
            return Ok(SignerVerdict {
                ok: false,
                signer_subject: Some(signer.subject_string()),
                signing_time: None,
                has_timestamp: false,
                timestamp: None,
                revocation: None,
                archive_timestamp: None,
                warnings: vec!["SignerInfo has no SignedAttributes".into()],
            });
        }
    };
    let to_verify_bytes = signed_attrs
        .to_der()
        .map_err(|e| Error::Cms(format!("re-encode SignedAttributes: {e}")))?;

    let signer_digest_algo = HashAlgo::from_oid_str(&si.digest_alg.oid.to_string())
        .ok_or_else(|| {
            Error::Cms(format!(
                "unsupported digest algorithm: {}",
                si.digest_alg.oid
            ))
        })?;
    let attrs_hash = signer_digest_algo.hash(&to_verify_bytes);
    let pk = chain::extract_rsa_pubkey(signer)?;
    let sig_bytes = si.signature.as_bytes();
    let verify_result = match signer_digest_algo {
        HashAlgo::Sha256 => {
            pk.verify(Pkcs1v15Sign::new::<RsaSha256>(), &attrs_hash, sig_bytes)
        }
        HashAlgo::Sha384 => {
            pk.verify(Pkcs1v15Sign::new::<RsaSha384>(), &attrs_hash, sig_bytes)
        }
        HashAlgo::Sha512 => {
            pk.verify(Pkcs1v15Sign::new::<RsaSha512>(), &attrs_hash, sig_bytes)
        }
    };
    if let Err(e) = verify_result {
        return Ok(SignerVerdict {
            ok: false,
            signer_subject: Some(signer.subject_string()),
            signing_time: extract_signing_time(signed_attrs),
            has_timestamp: has_timestamp(si.unsigned_attrs.as_ref()),
            timestamp: None,
            revocation: None,
            archive_timestamp: None,
            warnings: vec![format!("RSA verification failed: {e}")],
        });
    }

    // messageDigest signed attribute must equal H(content).
    let md_attr = find_attr(signed_attrs, &OID_MESSAGE_DIGEST).ok_or_else(|| {
        Error::Cms("messageDigest signed attribute missing".into())
    })?;
    let md_value = md_attr.values.as_slice().first().ok_or_else(|| {
        Error::Cms("messageDigest attribute has empty value set".into())
    })?;
    let md_bytes = der::asn1::OctetString::from_der(
        &md_value.to_der().map_err(|e| Error::Cms(format!("md to_der: {e}")))?,
    )
    .map_err(|e| Error::Cms(format!("messageDigest OctetString decode: {e}")))?;
    let expected_md = signer_digest_algo.hash(content);
    if md_bytes.as_bytes() != expected_md.as_slice() {
        return Ok(SignerVerdict {
            ok: false,
            signer_subject: Some(signer.subject_string()),
            signing_time: extract_signing_time(signed_attrs),
            has_timestamp: has_timestamp(si.unsigned_attrs.as_ref()),
            timestamp: None,
            revocation: None,
            archive_timestamp: None,
            warnings: vec!["messageDigest != hash(content)".into()],
        });
    }

    // Signer cert validity window: only applied when the caller
    // supplies an explicit validation_time. When None we trust
    // the embedded signingTime + timestamp evidence and skip the
    // check, matching pre-12c behavior.
    if let Some(at) = opts.validation_time {
        if let Err(e) = chain::check_validity_at(signer, at) {
            return Ok(SignerVerdict {
                ok: false,
                signer_subject: Some(signer.subject_string()),
                signing_time: extract_signing_time(signed_attrs),
                has_timestamp: has_timestamp(si.unsigned_attrs.as_ref()),
                timestamp: None,
                revocation: None,
                archive_timestamp: None,
                warnings: vec![format!("signer cert validity: {e}")],
            });
        }
    }

    // Walk the chain.
    let intermediate_refs: Vec<&SignerCert> =
        certs.iter().filter(|c| !std::ptr::eq(*c, signer)).collect();
    let chain_result = chain::build_and_verify_chain(signer, &intermediate_refs, &[trust_root]);
    if let Err(e) = chain_result {
        warnings.push(format!("chain build failed: {e}"));
        return Ok(SignerVerdict {
            ok: false,
            signer_subject: Some(signer.subject_string()),
            signing_time: extract_signing_time(signed_attrs),
            has_timestamp: has_timestamp(si.unsigned_attrs.as_ref()),
            timestamp: None,
            revocation: None,
            archive_timestamp: None,
            warnings,
        });
    }

    // Embedded RFC 3161 TimeStampToken (CAdES-T) over the OUTER
    // SignerInfo.signature bytes.
    let mut timestamp_verdict: Option<tsa::TimestampVerdict> = None;
    let mut ok = true;
    if let Some(unsigned) = si.unsigned_attrs.as_ref() {
        if let Some(ts_attr) = find_attr(unsigned, &OID_SIGNATURE_TIME_STAMP_TOKEN) {
            let token_value = ts_attr.values.as_slice().first().ok_or_else(|| {
                Error::Cms("signature-time-stamp attribute has empty value set".into())
            })?;
            // The attribute value is a `TimeStampToken` (a CMS
            // ContentInfo) directly. Re-encode the `Any` to its DER
            // bytes for the TSA verifier.
            let token_der = token_value
                .to_der()
                .map_err(|e| Error::Cms(format!("ts token to_der: {e}")))?;
            let v = tsa::verify_token(&token_der, sig_bytes, trust_root, opts.cert_internal)?;
            if !v.ok {
                ok = false;
                warnings.push("embedded TimeStampToken failed verification".into());
            }
            timestamp_verdict = Some(v);
        }
    }

    // Embedded -LT revocation values (CAdES-LT).
    let mut revocation_verdict = None;
    if let Some(unsigned) = si.unsigned_attrs.as_ref() {
        if let Some(rv_attr) = find_attr(unsigned, &OID_REVOCATION_VALUES) {
            let rv_value = rv_attr.values.as_slice().first().ok_or_else(|| {
                Error::Cms("revocation-values attribute empty".into())
            })?;
            let rv_der = rv_value
                .to_der()
                .map_err(|e| Error::Cms(format!("rv attr to_der: {e}")))?;
            let parsed =
                crate::verify::revocation::parse_revocation_values_seq(&rv_der)?;
            // Find issuer in intermediate_refs to walk OCSP CertID.
            let issuer = intermediate_refs
                .iter()
                .find(|c| c.parsed.tbs_certificate.subject == signer.parsed.tbs_certificate.issuer)
                .copied()
                .unwrap_or(trust_root);
            let v = crate::verify::revocation::validate_signer(
                &parsed,
                signer,
                issuer,
                &intermediate_refs,
                trust_root,
                opts.cert_internal,
            );
            if !v.ok {
                ok = false;
                warnings.push("embedded revocation-values rejected signer".into());
            }
            revocation_verdict = Some(v);
        }
    }
    // Revocation policy: caller may require embedded revocation data to be present.
    if opts.require_revocation && revocation_verdict.is_none() {
        ok = false;
        warnings.push("revocation data required (require_revocation) but none embedded".into());
    }

    // Embedded archive-time-stamp-v1 (CAdES-LTA).
    let mut archive_timestamp_verdict: Option<tsa::TimestampVerdict> = None;
    if let Some(unsigned) = si.unsigned_attrs.as_ref() {
        if let Some(ats_attr) = find_attr(unsigned, &OID_ARCHIVE_TIMESTAMP_V1) {
            let ats_value = ats_attr.values.as_slice().first().ok_or_else(|| {
                Error::Cms("archive-time-stamp attribute empty".into())
            })?;
            let ats_der = ats_value
                .to_der()
                .map_err(|e| Error::Cms(format!("ats attr to_der: {e}")))?;
            let imprint = reconstruct_archive_imprint(sd, si, content)?;
            let v = tsa::verify_token(&ats_der, &imprint, trust_root, opts.cert_internal)?;
            if !v.ok {
                ok = false;
                warnings.push("embedded archive timestamp failed verification".into());
            }
            archive_timestamp_verdict = Some(v);
        }
    }

    Ok(SignerVerdict {
        ok,
        signer_subject: Some(signer.subject_string()),
        signing_time: extract_signing_time(signed_attrs),
        has_timestamp: has_timestamp(si.unsigned_attrs.as_ref()),
        timestamp: timestamp_verdict,
        revocation: revocation_verdict,
        archive_timestamp: archive_timestamp_verdict,
        warnings,
    })
}

fn locate_signer<'a>(
    sid: &SignerIdentifier,
    certs: &'a [SignerCert],
) -> Result<&'a SignerCert> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer,
            serial_number,
        }) => {
            for c in certs {
                if &c.parsed.tbs_certificate.issuer == issuer
                    && &c.parsed.tbs_certificate.serial_number == serial_number
                {
                    return Ok(c);
                }
            }
            Err(Error::Cms(
                "no cert in SignedData.certificates matches SignerIdentifier issuer+serial".into(),
            ))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // ski.0 is the OctetString carrying the key-identifier
            // bytes (same form as the X.509 SKI extension's inner
            // value).
            let want = ski.0.as_bytes();
            for c in certs {
                if let Some(actual) = cert_subject_key_id(c) {
                    if actual.as_slice() == want {
                        return Ok(c);
                    }
                }
            }
            Err(Error::Cms(
                "no cert in SignedData.certificates matches SignerIdentifier SubjectKeyIdentifier"
                    .into(),
            ))
        }
    }
}

/// Pull the SubjectKeyIdentifier (OID 2.5.29.14) bytes out of a
/// cert's extensions. Returns None if the extension isn't present.
fn cert_subject_key_id(c: &SignerCert) -> Option<Vec<u8>> {
    let exts = c.parsed.tbs_certificate.extensions.as_ref()?;
    for e in exts {
        if e.extn_id == OID_SUBJECT_KEY_IDENTIFIER {
            // The extension's extn_value carries the raw DER of a
            // SubjectKeyIdentifier ::= OCTET STRING (RFC 5280
            // §4.2.1.2). Decode that wrapper to get the actual
            // key-identifier bytes.
            let raw = e.extn_value.as_bytes();
            if let Ok(inner) = OctetString::from_der(raw) {
                return Some(inner.as_bytes().to_vec());
            }
            return None;
        }
    }
    None
}

fn find_attr<'a>(
    attrs: &'a SetOfVec<Attribute>,
    oid: &ObjectIdentifier,
) -> Option<&'a Attribute> {
    attrs.as_slice().iter().find(|a| &a.oid == oid)
}

fn extract_signing_time(attrs: &SetOfVec<Attribute>) -> Option<String> {
    let a = find_attr(attrs, &OID_SIGNING_TIME)?;
    let v = a.values.as_slice().first()?;
    let raw = v.to_der().ok()?;
    // Try GeneralizedTime first, then UTCTime. Neither type
    // implements Display, so we render via Debug which gives a
    // structured timestamp.
    if let Ok(gt) = der::asn1::GeneralizedTime::from_der(&raw) {
        return Some(format!("{gt:?}"));
    }
    if let Ok(ut) = der::asn1::UtcTime::from_der(&raw) {
        return Some(format!("{ut:?}"));
    }
    None
}

fn has_timestamp(unsigned: Option<&SetOfVec<Attribute>>) -> bool {
    match unsigned {
        Some(s) => s
            .as_slice()
            .iter()
            .any(|a| a.oid == OID_SIGNATURE_TIME_STAMP_TOKEN),
        None => false,
    }
}

/// Rebuild the byte sequence the signer fed into the archive
/// timestamp's message imprint (per `crate::cades::build_archive_imprint`)
/// so we can confirm the embedded token's TSTInfo really covers
/// what the signer claims.
fn reconstruct_archive_imprint(
    sd: &SignedData,
    si: &cms::signed_data::SignerInfo,
    detached_content: &[u8],
) -> Result<Vec<u8>> {
    let cert_set_der = match sd.certificates.as_ref() {
        Some(cs) => cs
            .to_der()
            .map_err(|e| Error::Cms(format!("cert set to_der: {e}")))?,
        None => Vec::new(),
    };
    let crls_der = Vec::new(); // we never embed crls under SignedData.crls
    // Strip the archive-time-stamp attribute (and any later additions
    // beyond it) so the SignerInfo bytes match what the signer hashed.
    let pre_ats = strip_archive_timestamp(si)?;
    Ok(crate::cades::build_archive_imprint(
        detached_content,
        &cert_set_der,
        &crls_der,
        &pre_ats,
    ))
}

/// Encode a copy of `si` with the archive-time-stamp attribute (and
/// any unsigned attrs that sort after it) removed, matching the bytes
/// the signer hashed before attaching the archive timestamp.
fn strip_archive_timestamp(si: &cms::signed_data::SignerInfo) -> Result<Vec<u8>> {
    let mut clone = si.clone();
    if let Some(unsigned) = clone.unsigned_attrs.as_ref() {
        let filtered: Vec<Attribute> = unsigned
            .as_slice()
            .iter()
            .filter(|a| a.oid != OID_ARCHIVE_TIMESTAMP_V1)
            .cloned()
            .collect();
        clone.unsigned_attrs = if filtered.is_empty() {
            None
        } else {
            Some(
                SetOfVec::try_from(filtered)
                    .map_err(|e| Error::Cms(format!("strip ats SET: {e}")))?,
            )
        };
    }
    clone
        .to_der()
        .map_err(|e| Error::Cms(format!("SignerInfo without ATS to_der: {e}")))
}

