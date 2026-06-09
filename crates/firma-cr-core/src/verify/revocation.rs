//! Verify embedded -LT revocation values.
//!
//! Given the bytes carried by the `id-aa-ets-revocationValues`
//! unsigned attribute (CAdES/PAdES) or the `<xades:RevocationValues>`
//! element (XAdES), parse the embedded OCSP responses and CRLs and
//! confirm the signer cert is reported `good` (OCSP) and / or absent
//! from any CRL.

use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use rsa::Pkcs1v15Sign;
use rsa::sha2::{Sha256 as RsaSha256, Sha384 as RsaSha384, Sha512 as RsaSha512};
use sha1::{Digest as _, Sha1};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_ocsp::{BasicOcspResponse, CertId, CertStatus, ResponderId};

use crate::cert::SignerCert;
use crate::error::{Error, Result};

/// X.509 `id-ce-extKeyUsage` extension OID (RFC 5280 §4.2.1.12).
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// `id-kp-OCSPSigning` — required EKU on a delegated OCSP signer
/// per RFC 6960 §4.2.2.2.
const OID_KP_OCSP_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

/// What an `id-aa-ets-revocationValues` attribute reduced to.
#[derive(Default, Debug, Clone)]
pub struct ParsedRevocationValues {
    pub basic_ocsp_responses: Vec<BasicOcspResponse>,
    pub crls: Vec<CertificateList>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RevocationVerdict {
    pub ok: bool,
    pub ocsp_status: Option<String>,
    pub warnings: Vec<String>,
}

/// Decode the body bytes of the `RevocationValues` SEQUENCE.
///
/// ```text
/// RevocationValues ::= SEQUENCE {
///   crlVals  [0] EXPLICIT SEQUENCE OF CertificateList OPTIONAL,
///   ocspVals [1] EXPLICIT SEQUENCE OF BasicOCSPResponse OPTIONAL,
///   otherRevVals ... (ignored)
/// }
/// ```
///
/// `bytes` is the full SEQUENCE DER, including the outer header.
pub fn parse_revocation_values_seq(bytes: &[u8]) -> Result<ParsedRevocationValues> {
    let (outer, _) = read_tlv(bytes)?;
    if outer.tag != 0x30 {
        return Err(Error::Cms(format!(
            "RevocationValues not SEQUENCE (tag {:#x})",
            outer.tag
        )));
    }
    let mut out = ParsedRevocationValues::default();
    let mut cur = outer.value;
    while !cur.is_empty() {
        let (tlv, rest) = read_tlv(cur)?;
        cur = rest;
        match tlv.tag {
            // [0] EXPLICIT SEQUENCE OF CertificateList
            0xA0 => {
                let (inner_seq, _) = read_tlv(tlv.value)?;
                let mut body = inner_seq.value;
                while !body.is_empty() {
                    let (one, r) = read_tlv(body)?;
                    let crl = CertificateList::from_der(&reserialize(one.tag, one.value))
                        .map_err(|e| Error::Crl(format!("crl decode: {e}")))?;
                    out.crls.push(crl);
                    body = r;
                }
            }
            // [1] EXPLICIT SEQUENCE OF BasicOCSPResponse
            0xA1 => {
                let (inner_seq, _) = read_tlv(tlv.value)?;
                let mut body = inner_seq.value;
                while !body.is_empty() {
                    let (one, r) = read_tlv(body)?;
                    let bocsp =
                        BasicOcspResponse::from_der(&reserialize(one.tag, one.value))
                            .map_err(|e| Error::Ocsp(format!("basic decode: {e}")))?;
                    out.basic_ocsp_responses.push(bocsp);
                    body = r;
                }
            }
            _ => {} // ignore otherRevVals etc.
        }
    }
    Ok(out)
}

/// Re-emit the original DER bytes for a TLV the walker peeled apart.
fn reserialize(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.len() + 4);
    buf.push(tag);
    let n = value.len();
    if n < 0x80 {
        buf.push(n as u8);
    } else if n <= 0xFF {
        buf.push(0x81);
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0x82);
        buf.push((n >> 8) as u8);
        buf.push((n & 0xFF) as u8);
    } else {
        buf.push(0x83);
        buf.push((n >> 16) as u8);
        buf.push((n >> 8) as u8);
        buf.push((n & 0xFF) as u8);
    }
    buf.extend_from_slice(value);
    buf
}

/// Confirm the signer cert is in good standing per the embedded
/// revocation data. Returns `ok = true` iff at least one source
/// (OCSP or CRL) covers the signer cert and reports it not revoked.
/// If no source covers the signer cert, `ok = false` with a warning
/// — embedded -LT data must speak to the signer.
///
/// Each embedded BasicOcspResponse is fully verified:
///   1. Recover the OCSP signer cert (RFC 6960 §4.2.2) — either the
///      issuer of `signer` (when ResponderId matches the issuer) or
///      a delegated responder cert embedded under the OCSP response's
///      `certs` field.
///   2. RSA-verify the BasicOcspResponse signature over
///      `tbsResponseData.to_der()`.
///   3. Chain-build the OCSP signer cert against `trust_root`. With
///      `cert_internal: true` a chain-anchoring failure is demoted
///      to a warning instead of rejecting the response.
pub fn validate_signer(
    rev: &ParsedRevocationValues,
    signer: &SignerCert,
    issuer: &SignerCert,
    intermediates: &[&SignerCert],
    trust_root: &SignerCert,
    cert_internal: bool,
) -> RevocationVerdict {
    let mut warnings: Vec<String> = Vec::new();
    let mut ocsp_status_text: Option<String> = None;
    let mut covered_by_ocsp = false;
    let mut covered_by_crl = false;
    let mut revoked = false;

    // ---- OCSP ----
    let want_certid_der = CertId::from_cert::<Sha1>(&issuer.parsed, &signer.parsed)
        .ok()
        .and_then(|c| c.to_der().ok());

    'next_ocsp: for bocsp in &rev.basic_ocsp_responses {
        // 1. Resolve OCSP signer cert.
        let ocsp_signer = match resolve_ocsp_signer(bocsp, issuer) {
            Some(s) => s,
            None => {
                warnings.push(
                    "OCSP ResponderId matches neither issuer nor any embedded cert".into(),
                );
                continue 'next_ocsp;
            }
        };
        // 2. Verify OCSP signature (always, regardless of cert_internal).
        if let Err(e) = verify_basic_ocsp_signature(bocsp, &ocsp_signer) {
            warnings.push(format!("OCSP signature verification failed: {e}"));
            continue 'next_ocsp;
        }
        // 3. Delegated-signer EKU check (RFC 6960 §4.2.2.2). When
        //    the responder cert is not the issuer of the cert being
        //    checked, it MUST carry id-kp-OCSPSigning in its
        //    ExtendedKeyUsage extension — otherwise an attacker
        //    could mint a non-OCSP cert under a trusted CA and use
        //    it to forge revocation answers. Skip when responder ==
        //    issuer, which the spec implicitly allows.
        if ocsp_signer.der != issuer.der && !has_ocsp_signing_eku(&ocsp_signer) {
            warnings.push(
                "delegated OCSP signer missing id-kp-OCSPSigning EKU".into(),
            );
            continue 'next_ocsp;
        }
        // 4. Chain-check the responder. Skip when responder == issuer
        //    since the outer verifier already validated the issuer's
        //    path through to trust_root.
        if ocsp_signer.der != issuer.der {
            // Pass `issuer` as an intermediate so a delegated responder
            // (signed by the issuer) finds its parent.
            let mut full_intermediates: Vec<&SignerCert> = intermediates.to_vec();
            full_intermediates.push(issuer);
            match crate::verify::chain::build_and_verify_chain(
                &ocsp_signer,
                &full_intermediates,
                &[trust_root],
            ) {
                Ok(_) => {}
                Err(e) => {
                    if cert_internal {
                        warnings.push(format!(
                            "OCSP responder chain not anchored (cert_internal): {e}"
                        ));
                    } else {
                        warnings.push(format!("OCSP responder chain build failed: {e}"));
                        continue 'next_ocsp;
                    }
                }
            }
        }
        // 4. Scan the responses' singleResponses against our signer.
        let want_der = match &want_certid_der {
            Some(d) => d.as_slice(),
            None => continue 'next_ocsp,
        };
        for sr in &bocsp.tbs_response_data.responses {
            let id_der = match sr.cert_id.to_der() {
                Ok(d) => d,
                Err(_) => continue,
            };
            if id_der != want_der {
                continue;
            }
            covered_by_ocsp = true;
            match &sr.cert_status {
                CertStatus::Good(_) => {
                    ocsp_status_text = Some("good".into());
                }
                CertStatus::Revoked(_) => {
                    ocsp_status_text = Some("revoked".into());
                    revoked = true;
                }
                CertStatus::Unknown(_) => {
                    ocsp_status_text = Some("unknown".into());
                    warnings.push("OCSP responder returned unknown".into());
                }
            }
        }
    }

    // ---- CRL ----
    'next_crl: for crl in &rev.crls {
        // Only consider CRLs whose issuer matches our signer's
        // issuer — anything else can't speak to the signer cert.
        if crl.tbs_cert_list.issuer != signer.parsed.tbs_certificate.issuer {
            continue;
        }
        // 1. Resolve the cert that signed this CRL. The CRL's
        //    `tbs_cert_list.issuer` names the signing CA; usually it
        //    is exactly the signer's issuer cert we already have, but
        //    we still scan intermediates + trust_root to cover the
        //    case where the CRL is from a delegated CRL issuer.
        let crl_issuer = if crl.tbs_cert_list.issuer == issuer.parsed.tbs_certificate.subject
        {
            issuer
        } else {
            let needed = &crl.tbs_cert_list.issuer;
            let found = intermediates
                .iter()
                .copied()
                .chain(std::iter::once(trust_root))
                .find(|c| c.parsed.tbs_certificate.subject == *needed);
            match found {
                Some(c) => c,
                None => {
                    warnings.push(
                        "CRL issuer cert not found in intermediates or trust root"
                            .into(),
                    );
                    continue 'next_crl;
                }
            }
        };
        // 2. RSA-verify the CRL's own signature over its
        //    `tbsCertList` bytes. A forged CRL would fail this even
        //    if its body parses cleanly.
        if let Err(e) = verify_crl_signature(crl, crl_issuer) {
            warnings.push(format!("CRL signature verification failed: {e}"));
            continue 'next_crl;
        }
        // 3. Chain-check the CRL issuer cert (skip when it's the
        //    signer's issuer, which the outer verifier already
        //    chained). Same cert_internal semantics as the OCSP
        //    responder path.
        if crl_issuer.der != issuer.der {
            let mut full_intermediates: Vec<&SignerCert> = intermediates.to_vec();
            full_intermediates.push(issuer);
            match crate::verify::chain::build_and_verify_chain(
                crl_issuer,
                &full_intermediates,
                &[trust_root],
            ) {
                Ok(_) => {}
                Err(e) => {
                    if cert_internal {
                        warnings.push(format!(
                            "CRL issuer chain not anchored (cert_internal): {e}"
                        ));
                    } else {
                        warnings.push(format!("CRL issuer chain build failed: {e}"));
                        continue 'next_crl;
                    }
                }
            }
        }
        // 4. Only NOW the CRL is trusted enough to consult.
        covered_by_crl = true;
        if let Some(revoked_list) = &crl.tbs_cert_list.revoked_certificates {
            if revoked_list
                .iter()
                .any(|r| r.serial_number == signer.parsed.tbs_certificate.serial_number)
            {
                revoked = true;
                warnings.push("signer cert is on CRL".into());
            }
        }
    }

    if revoked {
        return RevocationVerdict {
            ok: false,
            ocsp_status: ocsp_status_text,
            warnings,
        };
    }
    if !covered_by_ocsp && !covered_by_crl {
        warnings.push(
            "embedded revocation-values has no OCSP/CRL data covering the signer cert"
                .into(),
        );
        return RevocationVerdict {
            ok: false,
            ocsp_status: ocsp_status_text,
            warnings,
        };
    }
    RevocationVerdict {
        ok: true,
        ocsp_status: ocsp_status_text,
        warnings,
    }
}

/// Locate the cert that signed `bocsp` per RFC 6960 §4.2.2.
/// First checks whether the issuer of `signer` is the OCSP signer
/// (the canonical case), then walks `bocsp.certs` for a delegated
/// responder cert matching the ResponderId.
fn resolve_ocsp_signer(
    bocsp: &BasicOcspResponse,
    issuer: &SignerCert,
) -> Option<SignerCert> {
    let rid = &bocsp.tbs_response_data.responder_id;
    if responder_matches(rid, issuer) {
        return Some(issuer.clone());
    }
    let certs = bocsp.certs.as_ref()?;
    for c in certs {
        let der = c.to_der().ok()?;
        let candidate = SignerCert {
            der,
            parsed: c.clone(),
        };
        if responder_matches(rid, &candidate) {
            return Some(candidate);
        }
    }
    None
}

/// True iff `cert` carries `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9)
/// inside its ExtendedKeyUsage extension. RFC 6960 §4.2.2.2 makes
/// this mandatory for a delegated OCSP responder cert; without it,
/// the responder is forbidden from issuing OCSP responses even if
/// it chains to the trust root.
fn has_ocsp_signing_eku(cert: &SignerCert) -> bool {
    let exts = match cert.parsed.tbs_certificate.extensions.as_ref() {
        Some(e) => e,
        None => return false,
    };
    let ext = match exts.iter().find(|e| e.extn_id == OID_EXT_KEY_USAGE) {
        Some(e) => e,
        None => return false,
    };
    let eku = match ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
        Ok(e) => e,
        Err(_) => return false,
    };
    eku.0.iter().any(|oid| *oid == OID_KP_OCSP_SIGNING)
}

/// True iff `cert` matches the given OCSP ResponderId. For
/// `ByName`, compares the responder Name field to the cert's
/// subject DN. For `ByKey`, compares the SHA-1 of the cert's
/// `subjectPublicKey` BIT STRING contents (RFC 6960 §4.2.2.3).
fn responder_matches(rid: &ResponderId, cert: &SignerCert) -> bool {
    match rid {
        ResponderId::ByName(name) => *name == cert.parsed.tbs_certificate.subject,
        ResponderId::ByKey(key_hash) => {
            let bits = match cert
                .parsed
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
            {
                Some(b) => b,
                None => return false,
            };
            let h = Sha1::digest(bits);
            key_hash.as_bytes() == h.as_slice()
        }
    }
}

/// RSA-verify a BasicOcspResponse: hash `tbsResponseData.to_der()`
/// with the algorithm from `signature_algorithm.oid`, RSA-verify
/// against `signer`'s public key.
fn verify_basic_ocsp_signature(
    bocsp: &BasicOcspResponse,
    signer: &SignerCert,
) -> Result<()> {
    let tbs_der = bocsp
        .tbs_response_data
        .to_der()
        .map_err(|e| Error::Ocsp(format!("tbsResponseData to_der: {e}")))?;
    let sig_bytes = bocsp
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Ocsp("OCSP signature BIT STRING unaligned".into()))?;
    let pk = crate::verify::chain::extract_rsa_pubkey(signer)?;
    let alg_oid = bocsp.signature_algorithm.oid.to_string();
    let result = match alg_oid.as_str() {
        // sha256WithRSAEncryption
        "1.2.840.113549.1.1.11" => {
            let h = Sha256::digest(&tbs_der);
            pk.verify(Pkcs1v15Sign::new::<RsaSha256>(), &h, sig_bytes)
        }
        // sha384WithRSAEncryption
        "1.2.840.113549.1.1.12" => {
            let h = Sha384::digest(&tbs_der);
            pk.verify(Pkcs1v15Sign::new::<RsaSha384>(), &h, sig_bytes)
        }
        // sha512WithRSAEncryption
        "1.2.840.113549.1.1.13" => {
            let h = Sha512::digest(&tbs_der);
            pk.verify(Pkcs1v15Sign::new::<RsaSha512>(), &h, sig_bytes)
        }
        other => {
            return Err(Error::Ocsp(format!(
                "unsupported OCSP signature algorithm: {other}"
            )))
        }
    };
    result.map_err(|e| Error::Ocsp(format!("RSA verify: {e}")))
}

/// RSA-verify a `CertificateList`: hash `tbsCertList.to_der()`
/// with the algorithm from `signatureAlgorithm.oid`, RSA-verify
/// against `issuer`'s public key. RFC 5280 §5.1 requires the
/// signature to be over the encoded TbsCertList.
fn verify_crl_signature(
    crl: &CertificateList,
    issuer: &SignerCert,
) -> Result<()> {
    let tbs_der = crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| Error::Crl(format!("tbsCertList to_der: {e}")))?;
    let sig_bytes = crl
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Crl("CRL signature BIT STRING unaligned".into()))?;
    let pk = crate::verify::chain::extract_rsa_pubkey(issuer)?;
    let alg_oid = crl.signature_algorithm.oid.to_string();
    let result = match alg_oid.as_str() {
        // sha256WithRSAEncryption
        "1.2.840.113549.1.1.11" => {
            let h = Sha256::digest(&tbs_der);
            pk.verify(Pkcs1v15Sign::new::<RsaSha256>(), &h, sig_bytes)
        }
        // sha384WithRSAEncryption
        "1.2.840.113549.1.1.12" => {
            let h = Sha384::digest(&tbs_der);
            pk.verify(Pkcs1v15Sign::new::<RsaSha384>(), &h, sig_bytes)
        }
        // sha512WithRSAEncryption
        "1.2.840.113549.1.1.13" => {
            let h = Sha512::digest(&tbs_der);
            pk.verify(Pkcs1v15Sign::new::<RsaSha512>(), &h, sig_bytes)
        }
        other => {
            return Err(Error::Crl(format!(
                "unsupported CRL signature algorithm: {other}"
            )))
        }
    };
    result.map_err(|e| Error::Crl(format!("RSA verify: {e}")))
}

// ---- minimal DER TLV walker ----

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_tlv(b: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if b.len() < 2 {
        return Err(Error::Cms("RV TLV truncated".into()));
    }
    let tag = b[0];
    let l = b[1];
    let (len, hdr) = if l < 0x80 {
        (l as usize, 2)
    } else {
        let n = (l & 0x7F) as usize;
        if n == 0 || n > 4 || b.len() < 2 + n {
            return Err(Error::Cms("RV TLV bad length".into()));
        }
        let mut v = 0usize;
        for &x in &b[2..2 + n] {
            v = (v << 8) | x as usize;
        }
        (v, 2 + n)
    };
    if b.len() < hdr + len {
        return Err(Error::Cms("RV TLV exceeds input".into()));
    }
    Ok((
        Tlv {
            tag,
            value: &b[hdr..hdr + len],
        },
        &b[hdr + len..],
    ))
}
