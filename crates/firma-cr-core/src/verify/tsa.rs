// SPDX-License-Identifier: GPL-3.0-or-later
//! RFC 3161 TimeStampToken verification.
//!
//! A TimeStampToken is itself a CMS `SignedData` whose
//! `encapContentInfo` carries `id-ct-TSTInfo` content (the TSTInfo
//! SEQUENCE). To validate a token we:
//!
//!   1. Decode the outer ContentInfo and confirm it's id-signedData.
//!   2. Confirm the inner eContentType is id-ct-TSTInfo and pull out
//!      the eContent OCTET STRING (the TSTInfo bytes).
//!   3. Parse TSTInfo to read `messageImprint.hashAlgorithm` and
//!      `messageImprint.hashedMessage` (plus `genTime` for reporting).
//!   4. Compare `hashedMessage` against `hash(expected_imprint_payload)`
//!      using the imprint's declared algorithm.
//!   5. Verify the token's own single SignerInfo: re-encode
//!      `signedAttrs` as SET OF, hash it, RSA-verify against the TSA
//!      cert's public key. Also confirm the `messageDigest` signed
//!      attr equals `hash(eContent)`.
//!   6. Chain-build the TSA cert against `trust_root`. With
//!      `cert_internal: true` an anchoring failure is demoted to a
//!      warning.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::SetOfVec;
use der::{Decode, Encode, oid::ObjectIdentifier};
use rsa::Pkcs1v15Sign;
use rsa::sha2::{Sha256 as RsaSha256, Sha384 as RsaSha384, Sha512 as RsaSha512};
use x509_cert::attr::Attribute;

use crate::cert::SignerCert;
use crate::digest::HashAlgo;
use crate::error::{Error, Result};
use crate::verify::chain;

const OID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// Result of verifying one TimeStampToken.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimestampVerdict {
    pub ok: bool,
    /// TSA cert subject distinguished name (best-effort).
    pub tsa_subject: Option<String>,
    /// Human-readable GeneralizedTime from `TSTInfo.genTime`.
    pub gen_time: Option<String>,
    pub warnings: Vec<String>,
}

/// Verify `token_der` (a CMS ContentInfo carrying a TimeStampToken).
/// `expected_imprint_payload` is the data the signer asked the TSA
/// to timestamp — for CAdES-T it's the outer `SignerInfo.signature`
/// bytes; for XAdES-T it's the Exclusive-C14N of the
/// `<ds:SignatureValue>` element.
///
/// `cert_internal: true` switches TSA-chain-anchoring failure from
/// hard-fail to warning, so the timestamp is treated as internally
/// consistent even if its TSA root isn't in `trust_root`'s chain.
pub fn verify_token(
    token_der: &[u8],
    expected_imprint_payload: &[u8],
    trust_root: &SignerCert,
    cert_internal: bool,
) -> Result<TimestampVerdict> {
    // 1. Outer ContentInfo.
    let ci = ContentInfo::from_der(token_der)
        .map_err(|e| Error::Tsa(format!("token ContentInfo decode: {e}")))?;
    if ci.content_type != OID_SIGNED_DATA {
        return Ok(TimestampVerdict::fail(format!(
            "TimeStampToken contentType is {}, expected id-signedData",
            ci.content_type
        )));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Tsa(format!("token SignedData decode: {e}")))?;

    // 2. encapContentInfo must carry TSTInfo bytes.
    if sd.encap_content_info.econtent_type != OID_ID_CT_TST_INFO {
        return Ok(TimestampVerdict::fail(format!(
            "token eContentType is {}, expected id-ct-TSTInfo",
            sd.encap_content_info.econtent_type
        )));
    }
    let econtent_any = sd.encap_content_info.econtent.as_ref().ok_or_else(|| {
        Error::Tsa("token encapContentInfo has no eContent".into())
    })?;
    // eContent is wrapped as `[0] EXPLICIT OCTET STRING` in the CMS
    // structure; the `cms` crate decodes that EXPLICIT layer for us,
    // so `econtent.value()` gives us the inner OCTET STRING's bytes
    // (the TSTInfo DER).
    let econtent_raw = econtent_any.value();
    let tst_info_der = der::asn1::OctetString::from_der(
        &wrap_explicit(econtent_raw, 0x04)?,
    )
    .map(|os| os.as_bytes().to_vec())
    .or_else(|_| {
        // Some encoders skip the inner OCTET STRING wrapper and just
        // place the TSTInfo SEQUENCE inline. Accept either.
        Ok::<Vec<u8>, Error>(econtent_raw.to_vec())
    })?;

    // 3. TSTInfo: extract messageImprint + genTime.
    let tst_info = parse_tst_info(&tst_info_der)?;

    // 4. Imprint check.
    let imprint_algo =
        HashAlgo::from_oid_str(&tst_info.imprint_algo_oid).ok_or_else(|| {
            Error::Tsa(format!(
                "unsupported messageImprint hash OID: {}",
                tst_info.imprint_algo_oid
            ))
        })?;
    let want_imprint = imprint_algo.hash(expected_imprint_payload);
    if tst_info.imprint_hash != want_imprint {
        return Ok(TimestampVerdict::fail(
            "messageImprint != hash(expected_payload)".into(),
        ));
    }

    // 5. Inner SignerInfo verification.
    let si = sd.signer_infos.0.as_slice().first().ok_or_else(|| {
        Error::Tsa("token SignedData has no SignerInfo".into())
    })?;
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
    let tsa_cert = locate_signer_in(&si.sid, &certs).ok_or_else(|| {
        Error::Tsa(
            "TSA cert not found in token (SignerIdentifier didn't match any embedded cert)"
                .into(),
        )
    })?;
    let tsa_subject = Some(tsa_cert.subject_string());

    let signed_attrs = si.signed_attrs.as_ref().ok_or_else(|| {
        Error::Tsa("token SignerInfo has no SignedAttributes".into())
    })?;
    let attrs_der = signed_attrs
        .to_der()
        .map_err(|e| Error::Tsa(format!("token attrs to_der: {e}")))?;
    let attr_hash_algo = HashAlgo::from_oid_str(&si.digest_alg.oid.to_string()).ok_or_else(|| {
        Error::Tsa(format!(
            "unsupported token digest algorithm: {}",
            si.digest_alg.oid
        ))
    })?;
    let attrs_hash = attr_hash_algo.hash(&attrs_der);
    let pk = chain::extract_rsa_pubkey(tsa_cert)?;
    let sig_bytes = si.signature.as_bytes();
    let verify_result = match attr_hash_algo {
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
        return Ok(TimestampVerdict {
            ok: false,
            tsa_subject,
            gen_time: tst_info.gen_time,
            warnings: vec![format!("token RSA verification failed: {e}")],
        });
    }

    // messageDigest signed-attr must equal hash(eContent).
    let md_attr = find_attr(signed_attrs, &OID_MESSAGE_DIGEST).ok_or_else(|| {
        Error::Tsa("token SignerInfo has no messageDigest attribute".into())
    })?;
    let md_value = md_attr.values.as_slice().first().ok_or_else(|| {
        Error::Tsa("token messageDigest attribute has empty value set".into())
    })?;
    let md_bytes = der::asn1::OctetString::from_der(
        &md_value.to_der().map_err(|e| Error::Tsa(format!("md to_der: {e}")))?,
    )
    .map_err(|e| Error::Tsa(format!("messageDigest OctetString decode: {e}")))?;
    let want_md = attr_hash_algo.hash(&tst_info_der);
    if md_bytes.as_bytes() != want_md.as_slice() {
        return Ok(TimestampVerdict {
            ok: false,
            tsa_subject,
            gen_time: tst_info.gen_time,
            warnings: vec!["token messageDigest != hash(eContent)".into()],
        });
    }

    // 6. Chain build (with cert_internal demoting failure to warning).
    let mut warnings: Vec<String> = Vec::new();
    let intermediates: Vec<&SignerCert> =
        certs.iter().filter(|c| !std::ptr::eq(*c, tsa_cert)).collect();
    match chain::build_and_verify_chain(tsa_cert, &intermediates, &[trust_root]) {
        Ok(_) => {}
        Err(e) => {
            if cert_internal {
                warnings.push(format!(
                    "TSA chain not anchored to trust root (cert_internal): {e}"
                ));
            } else {
                return Ok(TimestampVerdict {
                    ok: false,
                    tsa_subject,
                    gen_time: tst_info.gen_time,
                    warnings: vec![format!("TSA chain build failed: {e}")],
                });
            }
        }
    }

    Ok(TimestampVerdict {
        ok: true,
        tsa_subject,
        gen_time: tst_info.gen_time,
        warnings,
    })
}

impl TimestampVerdict {
    fn fail(msg: String) -> Self {
        Self {
            ok: false,
            tsa_subject: None,
            gen_time: None,
            warnings: vec![msg],
        }
    }
}

// ---------- TSTInfo hand-walk ----------

struct TstInfoFields {
    imprint_algo_oid: String,
    imprint_hash: Vec<u8>,
    gen_time: Option<String>,
    /// `TSTInfo.nonce` (OPTIONAL INTEGER), folded big-endian. Used at
    /// *issuance* time to confirm the TSA echoed the nonce we sent
    /// (RFC 3161 §2.4.2 replay/mix-up protection); `None` if absent.
    nonce: Option<u64>,
}

/// Parse the bytes that follow `TSTInfo ::= SEQUENCE` and extract the
/// fields we care about: messageImprint and genTime.
fn parse_tst_info(der_bytes: &[u8]) -> Result<TstInfoFields> {
    // Outer SEQUENCE.
    let (outer, _) = read_tlv(der_bytes)?;
    if outer.tag != 0x30 {
        return Err(Error::Tsa(format!(
            "TSTInfo not SEQUENCE (tag {:#x})",
            outer.tag
        )));
    }
    let mut body = outer.value;

    // version INTEGER (1)
    let (v, rest) = read_tlv(body)?;
    if v.tag != 0x02 {
        return Err(Error::Tsa("TSTInfo.version not INTEGER".into()));
    }
    body = rest;

    // policy OBJECT IDENTIFIER
    let (p, rest) = read_tlv(body)?;
    if p.tag != 0x06 {
        return Err(Error::Tsa("TSTInfo.policy not OID".into()));
    }
    body = rest;

    // messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    let (mi_seq, rest) = read_tlv(body)?;
    if mi_seq.tag != 0x30 {
        return Err(Error::Tsa("TSTInfo.messageImprint not SEQUENCE".into()));
    }
    body = rest;

    // Inside messageImprint:
    //   hashAlgorithm AlgorithmIdentifier ::= SEQUENCE { OID, parameters? }
    let (alg_seq, mi_rest) = read_tlv(mi_seq.value)?;
    if alg_seq.tag != 0x30 {
        return Err(Error::Tsa("hashAlgorithm not SEQUENCE".into()));
    }
    let (oid_tlv, _) = read_tlv(alg_seq.value)?;
    if oid_tlv.tag != 0x06 {
        return Err(Error::Tsa("hashAlgorithm OID expected".into()));
    }
    let oid_str = oid_bytes_to_string(oid_tlv.value)?;
    //   hashedMessage OCTET STRING
    let (hm, _) = read_tlv(mi_rest)?;
    if hm.tag != 0x04 {
        return Err(Error::Tsa("hashedMessage not OCTET STRING".into()));
    }
    let imprint_hash = hm.value.to_vec();

    // serialNumber INTEGER (skip)
    let (s, rest) = read_tlv(body)?;
    if s.tag != 0x02 {
        return Err(Error::Tsa("TSTInfo.serialNumber not INTEGER".into()));
    }
    body = rest;

    // genTime GeneralizedTime
    let (g, after_gen) = read_tlv(body)?;
    let gen_time = if g.tag == 0x18 {
        Some(String::from_utf8_lossy(g.value).to_string())
    } else {
        None
    };

    // Optional tail (in order): accuracy SEQUENCE, ordering BOOLEAN
    // DEFAULT FALSE, nonce INTEGER, tsa [0], extensions [1]. The only
    // INTEGER that can appear after genTime is the nonce, so scan for
    // the first 0x02 tag.
    let mut nonce = None;
    let mut tail = after_gen;
    while let Ok((tlv, rest)) = read_tlv(tail) {
        if tlv.tag == 0x02 {
            nonce = Some(be_bytes_to_u64(tlv.value));
            break;
        }
        if rest.len() >= tail.len() {
            break; // no forward progress — stop rather than loop
        }
        tail = rest;
    }

    Ok(TstInfoFields {
        imprint_algo_oid: oid_str,
        imprint_hash,
        gen_time,
        nonce,
    })
}

/// Fold a DER INTEGER's content octets (big-endian, two's complement
/// but our nonces are non-negative) into a `u64`, ignoring a leading
/// sign-padding zero. Values wider than 64 bits wrap — acceptable here
/// because we only ever compare against a `u64` nonce we generated.
fn be_bytes_to_u64(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)
}

/// Decode a TimeStampToken and return its `TSTInfo.nonce`, if present.
///
/// Used by the TSA *client* immediately after a round-trip to confirm the
/// response carries the same nonce the request sent (RFC 3161 anti-replay).
/// `None` means the token contained no nonce.
pub fn token_nonce(token_der: &[u8]) -> Result<Option<u64>> {
    let ci = ContentInfo::from_der(token_der)
        .map_err(|e| Error::Tsa(format!("token ContentInfo decode: {e}")))?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Tsa(format!("token SignedData decode: {e}")))?;
    let econtent_any = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| Error::Tsa("token encapContentInfo has no eContent".into()))?;
    let raw = econtent_any.value();
    let tst_info_der = der::asn1::OctetString::from_der(&wrap_explicit(raw, 0x04)?)
        .map(|os| os.as_bytes().to_vec())
        .unwrap_or_else(|_| raw.to_vec());
    Ok(parse_tst_info(&tst_info_der)?.nonce)
}

/// Convert a raw OID value-bytes blob into dotted decimal.
fn oid_bytes_to_string(v: &[u8]) -> Result<String> {
    if v.is_empty() {
        return Err(Error::Tsa("OID empty".into()));
    }
    let mut out = String::new();
    let first = v[0];
    out.push_str(&format!("{}.{}", first / 40, first % 40));
    let mut i = 1usize;
    while i < v.len() {
        let mut value: u64 = 0;
        loop {
            if i >= v.len() {
                return Err(Error::Tsa("OID truncated".into()));
            }
            let b = v[i];
            value = (value << 7) | ((b & 0x7F) as u64);
            i += 1;
            if (b & 0x80) == 0 {
                break;
            }
        }
        out.push('.');
        out.push_str(&value.to_string());
    }
    Ok(out)
}

/// Locate a cert in `certs` matching `sid`. Returns None on miss
/// rather than erroring — the caller wraps with their own error.
fn locate_signer_in<'a>(
    sid: &SignerIdentifier,
    certs: &'a [SignerCert],
) -> Option<&'a SignerCert> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs.iter().find(|c| {
            c.parsed.tbs_certificate.issuer == ias.issuer
                && c.parsed.tbs_certificate.serial_number == ias.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let want = ski.0.as_bytes();
            certs.iter().find(|c| {
                let exts = match c.parsed.tbs_certificate.extensions.as_ref() {
                    Some(e) => e,
                    None => return false,
                };
                exts.iter().any(|e| {
                    e.extn_id.to_string() == "2.5.29.14"
                        && der::asn1::OctetString::from_der(e.extn_value.as_bytes())
                            .map(|inner| inner.as_bytes() == want)
                            .unwrap_or(false)
                })
            })
        }
    }
}

fn find_attr<'a>(
    attrs: &'a SetOfVec<Attribute>,
    oid: &ObjectIdentifier,
) -> Option<&'a Attribute> {
    attrs.as_slice().iter().find(|a| &a.oid == oid)
}

// ---------- minimal DER helpers ----------

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_tlv(b: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if b.len() < 2 {
        return Err(Error::Tsa("TLV truncated".into()));
    }
    let tag = b[0];
    let l = b[1];
    let (len, hdr) = if l < 0x80 {
        (l as usize, 2)
    } else {
        let n = (l & 0x7F) as usize;
        if n == 0 || n > 4 || b.len() < 2 + n {
            return Err(Error::Tsa("TLV bad length".into()));
        }
        let mut v: usize = 0;
        for &x in &b[2..2 + n] {
            v = (v << 8) | x as usize;
        }
        (v, 2 + n)
    };
    if b.len() < hdr + len {
        return Err(Error::Tsa("TLV length exceeds input".into()));
    }
    Ok((Tlv { tag, value: &b[hdr..hdr + len] }, &b[hdr + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        assert!(val.len() < 0x80, "test helper only does short-form lengths");
        let mut o = vec![tag, val.len() as u8];
        o.extend_from_slice(val);
        o
    }

    #[test]
    fn be_bytes_folds_nonce() {
        assert_eq!(be_bytes_to_u64(&[0x12, 0x34]), 0x1234);
        assert_eq!(be_bytes_to_u64(&[0x00, 0xFF]), 0xFF); // leading sign-pad zero
        assert_eq!(be_bytes_to_u64(&0xDEAD_BEEF_u64.to_be_bytes()), 0xDEAD_BEEF);
    }

    #[test]
    fn parse_tst_info_extracts_nonce_after_optional_fields() {
        // Minimal TSTInfo with the optional `ordering BOOLEAN` present
        // before the nonce, to prove the scan skips it.
        let sha256_alg = tlv(0x30, &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        let hashed = tlv(0x04, &[0xAA; 32]);
        let mut mi = sha256_alg;
        mi.extend_from_slice(&hashed);
        let message_imprint = tlv(0x30, &mi);

        let nonce_val: u64 = 0x0102_0304_0506_0708;
        let mut body = Vec::new();
        body.extend_from_slice(&tlv(0x02, &[0x01])); // version
        body.extend_from_slice(&tlv(0x06, &[0x2A, 0x03])); // policy OID 1.2.3
        body.extend_from_slice(&message_imprint);
        body.extend_from_slice(&tlv(0x02, &[0x05])); // serialNumber
        body.extend_from_slice(&tlv(0x18, b"20260101000000Z")); // genTime
        body.extend_from_slice(&tlv(0x01, &[0xFF])); // ordering BOOLEAN TRUE (optional)
        body.extend_from_slice(&tlv(0x02, &nonce_val.to_be_bytes())); // nonce
        let tst = tlv(0x30, &body);

        let fields = parse_tst_info(&tst).expect("parse");
        assert_eq!(fields.nonce, Some(nonce_val));
        assert_eq!(fields.imprint_algo_oid, "2.16.840.1.101.3.4.2.1");
    }

    #[test]
    fn parse_tst_info_nonce_absent_is_none() {
        let sha256_alg = tlv(0x30, &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        let hashed = tlv(0x04, &[0xBB; 32]);
        let mut mi = sha256_alg;
        mi.extend_from_slice(&hashed);
        let message_imprint = tlv(0x30, &mi);
        let mut body = Vec::new();
        body.extend_from_slice(&tlv(0x02, &[0x01]));
        body.extend_from_slice(&tlv(0x06, &[0x2A, 0x03]));
        body.extend_from_slice(&message_imprint);
        body.extend_from_slice(&tlv(0x02, &[0x05]));
        body.extend_from_slice(&tlv(0x18, b"20260101000000Z"));
        let tst = tlv(0x30, &body);
        assert_eq!(parse_tst_info(&tst).unwrap().nonce, None);
    }
}

/// Wrap raw bytes in an EXPLICIT [0] tag, used only as a fallback
/// path when probing whether the cms crate already stripped one
/// EXPLICIT wrapper or not.
fn wrap_explicit(inner: &[u8], inner_tag: u8) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(inner.len() + 4);
    buf.push(inner_tag);
    if inner.len() < 0x80 {
        buf.push(inner.len() as u8);
    } else if inner.len() <= 0xFF {
        buf.push(0x81);
        buf.push(inner.len() as u8);
    } else {
        buf.push(0x82);
        buf.push((inner.len() >> 8) as u8);
        buf.push((inner.len() & 0xFF) as u8);
    }
    buf.extend_from_slice(inner);
    Ok(buf)
}
