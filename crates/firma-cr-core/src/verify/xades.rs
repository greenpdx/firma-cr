// SPDX-License-Identifier: GPL-3.0-or-later
//! XAdES verification — enveloped mode.
//!
//! Verification steps:
//!
//!   1. Find the `<ds:Signature>` element.
//!   2. Extract every `<ds:X509Certificate>` (leaf first, then any
//!      intermediates) and decode each to DER.
//!   3. Parse the two `<ds:Reference>` blocks in `<ds:SignedInfo>`
//!      (their URI, DigestMethod URI, DigestValue text).
//!   4. **URI=""** reference: reconstruct the pre-signing document by
//!      removing the `<ds:Signature>` subtree, Exclusive C14N it,
//!      hash with the algo declared by this reference's DigestMethod,
//!      compare to the embedded DigestValue.
//!   5. **URI="#<id>"** reference: locate the element bearing that
//!      `Id=`, Exclusive C14N + hash + compare. (For our own signer
//!      this is `<xades:SignedProperties>`.)
//!   6. C14N `<ds:SignedInfo>`, hash per the SignatureMethod URI,
//!      RSA-verify `<ds:SignatureValue>` against the leaf's public
//!      key.
//!   7. Chain-build leaf → trust root through the supplied
//!      intermediates.
//!
//! Out of scope: enveloping / detached modes, embedded TimeStampToken
//! validation (we still only report `has_timestamp: bool`).

use rsa::Pkcs1v15Sign;
use rsa::sha2::{Sha256 as RsaSha256, Sha384 as RsaSha384, Sha512 as RsaSha512};

use crate::c14n::excl_c14n;
use crate::cert::SignerCert;
use crate::digest::HashAlgo;
use crate::error::{Error, Result};
use crate::verify::{SignerVerdict, VerifyOptions, VerifyReport, chain, tsa};

const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// Build a single-signer `VerifyReport` from the per-signer
/// fields — XAdES files always carry exactly one
/// `<ds:Signature>`, so the `signers` Vec is always length 1 and
/// mirrors the legacy top-level fields.
#[allow(clippy::too_many_arguments)]
fn xades_report(
    ok: bool,
    signer_subject: Option<String>,
    signing_time: Option<String>,
    has_timestamp: bool,
    timestamp: Option<tsa::TimestampVerdict>,
    revocation: Option<crate::verify::revocation::RevocationVerdict>,
    archive_timestamp: Option<tsa::TimestampVerdict>,
    warnings: Vec<String>,
) -> VerifyReport {
    let signer = SignerVerdict {
        ok,
        signer_subject: signer_subject.clone(),
        signing_time: signing_time.clone(),
        has_timestamp,
        timestamp: timestamp.clone(),
        revocation: revocation.clone(),
        archive_timestamp: archive_timestamp.clone(),
        warnings: warnings.clone(),
    };
    VerifyReport {
        ok,
        signer_subject,
        signing_time,
        has_timestamp,
        timestamp,
        revocation,
        archive_timestamp,
        // Mirror per-signer warnings up to the top level — pre-12b
        // single-signer reports lived here and callers grep for
        // warning text. For multi-signer CMS the equivalent lives in
        // `signers[i].warnings`; the top-level Vec is left empty
        // there to avoid mis-attributing warnings across signers.
        warnings: warnings.clone(),
        signers: vec![signer],
    }
}

pub fn verify_xml(
    xml: &[u8],
    trust_root: &SignerCert,
    opts: VerifyOptions,
) -> Result<VerifyReport> {
    verify_xml_inner(xml, None, trust_root, opts)
}

/// Verify a detached XAdES signature whose URI="" Reference points
/// at an external file. The caller supplies the bytes that should
/// be hashed for that Reference; the signer must have given the
/// verifier the exact same bytes for the digest to match.
pub fn verify_xml_detached(
    signature_xml: &[u8],
    referenced_content: &[u8],
    trust_root: &SignerCert,
    opts: VerifyOptions,
) -> Result<VerifyReport> {
    verify_xml_inner(signature_xml, Some(referenced_content), trust_root, opts)
}

fn verify_xml_inner(
    xml: &[u8],
    external_content: Option<&[u8]>,
    trust_root: &SignerCert,
    opts: VerifyOptions,
) -> Result<VerifyReport> {
    let xml_str = std::str::from_utf8(xml)
        .map_err(|_| Error::Xml("input XML not UTF-8".into()))?;

    let sig_span = locate_element(xml_str, "ds:Signature")
        .ok_or_else(|| Error::Xades("no <ds:Signature> element".into()))?;
    let signature_xml = &xml_str[sig_span.0..sig_span.1];

    // ---- certs ----
    let cert_blobs = collect_x509_certificates(signature_xml);
    if cert_blobs.is_empty() {
        return Err(Error::Xades(
            "no <ds:X509Certificate> inside KeyInfo/X509Data".into(),
        ));
    }
    let mut all_certs: Vec<SignerCert> = Vec::with_capacity(cert_blobs.len());
    for b64 in &cert_blobs {
        let der = base64_decode(b64.trim())?;
        all_certs.push(SignerCert::from_der(der)?);
    }
    let signer = all_certs.remove(0);
    let intermediates: Vec<&SignerCert> = all_certs.iter().collect();
    let signer_subject = Some(signer.subject_string());

    // ---- SignatureValue base64 ----
    let signature_value_b64 = inner_text(signature_xml, "ds:SignatureValue").ok_or_else(
        || Error::Xades("no <ds:SignatureValue>".into()),
    )?;
    let sig_bytes = base64_decode(signature_value_b64.trim())?;

    // ---- SignedInfo ----
    let signed_info_span = locate_element(signature_xml, "ds:SignedInfo")
        .ok_or_else(|| Error::Xades("no <ds:SignedInfo>".into()))?;
    let signed_info_xml = &signature_xml[signed_info_span.0..signed_info_span.1];

    // The c14n input must inherit the xmlns:ds declaration. Our own
    // signer puts it directly on <ds:SignedInfo>; if a foreign signer
    // didn't, re-attach.
    let si_for_c14n: String = if signed_info_xml.contains("xmlns:ds") {
        signed_info_xml.to_string()
    } else {
        signed_info_xml.replacen(
            "<ds:SignedInfo",
            "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            1,
        )
    };
    let si_c14n = excl_c14n(si_for_c14n.as_bytes())?;

    // SignatureMethod tells us which hash feeds RSA verification.
    let sig_method_uri = attr_value(signed_info_xml, "ds:SignatureMethod", "Algorithm")
        .ok_or_else(|| {
            Error::Xades("<ds:SignatureMethod> Algorithm attr missing".into())
        })?;
    let sig_hash = hash_algo_from_signature_method_uri(&sig_method_uri).ok_or_else(|| {
        Error::Xades(format!(
            "unsupported SignatureMethod algorithm: {sig_method_uri}"
        ))
    })?;
    let si_digest = sig_hash.hash(&si_c14n);
    let pk = chain::extract_rsa_pubkey(&signer)?;
    let verify_si = match sig_hash {
        HashAlgo::Sha256 => {
            pk.verify(Pkcs1v15Sign::new::<RsaSha256>(), &si_digest, &sig_bytes)
        }
        HashAlgo::Sha384 => {
            pk.verify(Pkcs1v15Sign::new::<RsaSha384>(), &si_digest, &sig_bytes)
        }
        HashAlgo::Sha512 => {
            pk.verify(Pkcs1v15Sign::new::<RsaSha512>(), &si_digest, &sig_bytes)
        }
    };

    let mut warnings: Vec<String> = Vec::new();
    let has_timestamp = signature_xml.contains("xades:SignatureTimeStamp");

    if let Err(e) = verify_si {
        return Ok(xades_report(
            false,
            signer_subject,
            None,
            has_timestamp,
            None,
            None,
            None,
            vec![format!("SignatureValue verification failed: {e}")],
        ));
    }

    // ---- per-reference digest checks ----
    let references = parse_references(signed_info_xml)?;
    if references.is_empty() {
        return Err(Error::Xades(
            "<ds:SignedInfo> contains no <ds:Reference>".into(),
        ));
    }
    for r in &references {
        let computed = match recompute_reference_digest(xml_str, sig_span, r, external_content) {
            Ok(d) => d,
            Err(e) => {
                return Ok(xades_report(
                    false,
                    signer_subject,
                    None,
                    has_timestamp,
                    None,
                    None,
                    None,
                    vec![format!(
                        "Reference URI={:?} could not be recomputed: {e}",
                        r.uri
                    )],
                ));
            }
        };
        let claimed = base64_decode(r.digest_value_b64.trim())?;
        if computed != claimed {
            return Ok(xades_report(
                false,
                signer_subject,
                None,
                has_timestamp,
                None,
                None,
                None,
                vec![format!(
                    "Reference URI={:?} DigestValue mismatch (computed {} bytes, claimed {} bytes)",
                    r.uri,
                    computed.len(),
                    claimed.len(),
                )],
            ));
        }
    }

    // ---- chain ----
    let chain_res = chain::build_and_verify_chain(&signer, &intermediates, &[trust_root]);
    if let Err(e) = chain_res {
        warnings.push(format!("chain build failed: {e}"));
        return Ok(xades_report(
            false,
            signer_subject,
            None,
            has_timestamp,
            None,
            None,
            None,
            warnings,
        ));
    }

    // ---- optional <xades:SignatureTimeStamp> validation ----
    let mut ok = true;
    let mut timestamp_verdict: Option<tsa::TimestampVerdict> = None;
    if has_timestamp {
        match extract_xades_token(signature_xml) {
            Some(token_der) => {
                // The signer hashed `excl_c14n(<ds:SignatureValue
                // xmlns:ds="…">B64</ds:SignatureValue>)`. Reconstruct.
                let sv_element = format!(
                    "<ds:SignatureValue xmlns:ds=\"{NS_DS}\">{}</ds:SignatureValue>",
                    signature_value_b64.trim(),
                );
                let sv_c14n = excl_c14n(sv_element.as_bytes())?;
                let v = tsa::verify_token(
                    &token_der,
                    &sv_c14n,
                    trust_root,
                    opts.cert_internal,
                )?;
                if !v.ok {
                    ok = false;
                    warnings.push("embedded SignatureTimeStamp failed verification".into());
                }
                timestamp_verdict = Some(v);
            }
            None => {
                warnings.push(
                    "SignatureTimeStamp element present but token could not be extracted"
                        .into(),
                );
            }
        }
    }

    // ---- optional XAdES <RevocationValues> validation ----
    let mut revocation_verdict = None;
    if let Some(rev_xml) = extract_xades_revocation_values(signature_xml) {
        let parsed = parse_xades_revocation_values(&rev_xml)?;
        let issuer = intermediates
            .iter()
            .find(|c| c.parsed.tbs_certificate.subject == signer.parsed.tbs_certificate.issuer)
            .copied()
            .unwrap_or(trust_root);
        let v = crate::verify::revocation::validate_signer(
            &parsed,
            &signer,
            issuer,
            &intermediates,
            trust_root,
            opts.cert_internal,
        );
        if !v.ok {
            ok = false;
            warnings.push("XAdES RevocationValues rejected signer".into());
        }
        revocation_verdict = Some(v);
    }
    // Revocation policy: caller may require embedded revocation data to be present.
    if opts.require_revocation && revocation_verdict.is_none() {
        ok = false;
        warnings.push("revocation data required (require_revocation) but none embedded".into());
    }

    // ---- optional XAdES <ArchiveTimeStamp> validation ----
    let mut archive_timestamp_verdict: Option<tsa::TimestampVerdict> = None;
    if let Some(at_token_der) = extract_xades_archive_token(signature_xml) {
        // Reconstruct the imprint per ETSI 319 132-1 §5.5.2. The
        // first reference's c14n bytes vary by URI (enveloped /
        // enveloping / detached), so we pass the already-parsed
        // references list + external_content through.
        let imprint = build_xades_archive_imprint(
            xml_str,
            sig_span,
            signature_xml,
            signed_info_xml,
            signature_value_b64.trim(),
            &references,
            external_content,
        )?;
        let v = tsa::verify_token(
            &at_token_der,
            &imprint,
            trust_root,
            opts.cert_internal,
        )?;
        if !v.ok {
            ok = false;
            warnings.push("embedded XAdES ArchiveTimeStamp failed verification".into());
        }
        archive_timestamp_verdict = Some(v);
    }

    Ok(xades_report(
        ok,
        signer_subject,
        None,
        has_timestamp,
        timestamp_verdict,
        revocation_verdict,
        archive_timestamp_verdict,
        warnings,
    ))
}

/// Pull the base64 inside `<xades:ArchiveTimeStamp>`'s
/// `<xades:EncapsulatedTimeStamp>` child and decode to TST DER.
fn extract_xades_archive_token(signature_xml: &str) -> Option<Vec<u8>> {
    let (s, e) = locate_element(signature_xml, "xades:ArchiveTimeStamp")?;
    let inside = &signature_xml[s..e];
    let open = "<xades:EncapsulatedTimeStamp";
    let close = "</xades:EncapsulatedTimeStamp>";
    let open_idx = inside.find(open)?;
    let after_open = inside[open_idx..].find('>')? + open_idx + 1;
    let close_idx = inside[after_open..].find(close)? + after_open;
    let b64 = &inside[after_open..close_idx];
    base64_decode(b64.trim()).ok()
}

/// Rebuild the imprint bytes the signer fed into the XAdES
/// archive-time-stamp. The order matches ETSI EN 319 132-1 §5.5.2:
/// each Reference target, SignedInfo, SignatureValue, KeyInfo,
/// then every USP element preceding the archive timestamp itself.
///
/// Reference targets are c14n'd per the same logic as the
/// per-reference digest check, so enveloped (URI=""), enveloping
/// (URI="#obj-1"), and detached (URI=<external>) modes share the
/// implementation.
fn build_xades_archive_imprint(
    xml_str: &str,
    sig_span: (usize, usize),
    signature_xml: &str,
    signed_info_xml: &str,
    signature_value_b64: &str,
    references: &[Reference],
    external_content: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut imprint = Vec::new();

    // 1. Every Reference's c14n target, in document order.
    for r in references {
        let bytes = compute_reference_c14n_bytes(xml_str, sig_span, r, external_content)?;
        imprint.extend_from_slice(&bytes);
    }

    // 3. SignedInfo — re-attach xmlns:ds if not present.
    let si_for_c14n: String = if signed_info_xml.contains("xmlns:ds") {
        signed_info_xml.to_string()
    } else {
        signed_info_xml.replacen(
            "<ds:SignedInfo",
            &format!("<ds:SignedInfo xmlns:ds=\"{NS_DS}\""),
            1,
        )
    };
    imprint.extend_from_slice(&excl_c14n(si_for_c14n.as_bytes())?);

    // 4. SignatureValue — reconstruct with xmlns:ds attached.
    let sv = format!(
        "<ds:SignatureValue xmlns:ds=\"{NS_DS}\">{signature_value_b64}</ds:SignatureValue>"
    );
    imprint.extend_from_slice(&excl_c14n(sv.as_bytes())?);

    // 5. KeyInfo — reconstruct from the X509Certificate children.
    let (ki_s, ki_e) = locate_element(signature_xml, "ds:KeyInfo")
        .ok_or_else(|| Error::Xades("no <ds:KeyInfo>".into()))?;
    let ki_for_c14n: String = {
        let inner = &signature_xml[ki_s..ki_e];
        if inner.contains("xmlns:ds") {
            inner.to_string()
        } else {
            inner.replacen(
                "<ds:KeyInfo",
                &format!("<ds:KeyInfo xmlns:ds=\"{NS_DS}\""),
                1,
            )
        }
    };
    imprint.extend_from_slice(&excl_c14n(ki_for_c14n.as_bytes())?);

    // 6. Preceding USP elements — find each named USP child up to,
    //    but not including, <xades:ArchiveTimeStamp> itself. The
    //    spec covers them in document order.
    let usp = match locate_element(signature_xml, "xades:UnsignedSignatureProperties") {
        Some((s, e)) => &signature_xml[s..e],
        None => return Ok(imprint),
    };
    let at_pos = usp.find("<xades:ArchiveTimeStamp").unwrap_or(usp.len());
    let preceding = &usp[..at_pos];
    // Walk every immediate child of UnsignedSignatureProperties.
    for tag in &["xades:SignatureTimeStamp", "xades:RevocationValues"] {
        if let Some((cs, ce)) = locate_element(preceding, tag) {
            let body = &preceding[cs..ce];
            let with_ns = if body.contains("xmlns:xades") {
                body.to_string()
            } else {
                body.replacen(
                    &format!("<{tag}"),
                    &format!(
                        "<{tag} xmlns:xades=\"{NS_XADES}\" xmlns:ds=\"{NS_DS}\""
                    ),
                    1,
                )
            };
            imprint.extend_from_slice(&excl_c14n(with_ns.as_bytes())?);
        }
    }

    Ok(imprint)
}

/// Slice out the `<xades:RevocationValues>…</xades:RevocationValues>`
/// element, if present.
fn extract_xades_revocation_values(signature_xml: &str) -> Option<&str> {
    let (s, e) = locate_element(signature_xml, "xades:RevocationValues")?;
    Some(&signature_xml[s..e])
}

/// Parse the `<xades:RevocationValues>` element and decode each
/// embedded base64 OCSP / CRL into the canonical RustCrypto types.
fn parse_xades_revocation_values(
    xml: &str,
) -> Result<crate::verify::revocation::ParsedRevocationValues> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    use x509_ocsp::BasicOcspResponse;
    let mut out = crate::verify::revocation::ParsedRevocationValues::default();
    for b64 in collect_inner_text(xml, "xades:EncapsulatedOCSPValue") {
        let der = base64_decode(b64.trim())?;
        let bocsp = BasicOcspResponse::from_der(&der)
            .map_err(|e| Error::Xades(format!("EncapsulatedOCSPValue decode: {e}")))?;
        out.basic_ocsp_responses.push(bocsp);
    }
    for b64 in collect_inner_text(xml, "xades:EncapsulatedCRLValue") {
        let der = base64_decode(b64.trim())?;
        let crl = CertificateList::from_der(&der)
            .map_err(|e| Error::Xades(format!("EncapsulatedCRLValue decode: {e}")))?;
        out.crls.push(crl);
    }
    Ok(out)
}

/// Return every text node inside `<tag …>…</tag>` occurrences in `s`,
/// preserving document order.
fn collect_inner_text<'a>(s: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut cursor = 0;
    while let Some(rel) = s[cursor..].find(&open) {
        let abs_open = cursor + rel;
        let after_open = match s[abs_open..].find('>') {
            Some(i) => abs_open + i + 1,
            None => break,
        };
        let abs_close = match s[after_open..].find(close.as_str()) {
            Some(i) => after_open + i,
            None => break,
        };
        out.push(&s[after_open..abs_close]);
        cursor = abs_close + close.len();
    }
    out
}

/// Pull the base64 inside `<xades:EncapsulatedTimeStamp>` and decode
/// it to the TimeStampToken DER bytes.
fn extract_xades_token(signature_xml: &str) -> Option<Vec<u8>> {
    let open = "<xades:EncapsulatedTimeStamp";
    let close = "</xades:EncapsulatedTimeStamp>";
    let open_idx = signature_xml.find(open)?;
    let after_open = signature_xml[open_idx..].find('>')? + open_idx + 1;
    let close_idx = signature_xml[after_open..].find(close)? + after_open;
    let b64 = &signature_xml[after_open..close_idx];
    base64_decode(b64.trim()).ok()
}

/// One parsed `<ds:Reference>` block.
struct Reference {
    uri: String,
    digest_algo: HashAlgo,
    digest_value_b64: String,
    /// Whether the Transforms list contains the
    /// `enveloped-signature` transform (causes the verifier to strip
    /// the Signature subtree before hashing).
    enveloped: bool,
}

/// Pull every `<ds:Reference …>…</ds:Reference>` out of the
/// SignedInfo block in document order.
fn parse_references(signed_info_xml: &str) -> Result<Vec<Reference>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let open_pat = "<ds:Reference";
    let close_pat = "</ds:Reference>";
    while let Some(rel) = signed_info_xml[cursor..].find(open_pat) {
        let abs_open = cursor + rel;
        // End of opening tag.
        let tag_end = signed_info_xml[abs_open..]
            .find('>')
            .ok_or_else(|| Error::Xades("<ds:Reference> opening tag has no '>'".into()))?
            + abs_open;
        let opening = &signed_info_xml[abs_open..=tag_end];
        let close_rel = signed_info_xml[tag_end..]
            .find(close_pat)
            .ok_or_else(|| Error::Xades("<ds:Reference> not closed".into()))?;
        let close_abs = tag_end + close_rel;
        let body = &signed_info_xml[tag_end + 1..close_abs];

        let uri = attr_value_in_tag(opening, "URI").unwrap_or_default();
        let dm_uri = attr_value(body, "ds:DigestMethod", "Algorithm").ok_or_else(|| {
            Error::Xades(format!(
                "Reference URI={uri:?} has no DigestMethod Algorithm"
            ))
        })?;
        let digest_algo = hash_algo_from_digest_method_uri(&dm_uri).ok_or_else(|| {
            Error::Xades(format!(
                "Reference URI={uri:?} unsupported DigestMethod: {dm_uri}"
            ))
        })?;
        let digest_value_b64 = inner_text(body, "ds:DigestValue")
            .ok_or_else(|| {
                Error::Xades(format!("Reference URI={uri:?} has no DigestValue"))
            })?
            .to_string();
        let enveloped = body.contains(ALG_ENVELOPED);

        out.push(Reference {
            uri,
            digest_algo,
            digest_value_b64,
            enveloped,
        });
        cursor = close_abs + close_pat.len();
    }
    Ok(out)
}

/// Compute the c14n'd bytes a Reference covers — i.e. the bytes
/// that get hashed for the DigestValue. Factored out so the
/// per-reference digest check AND the archive-timestamp imprint
/// reconstruction (which includes Reference 1's c14n bytes) share
/// a single source of truth.
fn compute_reference_c14n_bytes(
    xml_str: &str,
    sig_span: (usize, usize),
    r: &Reference,
    external_content: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if r.uri.is_empty() {
        // The whole document, with enveloped-signature transform if
        // requested (XAdES-B-B enveloped). Without the enveloped
        // transform this reference shape is unusual but we mirror the
        // sign-side behavior: c14n the input as-is.
        let mut doc = String::with_capacity(xml_str.len());
        if r.enveloped {
            doc.push_str(&xml_str[..sig_span.0]);
            doc.push_str(&xml_str[sig_span.1..]);
        } else {
            doc.push_str(xml_str);
        }
        excl_c14n(doc.as_bytes())
    } else if let Some(id) = r.uri.strip_prefix('#') {
        // Same-document reference. Find the element with Id="<id>".
        // For XAdES enveloping mode this is `<ds:Object Id="obj-1">`
        // (the signer emits it with its own xmlns:ds); for XAdES-LT
        // it's `<xades:SignedProperties Id="…">`.
        let (start, end) = locate_element_by_id(xml_str, id).ok_or_else(|| {
            Error::Xades(format!(
                "Reference URI=#{id:?} target element not found"
            ))
        })?;
        excl_c14n(xml_str[start..end].as_bytes())
    } else {
        // External URI — XAdES detached mode. The caller must have
        // supplied the referenced bytes via `verify_xml_detached`.
        let bytes = external_content.ok_or_else(|| {
            Error::Xades(format!(
                "Reference URI={:?} is external; call verify_xml_detached with the bytes",
                r.uri
            ))
        })?;
        excl_c14n(bytes)
    }
}

fn recompute_reference_digest(
    xml_str: &str,
    sig_span: (usize, usize),
    r: &Reference,
    external_content: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let c14n = compute_reference_c14n_bytes(xml_str, sig_span, r, external_content)?;
    Ok(r.digest_algo.hash(&c14n))
}

/// Locate the byte span (start, end-exclusive) of a single element
/// `<tag …>…</tag>` in the haystack. Returns the open `<` through the
/// final `>` of the closing tag. Simple — assumes the tag isn't
/// nested with same-name children.
fn locate_element(s: &str, tag: &str) -> Option<(usize, usize)> {
    let open_pat = format!("<{tag}");
    let open_idx = s.find(&open_pat)?;
    let close_pat = format!("</{tag}>");
    let close_rel = s[open_idx..].find(&close_pat)?;
    let end = open_idx + close_rel + close_pat.len();
    Some((open_idx, end))
}

/// Locate any element whose opening tag carries `Id="<id>"`. Returns
/// (start, end-exclusive) of the full element, including its closing
/// tag. Independent of the element's tag name.
fn locate_element_by_id(s: &str, id: &str) -> Option<(usize, usize)> {
    let needle = format!("Id=\"{id}\"");
    let attr_idx = s.find(&needle)?;
    // Walk backwards to the nearest '<' — that's the opening of our
    // element.
    let open_idx = s[..attr_idx].rfind('<')?;
    // Read the element name.
    let mut j = open_idx + 1;
    let bytes = s.as_bytes();
    while j < bytes.len() {
        let c = bytes[j];
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' || c == b'/' || c == b'>' {
            break;
        }
        j += 1;
    }
    let name = &s[open_idx + 1..j];
    if name.is_empty() {
        return None;
    }
    let close_pat = format!("</{name}>");
    let close_rel = s[attr_idx..].find(&close_pat)?;
    let end = attr_idx + close_rel + close_pat.len();
    Some((open_idx, end))
}

/// Return the text content between `<tag …>` and `</tag>`, or None.
fn inner_text<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let (start, end) = locate_element(s, tag)?;
    let open_pat = format!("<{tag}");
    let after_open = s[start + open_pat.len()..end]
        .find('>')
        .map(|i| start + open_pat.len() + i + 1)?;
    let close_pat = format!("</{tag}>");
    let before_close = end - close_pat.len();
    Some(&s[after_open..before_close])
}

/// Read an attribute `attr` off the first `<tag …>` occurrence in `s`.
fn attr_value(s: &str, tag: &str, attr: &str) -> Option<String> {
    let open_pat = format!("<{tag}");
    let open = s.find(&open_pat)?;
    let tag_end = s[open..].find('>')?;
    let opening = &s[open..=open + tag_end];
    attr_value_in_tag(opening, attr)
}

/// Read an attribute value out of one opening-tag string.
fn attr_value_in_tag(opening_tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let i = opening_tag.find(&needle)?;
    let start = i + needle.len();
    let rest = &opening_tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Map a `<ds:SignatureMethod Algorithm="…">` URI to a HashAlgo.
fn hash_algo_from_signature_method_uri(uri: &str) -> Option<HashAlgo> {
    match uri {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(HashAlgo::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Some(HashAlgo::Sha384),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Some(HashAlgo::Sha512),
        _ => None,
    }
}

/// Map a `<ds:DigestMethod Algorithm="…">` URI to a HashAlgo.
fn hash_algo_from_digest_method_uri(uri: &str) -> Option<HashAlgo> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some(HashAlgo::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(HashAlgo::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Some(HashAlgo::Sha512),
        _ => None,
    }
}

/// Return the base64 payload of every `<ds:X509Certificate>…</ds:X509Certificate>`
/// element found in `s`, in document order.
fn collect_x509_certificates(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let open = "<ds:X509Certificate";
    let close = "</ds:X509Certificate>";
    let mut cursor = 0;
    while let Some(rel) = s[cursor..].find(open) {
        let abs_open = cursor + rel;
        let after_open = match s[abs_open..].find('>') {
            Some(i) => abs_open + i + 1,
            None => break,
        };
        let abs_close = match s[after_open..].find(close) {
            Some(i) => after_open + i,
            None => break,
        };
        out.push(&s[after_open..abs_close]);
        cursor = abs_close + close.len();
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| Error::Xml(format!("base64 decode: {e}")))
}
