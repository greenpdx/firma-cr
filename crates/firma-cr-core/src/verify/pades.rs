//! PAdES PDF signature verification.
//!
//! Locates the `/Type /Sig` dict in the PDF, extracts `/ByteRange`
//! and `/Contents`, concatenates the byterange slices, and delegates
//! to `verify::cms::verify_detached` over those bytes. For -LT
//! signatures we additionally look up the `/DSS` catalog entry,
//! decode its `/OCSPs`, `/CRLs` (and `/Certs`) streams, and feed the
//! recovered revocation evidence into the shared validator from
//! `verify::revocation`.

use lopdf::Document;

use crate::cert::SignerCert;
use crate::error::{Error, Result};
use crate::verify::{VerifyOptions, VerifyReport, cms as verify_cms};

pub fn verify_pdf(
    pdf: &[u8],
    trust_root: &SignerCert,
    opts: VerifyOptions,
) -> Result<VerifyReport> {
    let (byterange_data, cms_der) = extract_sig_payload(pdf)?;
    let mut report = verify_cms::verify_detached(&cms_der, &byterange_data, trust_root, opts)?;

    // ---- PAdES-LTA — embedded /Type /DocTimeStamp ----
    if let Some((dts_br_data, dts_token_der)) = extract_doctimestamp_payload(pdf)? {
        let verdict = crate::verify::tsa::verify_token(
            &dts_token_der,
            &dts_br_data,
            trust_root,
            opts.cert_internal,
        )?;
        if !verdict.ok {
            report.ok = false;
            report
                .warnings
                .push("PDF DocTimeStamp failed verification".into());
        }
        report.archive_timestamp = Some(verdict);
    }

    // If the CMS already carried `id-aa-ets-revocationValues` and
    // validated, don't override that verdict. Otherwise fall back to
    // the PDF's /DSS catalog entry for the same evidence.
    if report.revocation.is_none() {
        if let Some(dss_rev) = extract_dss_revocation(pdf)? {
            if let Some(signer_subject) = report.signer_subject.as_ref() {
                // We need the SignerCert + issuer to call validate_signer.
                // The CMS verifier already loaded those, but didn't expose
                // them. For now re-decode the CMS just to recover the
                // signer cert; cheap and keeps the per-format verifiers
                // independent.
                let (signer, issuer) = signer_and_issuer_from_cms(&cms_der)?;
                let _ = signer_subject;
                // For the PDF /DSS path we don't have the full CMS
                // intermediate list handy; pass just the issuer.
                // A delegated OCSP signer whose chain depends on a
                // third intermediate would fail to anchor and surface
                // as a warning (with cert_internal) or a failure
                // (strict) — acceptable for now.
                let intermediates: Vec<&SignerCert> = vec![&issuer];
                let v = crate::verify::revocation::validate_signer(
                    &dss_rev,
                    &signer,
                    &issuer,
                    &intermediates,
                    trust_root,
                    opts.cert_internal,
                );
                if !v.ok {
                    report.ok = false;
                    report
                        .warnings
                        .push("PDF /DSS revocation data rejected signer".into());
                }
                report.revocation = Some(v);
            }
        }
    }
    Ok(report)
}

/// Pull the SignerCert + its issuer cert out of a CMS SignedData,
/// matching how verify::cms locates the signer.
fn signer_and_issuer_from_cms(cms_der: &[u8]) -> Result<(SignerCert, SignerCert)> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::{SignedData, SignerIdentifier};
    use der::Decode;
    use der::Encode;

    let ci = ContentInfo::from_der(cms_der)
        .map_err(|e| Error::Pdf(format!("PDF /DSS path: CMS decode: {e}")))?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Pdf(format!("PDF /DSS path: SignedData decode: {e}")))?;
    let si = sd.signer_infos.0.as_slice().first().ok_or_else(|| {
        Error::Pdf("PDF /DSS path: no SignerInfo".into())
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
    let signer_owned = match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs
            .iter()
            .find(|c| {
                c.parsed.tbs_certificate.issuer == ias.issuer
                    && c.parsed.tbs_certificate.serial_number == ias.serial_number
            })
            .cloned(),
        SignerIdentifier::SubjectKeyIdentifier(_) => None, // not exercised by /DSS path yet
    }
    .ok_or_else(|| Error::Pdf("PDF /DSS path: signer cert not in CMS".into()))?;
    let issuer = certs
        .iter()
        .find(|c| {
            c.parsed.tbs_certificate.subject == signer_owned.parsed.tbs_certificate.issuer
        })
        .cloned()
        .ok_or_else(|| Error::Pdf("PDF /DSS path: issuer cert not in CMS".into()))?;
    Ok((signer_owned, issuer))
}

/// Walk the PDF's catalog for a `/DSS` entry; decode its `/OCSPs`
/// and `/CRLs` array streams into the shared ParsedRevocationValues
/// shape. Returns `None` if there's no DSS dictionary.
fn extract_dss_revocation(
    pdf: &[u8],
) -> Result<Option<crate::verify::revocation::ParsedRevocationValues>> {
    use der::Decode;
    use lopdf::Object;
    use x509_cert::crl::CertificateList;
    use x509_ocsp::BasicOcspResponse;

    let doc = Document::load_mem(pdf)
        .map_err(|e| Error::Pdf(format!("load PDF for DSS scan: {e}")))?;
    let catalog_ref = match doc.trailer.get(b"Root").and_then(|o| o.as_reference()) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let catalog = match doc.get_object(catalog_ref).and_then(|o| o.as_dict()) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let dss_obj = match catalog.get(b"DSS") {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };
    let dss = match deref_dict(&doc, dss_obj) {
        Some(d) => d,
        None => return Ok(None),
    };

    let mut out = crate::verify::revocation::ParsedRevocationValues::default();
    if let Ok(Object::Array(arr)) = dss.get(b"OCSPs") {
        for item in arr {
            if let Some(bytes) = deref_stream_bytes(&doc, item) {
                let bocsp = BasicOcspResponse::from_der(&bytes)
                    .map_err(|e| Error::Pdf(format!("/DSS OCSP decode: {e}")))?;
                out.basic_ocsp_responses.push(bocsp);
            }
        }
    }
    if let Ok(Object::Array(arr)) = dss.get(b"CRLs") {
        for item in arr {
            if let Some(bytes) = deref_stream_bytes(&doc, item) {
                let crl = CertificateList::from_der(&bytes)
                    .map_err(|e| Error::Pdf(format!("/DSS CRL decode: {e}")))?;
                out.crls.push(crl);
            }
        }
    }
    if out.basic_ocsp_responses.is_empty() && out.crls.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

fn deref_dict<'a>(doc: &'a Document, o: &'a lopdf::Object) -> Option<&'a lopdf::Dictionary> {
    use lopdf::Object;
    match o {
        Object::Dictionary(d) => Some(d),
        Object::Reference(r) => doc.get_object(*r).ok().and_then(|x| x.as_dict().ok()),
        _ => None,
    }
}

fn deref_stream_bytes(doc: &Document, o: &lopdf::Object) -> Option<Vec<u8>> {
    use lopdf::Object;
    let target = match o {
        Object::Reference(r) => doc.get_object(*r).ok()?,
        other => other,
    };
    match target {
        Object::Stream(s) => Some(s.content.clone()),
        _ => None,
    }
}

/// Pull `/ByteRange [a b c d]` + `/Contents <hex>` out of the PDF
/// bytes and return `(byterange_slice_concat, cms_der)`.
///
/// This is the byte-level inverse of `pades::sign_pdf`'s patching.
fn extract_sig_payload(pdf: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Find the `/ByteRange [` opener; the four numbers that follow
    // are space-separated and terminated by `]`.
    let br_tag = b"/ByteRange";
    let br_idx = find_in(pdf, br_tag)
        .ok_or_else(|| Error::Pdf("no /ByteRange in PDF".into()))?;
    let br_open = pdf[br_idx + br_tag.len()..]
        .iter()
        .position(|&b| b == b'[')
        .ok_or_else(|| Error::Pdf("/ByteRange '[' not found".into()))?
        + br_idx
        + br_tag.len();
    let br_close = pdf[br_open + 1..]
        .iter()
        .position(|&b| b == b']')
        .ok_or_else(|| Error::Pdf("/ByteRange ']' not found".into()))?
        + br_open
        + 1;
    let body = std::str::from_utf8(&pdf[br_open + 1..br_close])
        .map_err(|_| Error::Pdf("/ByteRange body not UTF-8".into()))?;
    let nums: Vec<usize> = body
        .split_whitespace()
        .map(|s| s.parse::<usize>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Pdf(format!("/ByteRange parse: {e}")))?;
    if nums.len() != 4 {
        return Err(Error::Pdf("/ByteRange must have 4 ints".into()));
    }
    let (r1_off, r1_len, r2_off, r2_len) = (nums[0], nums[1], nums[2], nums[3]);
    if r1_off + r1_len > pdf.len() || r2_off + r2_len > pdf.len() {
        return Err(Error::Pdf("/ByteRange exceeds PDF length".into()));
    }

    let mut byterange = Vec::with_capacity(r1_len + r2_len);
    byterange.extend_from_slice(&pdf[r1_off..r1_off + r1_len]);
    byterange.extend_from_slice(&pdf[r2_off..r2_off + r2_len]);

    // Find the /Contents<...> hex string. PDFs also use `/Contents`
    // as a page-dict key pointing at an indirect ref to the content
    // stream (`/Contents N 0 R`); the signature dict instead has a
    // literal hex string immediately after. Match `/Contents<` so
    // we land on the right one.
    let c_tag = b"/Contents<";
    let c_idx = find_in(pdf, c_tag)
        .ok_or_else(|| Error::Pdf("no /Contents<...> hex string in PDF".into()))?;
    let c_open = c_idx + c_tag.len() - 1;
    let c_close = pdf[c_open + 1..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| Error::Pdf("/Contents '>' not found".into()))?
        + c_open
        + 1;
    let hex_str = std::str::from_utf8(&pdf[c_open + 1..c_close])
        .map_err(|_| Error::Pdf("/Contents body not UTF-8".into()))?;
    // The CMS is left-justified inside the placeholder; trailing
    // zeros may be PAdES padding. Strip after we hit our own
    // end-of-CMS heuristic (last non-zero pair).
    let trimmed = trim_trailing_zero_pairs(hex_str);
    let cms_der = hex::decode(trimmed)
        .map_err(|e| Error::Pdf(format!("/Contents hex decode: {e}")))?;

    Ok((byterange, cms_der))
}

fn find_in(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// If the PDF carries a `/Type /DocTimeStamp` signature dictionary
/// (PAdES-LTA, ETSI 319 142-1 §5.3), pull its byterange + token
/// bytes the same way `extract_sig_payload` does for the main
/// signature. Returns `None` when no DocTimeStamp is present.
fn extract_doctimestamp_payload(pdf: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let marker = b"/Type/DocTimeStamp";
    let dts_pos = match find_in(pdf, marker) {
        Some(p) => p,
        None => return Ok(None),
    };
    // The DocTimeStamp dict ends at the first `>>` after `dts_pos`,
    // accounting for the inner `<...>` /Contents string. Easier path:
    // scan from dts_pos for /ByteRange and /Contents; both are
    // unique within the dict because we wrote them ourselves.
    let tail = &pdf[dts_pos..];

    // /ByteRange[N N N N]
    let br_tag = b"/ByteRange[";
    let br_open_rel = find_in(tail, br_tag).ok_or_else(|| {
        Error::Pdf("/Type/DocTimeStamp: /ByteRange not found".into())
    })?;
    let br_body_start = dts_pos + br_open_rel + br_tag.len();
    let br_body_end_rel = pdf[br_body_start..]
        .iter()
        .position(|&b| b == b']')
        .ok_or_else(|| Error::Pdf("/Type/DocTimeStamp: /ByteRange ']' not found".into()))?;
    let body = std::str::from_utf8(&pdf[br_body_start..br_body_start + br_body_end_rel])
        .map_err(|_| Error::Pdf("/Type/DocTimeStamp: ByteRange body not UTF-8".into()))?;
    let nums: Vec<usize> = body
        .split_whitespace()
        .map(|s| s.parse::<usize>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Pdf(format!("DocTimeStamp /ByteRange parse: {e}")))?;
    if nums.len() != 4 {
        return Err(Error::Pdf(
            "/Type/DocTimeStamp: /ByteRange must have 4 ints".into(),
        ));
    }
    let (r1_off, r1_len, r2_off, r2_len) = (nums[0], nums[1], nums[2], nums[3]);
    if r1_off + r1_len > pdf.len() || r2_off + r2_len > pdf.len() {
        return Err(Error::Pdf(
            "/Type/DocTimeStamp: /ByteRange exceeds PDF length".into(),
        ));
    }
    let mut byterange = Vec::with_capacity(r1_len + r2_len);
    byterange.extend_from_slice(&pdf[r1_off..r1_off + r1_len]);
    byterange.extend_from_slice(&pdf[r2_off..r2_off + r2_len]);

    // /Contents<hex>
    let c_tag = b"/Contents<";
    let c_open_rel = find_in(tail, c_tag).ok_or_else(|| {
        Error::Pdf("/Type/DocTimeStamp: /Contents not found".into())
    })?;
    let c_open = dts_pos + c_open_rel + c_tag.len() - 1;
    let c_close = pdf[c_open + 1..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| Error::Pdf("/Type/DocTimeStamp: /Contents '>' not found".into()))?
        + c_open
        + 1;
    let hex_str = std::str::from_utf8(&pdf[c_open + 1..c_close])
        .map_err(|_| Error::Pdf("/Type/DocTimeStamp: /Contents body not UTF-8".into()))?;
    let trimmed = trim_trailing_zero_pairs(hex_str);
    let token_der = hex::decode(trimmed).map_err(|e| {
        Error::Pdf(format!("/Type/DocTimeStamp /Contents hex decode: {e}"))
    })?;
    Ok(Some((byterange, token_der)))
}

/// Trim trailing `0` chars in pairs so the resulting hex decodes
/// only the CMS bytes, not the padding placeholder.
fn trim_trailing_zero_pairs(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end >= 2 && bytes[end - 1] == b'0' && bytes[end - 2] == b'0' {
        end -= 2;
    }
    &s[..end]
}
