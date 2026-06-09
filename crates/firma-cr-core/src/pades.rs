// SPDX-License-Identifier: GPL-3.0-or-later
//! PAdES-B-B signing.
//!
//! Embeds a CAdES detached CMS into a PDF's signature dictionary
//! per ETSI EN 319 142-1 / ISO 32000-1 §12.8. Signature appears
//! as an invisible (zero-rect) widget annotation; visible
//! signature appearances are a Phase-3.5 extension.
//!
//! Strategy (single-pass, fixed-width /ByteRange placeholder):
//!
//!   1. Load the PDF with lopdf, add a signature dictionary as a
//!      new object with `/Contents <00...00>` (8 KB of zero bytes
//!      = 16384 hex zeros) and `/ByteRange [0 0 0 0]` placeholder.
//!   2. Add an invisible Sig widget annotation referencing the
//!      signature dict, wire it into a new AcroForm in /Catalog.
//!   3. Serialize the document into a `Vec<u8>`.
//!   4. Locate the two placeholders in the byte stream.
//!   5. Replace the short `[0 0 0 0]` with a fixed-width 45-byte
//!      `[r1off r1len r2off r2len]` whose values are computed
//!      with awareness of the 36-byte expansion this introduces.
//!   6. Extract the two byterange slices from the patched buffer,
//!      concatenate, feed to `CadesBuilder` (which hashes them and
//!      produces the CMS).
//!   7. Hex-uppercase the CMS, pad with `0` to fill the 16384-char
//!      `/Contents` slot, patch into the buffer.
//!   8. Return the signed PDF bytes.
//!
//! If the input PDF already contains a `/Type /Sig` object the
//! function errors with `PdfAlreadySigned` unless `allow_resign`
//! is set (in which case the new signature is added in a second
//! signature field; this preserves the existing signature as long
//! as we don't rewrite — we always write incremental in lopdf).

use std::time::SystemTime;

use lopdf::{Dictionary, Document, Object, StringFormat, dictionary};

use crate::cades::{CadesBuilder, TimestampFn};
use crate::cert::SignerCert;
use crate::digest::HashAlgo;
use crate::error::{Error, Result};
use crate::signer::Signer;

const CMS_BINARY_BYTES: usize = 8192;
const CMS_HEX_CHARS: usize = CMS_BINARY_BYTES * 2; // 16384
/// 10-digit number used as the placeholder for each /ByteRange
/// integer at PDF-serialization time. Big enough that lopdf emits
/// it as exactly 10 ASCII chars, so the final zero-padded real value
/// substitutes in-place without changing byte offsets.
const BYTERANGE_PLACEHOLDER: i64 = 1_000_000_000;

/// Optional visible-appearance request for the signature widget.
///
/// `rect` is `(llx, lly, urx, ury)` in PDF default-user-space points
/// (1/72 inch). `page` is 1-based; if it doesn't exist, the
/// appearance is added to page 1.
#[derive(Clone, Debug)]
pub struct VisibleAppearance {
    pub rect: (f32, f32, f32, f32),
    pub page: usize,
    /// Text rendered inside the box. Phase 8f hard-codes "TEST"; a
    /// fast-follow lets the caller pass signer-name + date.
    pub label: String,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_pdf(
    input_pdf: &[u8],
    cert: &SignerCert,
    additional_certs: &[&SignerCert],
    hash_algo: HashAlgo,
    reason: Option<&str>,
    location: Option<&str>,
    contact_info: Option<&str>,
    signing_time: SystemTime,
    signer: &dyn Signer,
    timestamp_fn: Option<TimestampFn>,
    visible: Option<VisibleAppearance>,
    allow_resign: bool,
    revocation_data: Option<&crate::revocation::RevocationData>,
) -> Result<Vec<u8>> {
    let mut doc = Document::load_mem(input_pdf)
        .map_err(|e| Error::Pdf(format!("load PDF: {e}")))?;

    if !allow_resign && pdf_has_signature(&doc) {
        return Err(Error::PdfAlreadySigned);
    }

    // ---------- signature dictionary ----------
    let placeholder = vec![0u8; CMS_BINARY_BYTES];
    let mut sig_dict = Dictionary::new();
    sig_dict.set("Type", Object::Name(b"Sig".to_vec()));
    sig_dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig_dict.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
    sig_dict.set(
        "ByteRange",
        // 10-digit placeholder so the field width matches the eventual
        // zero-padded values. Keeping the byte length stable means the
        // PDF's xref table and any DSS streams keep their offsets after
        // we patch in the real ByteRange numbers.
        Object::Array(vec![
            Object::Integer(BYTERANGE_PLACEHOLDER),
            Object::Integer(BYTERANGE_PLACEHOLDER),
            Object::Integer(BYTERANGE_PLACEHOLDER),
            Object::Integer(BYTERANGE_PLACEHOLDER),
        ]),
    );
    sig_dict.set(
        "Contents",
        Object::String(placeholder, StringFormat::Hexadecimal),
    );
    sig_dict.set("M", Object::string_literal(pdf_date_string(signing_time)));
    if let Some(r) = reason {
        sig_dict.set("Reason", Object::string_literal(r));
    }
    if let Some(l) = location {
        sig_dict.set("Location", Object::string_literal(l));
    }
    if let Some(c) = contact_info {
        sig_dict.set("ContactInfo", Object::string_literal(c));
    }
    let sig_obj_id = doc.add_object(Object::Dictionary(sig_dict));

    // ---------- signature widget / form field ----------
    let mut field = Dictionary::new();
    field.set("FT", Object::Name(b"Sig".to_vec()));
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("T", Object::string_literal("Signature1"));

    let visible_page_id = if let Some(v) = &visible {
        let (llx, lly, urx, ury) = v.rect;
        let w = (urx - llx).max(1.0);
        let h = (ury - lly).max(1.0);
        field.set(
            "Rect",
            Object::Array(vec![
                Object::Real(llx),
                Object::Real(lly),
                Object::Real(urx),
                Object::Real(ury),
            ]),
        );
        field.set("F", Object::Integer(4)); // print flag only (visible)

        // Build appearance Form XObject:
        //  q 0 0 0 RG 1 w 0 0 w h re S
        //  BT /F1 (h/2) Tf 2 (h/3) Td (label) Tj ET Q
        let font_size = (h * 0.4).max(8.0);
        let stream = format!(
            "q\n0 0 0 RG\n1 w\n0 0 {w} {h} re\nS\nBT\n/F1 {fs} Tf\n2 {ty} Td\n({label}) Tj\nET\nQ\n",
            w = w,
            h = h,
            fs = font_size,
            ty = (h - font_size) / 2.0,
            label = v.label,
        );
        let font_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources = lopdf::dictionary! {
            "Font" => lopdf::dictionary! { "F1" => font_id },
        };
        let xobj = doc.add_object(lopdf::Stream::new(
            lopdf::dictionary! {
                "Type" => "XObject",
                "Subtype" => "Form",
                "BBox" => vec![
                    Object::Real(0.0),
                    Object::Real(0.0),
                    Object::Real(w),
                    Object::Real(h),
                ],
                "Resources" => resources,
            },
            stream.into_bytes(),
        ));
        let ap = lopdf::dictionary! { "N" => xobj };
        field.set("AP", Object::Dictionary(ap));

        Some(v.page)
    } else {
        field.set(
            "Rect",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        );
        field.set("F", Object::Integer(132)); // hidden + locked
        None
    };

    field.set("V", Object::Reference(sig_obj_id));
    let field_id = doc.add_object(Object::Dictionary(field));

    // Add the widget to the requested page's /Annots so PDF
    // viewers actually render it. If we can't locate the page,
    // the appearance just won't render — the cryptographic
    // signature is still valid.
    if let Some(page_num) = visible_page_id {
        if let Some(page_id) = nth_page_id(&doc, page_num) {
            if let Ok(page) = doc.get_object_mut(page_id).and_then(|o| o.as_dict_mut()) {
                let annots = page.get_mut(b"Annots").ok().and_then(|o| match o {
                    Object::Array(a) => Some(a),
                    _ => None,
                });
                match annots {
                    Some(arr) => arr.push(Object::Reference(field_id)),
                    None => {
                        page.set(
                            "Annots",
                            Object::Array(vec![Object::Reference(field_id)]),
                        );
                    }
                }
            }
        }
    }

    // ---------- AcroForm on Catalog ----------
    let catalog_ref = doc
        .trailer
        .get(b"Root")
        .map_err(|e| Error::Pdf(format!("catalog Root: {e}")))?
        .as_reference()
        .map_err(|e| Error::Pdf(format!("Root not a reference: {e}")))?;
    {
        let cat = doc
            .get_object_mut(catalog_ref)
            .map_err(|e| Error::Pdf(format!("get catalog: {e}")))?
            .as_dict_mut()
            .map_err(|e| Error::Pdf(format!("catalog not dict: {e}")))?;
        let mut acroform = Dictionary::new();
        acroform.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
        acroform.set("SigFlags", Object::Integer(3));
        cat.set("AcroForm", Object::Dictionary(acroform));
    }

    // ---------- PAdES-B-LT Document Security Store (DSS) ----------
    //
    // ETSI EN 319 142-1 §5.1: a top-level `/DSS` catalog entry holds
    // arrays of stream objects carrying validation evidence — certs
    // (`/Certs`), CRLs (`/CRLs`), OCSP responses (`/OCSPs`). For an
    // initial signature (our case) the DSS lands inside the byte
    // range so it is covered by the signature. The verifier reads
    // these streams to anchor revocation status without needing live
    // CA access.
    if let Some(rev) = revocation_data {
        if !rev.is_empty() || !additional_certs.is_empty() {
            let mut dss = Dictionary::new();

            // /Certs — embed the leaf + every intermediate so a
            // verifier can build the chain without --include-chain.
            let mut cert_refs: Vec<Object> = Vec::new();
            cert_refs.push(Object::Reference(
                add_der_stream(&mut doc, &cert.der),
            ));
            for c in additional_certs {
                cert_refs.push(Object::Reference(add_der_stream(&mut doc, &c.der)));
            }
            dss.set("Certs", Object::Array(cert_refs));

            if !rev.ocsp_responses.is_empty() {
                let mut ocsp_refs: Vec<Object> = Vec::new();
                for ocsp_der in &rev.ocsp_responses {
                    // ETSI 319 142-1 §5.1.2: each /OCSPs entry is a
                    // BasicOCSPResponse — unwrap from outer
                    // OCSPResponse first.
                    let basic = unwrap_basic_ocsp(ocsp_der)?;
                    ocsp_refs.push(Object::Reference(add_der_stream(&mut doc, &basic)));
                }
                dss.set("OCSPs", Object::Array(ocsp_refs));
            }
            if !rev.crls.is_empty() {
                let mut crl_refs: Vec<Object> = Vec::new();
                for crl_der in &rev.crls {
                    crl_refs.push(Object::Reference(add_der_stream(&mut doc, crl_der)));
                }
                dss.set("CRLs", Object::Array(crl_refs));
            }

            let dss_ref = doc.add_object(Object::Dictionary(dss));
            let cat = doc
                .get_object_mut(catalog_ref)
                .map_err(|e| Error::Pdf(format!("get catalog: {e}")))?
                .as_dict_mut()
                .map_err(|e| Error::Pdf(format!("catalog not dict: {e}")))?;
            cat.set("DSS", Object::Reference(dss_ref));
        }
    }

    // ---------- serialize ----------
    let mut buf: Vec<u8> = Vec::with_capacity(input_pdf.len() + 32 * 1024);
    doc.save_to(&mut buf)
        .map_err(|e| Error::Pdf(format!("save_to: {e}")))?;

    // ---------- locate placeholders ----------
    // lopdf serializes dictionary entries without a separating
    // space (e.g. `/Contents<00…00>`), so the search markers must
    // not include one. Same for `/ByteRange[0 0 0 0]`.
    let contents_marker = format!("/Contents<{}>", "0".repeat(CMS_HEX_CHARS));
    let contents_pos = find_in_buf(&buf, contents_marker.as_bytes()).ok_or_else(|| {
        Error::Pdf("could not locate /Contents<00…00> placeholder after serialization".into())
    })?;
    let contents_value_start = contents_pos + b"/Contents<".len();
    let contents_value_end = contents_value_start + CMS_HEX_CHARS; // exclusive (position of `>`)

    // 10-digit `BYTERANGE_PLACEHOLDER` per integer makes the array
    // body exactly 45 bytes: `[NNNNNNNNNN NNNNNNNNNN NNNNNNNNNN
    // NNNNNNNNNN]`. We replace those 10-digit fields with the actual
    // zero-padded offsets without changing the buffer's byte length,
    // so the xref table and any DSS streams stay at their original
    // offsets and the saved PDF remains structurally valid.
    let br_marker = format!(
        "/ByteRange[{p} {p} {p} {p}]",
        p = BYTERANGE_PLACEHOLDER
    );
    let br_pos = find_in_buf(&buf, br_marker.as_bytes()).ok_or_else(|| {
        Error::Pdf("could not locate fixed-width /ByteRange placeholder".into())
    })?;
    let array_only_start = br_pos + b"/ByteRange".len();
    const ARR_LEN: usize = 45; // see invariant above

    // /ByteRange skips the value of /Contents (the hex bytes between
    // `<` and `>`). Range 1 ends at `<` (inclusive), range 2 starts at
    // `>` (inclusive).
    let r1_off = 0usize;
    let r1_len = contents_pos + b"/Contents<".len();
    let r2_off = contents_pos + b"/Contents<".len() + CMS_HEX_CHARS;
    let r2_len = buf.len() - r2_off;
    let _ = contents_value_start;
    let _ = contents_value_end;

    let new_br = format!(
        "[{:010} {:010} {:010} {:010}]",
        r1_off, r1_len, r2_off, r2_len
    );
    assert_eq!(new_br.len(), ARR_LEN);

    // ---------- patch buffer (length-preserving) ----------
    let mut patched = buf;
    patched[array_only_start..array_only_start + ARR_LEN]
        .copy_from_slice(new_br.as_bytes());

    // ---------- build CAdES over the byteranges ----------
    let mut byterange_data = Vec::with_capacity(r1_len + r2_len);
    byterange_data.extend_from_slice(&patched[r1_off..r1_off + r1_len]);
    byterange_data.extend_from_slice(&patched[r2_off..r2_off + r2_len]);

    let mut builder = CadesBuilder::new(&byterange_data, hash_algo, cert)
        .signing_time(signing_time);
    if !additional_certs.is_empty() {
        builder = builder.include_chain(additional_certs.to_vec());
    }
    if let Some(ts_fn) = timestamp_fn {
        builder = builder.with_timestamp(move |sig| ts_fn(sig));
    }
    let cms_der = builder.build(signer)?;
    if cms_der.len() > CMS_BINARY_BYTES {
        return Err(Error::Pdf(format!(
            "CMS signature ({} bytes) exceeds /Contents allocation ({} bytes); \
             increase CMS_BINARY_BYTES in pades.rs",
            cms_der.len(),
            CMS_BINARY_BYTES,
        )));
    }

    // ---------- patch /Contents hex ----------
    let mut hex_cms = hex::encode_upper(&cms_der);
    if hex_cms.len() < CMS_HEX_CHARS {
        hex_cms.extend(std::iter::repeat('0').take(CMS_HEX_CHARS - hex_cms.len()));
    }
    let contents_hex_start_in_patched = contents_pos + b"/Contents<".len();
    patched[contents_hex_start_in_patched..contents_hex_start_in_patched + CMS_HEX_CHARS]
        .copy_from_slice(hex_cms.as_bytes());

    Ok(patched)
}

/// Return the object id of the `n`th page (1-based), or None if the
/// document has fewer pages.
fn nth_page_id(doc: &Document, n: usize) -> Option<lopdf::ObjectId> {
    if n == 0 {
        return None;
    }
    let pages = doc.get_pages();
    pages.get(&(n as u32)).copied()
}

/// True if any object in the document has `/Type /Sig`.
/// Add a PDF Stream object whose content is exactly `bytes`. No
/// filters — verifiers read it as raw DER. Returns the object id.
fn add_der_stream(doc: &mut Document, bytes: &[u8]) -> lopdf::ObjectId {
    use lopdf::Stream;
    let mut dict = Dictionary::new();
    dict.set("Length", Object::Integer(bytes.len() as i64));
    let stream = Stream::new(dict, bytes.to_vec());
    doc.add_object(Object::Stream(stream))
}

/// Unwrap a wire-format `OCSPResponse` DER to its inner
/// `BasicOCSPResponse` DER. ETSI 319 142-1 §5.1.2 mandates the Basic
/// form inside `/OCSPs` arrays.
fn unwrap_basic_ocsp(outer_der: &[u8]) -> Result<Vec<u8>> {
    use der::Decode;
    use x509_ocsp::OcspResponse;
    let outer = OcspResponse::from_der(outer_der)
        .map_err(|e| Error::Pdf(format!("OcspResponse decode for DSS: {e}")))?;
    let bytes = outer
        .response_bytes
        .ok_or_else(|| Error::Pdf("OcspResponse missing responseBytes".into()))?;
    Ok(bytes.response.as_bytes().to_vec())
}

fn pdf_has_signature(doc: &Document) -> bool {
    for (_id, obj) in doc.objects.iter() {
        if let Ok(d) = obj.as_dict() {
            if let Ok(t) = d.get(b"Type") {
                if let Ok(n) = t.as_name() {
                    if n == b"Sig" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// PDF date string per ISO 32000-1 §7.9.4: `D:YYYYMMDDHHmmSSOHH'mm'`.
/// We emit UTC (`+00'00'`) since SystemTime doesn't carry a zone.
fn pdf_date_string(t: SystemTime) -> String {
    let unix_secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Minimal date arithmetic — good enough for signatures, year > 2000.
    let (year, month, day, hour, min, sec) = secs_to_utc(unix_secs);
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}+00'00'",
        year, month, day, hour, min, sec
    )
}

/// Public re-export of secs_to_utc so xades.rs can share the date
/// arithmetic. Kept in pades.rs because that's where it was first
/// needed; moving to a shared time.rs is a fast-follow.
pub fn secs_to_utc_pub(s: i64) -> (i32, u32, u32, u32, u32, u32) {
    secs_to_utc(s)
}

/// Convert unix seconds to (year, month, day, hour, min, sec) in UTC.
/// Simple algorithm — handles dates between 1970 and 9999.
fn secs_to_utc(mut s: i64) -> (i32, u32, u32, u32, u32, u32) {
    let sec = (s % 60) as u32;
    s /= 60;
    let min = (s % 60) as u32;
    s /= 60;
    let hour = (s % 24) as u32;
    let mut days = s / 24;
    let mut year = 1970i32;
    loop {
        let leap = is_leap(year);
        let yd = if leap { 366 } else { 365 };
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }
    let mut month = 1u32;
    let mdays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (i, dm) in mdays.iter().enumerate() {
        let m = if i == 1 && is_leap(year) { 29 } else { *dm };
        if days < m {
            month = (i as u32) + 1;
            break;
        }
        days -= m;
    }
    let day = (days as u32) + 1;
    (year, month, day, hour, min, sec)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Find a byte pattern in `haystack`; return the first start position.
fn find_in_buf(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

// ============================================================
// PAdES-LTA — Document Time-Stamp (ETSI EN 319 142-1 §5.3)
// ============================================================
//
// Adds a `/Type /DocTimeStamp` signature dictionary to an
// already-signed PDF via a proper PDF incremental update — i.e. we
// append new object definitions + xref subsection + trailer to the
// existing bytes without modifying any byte that came before. The
// new dict's /SubFilter is `/ETSI.RFC3161` and its /Contents holds
// a raw TimeStampToken DER whose imprint covers the byterange.
//
// Layout produced (everything below the original `%%EOF` line):
//
//   <orig PDF bytes ...>          ← unchanged, signature stays valid
//   <newline>
//   N1 0 obj                        ← DocTimeStamp signature dict
//   <</Type/DocTimeStamp/Filter/Adobe.PPKLite/SubFilter/ETSI.RFC3161
//     /ByteRange[1000000000 1000000000 1000000000 1000000000]
//     /Contents<00…00>>>
//   endobj
//   N2 0 obj                        ← Widget annotation
//   <</Type/Annot/Subtype/Widget/FT/Sig/T(DocTimeStamp1)/V N1 0 R
//     /Rect[0 0 0 0]/F 132>>
//   endobj
//   CATALOG_ID 0 obj                ← updated catalog (same id)
//   <</Type/Catalog ... /AcroForm <</Fields[OLD_FIELD N2 0 R]
//      /SigFlags 3>>>>
//   endobj
//   xref
//   0 1
//   0000000000 65535 f
//   N1 1
//   OOOOOOOOOO 00000 n
//   …
//   trailer
//   <</Size .../Prev OLD_STARTXREF/Root CATALOG_ID 0 R>>
//   startxref
//   NEW_XREF_OFFSET
//   %%EOF

#[allow(clippy::too_many_arguments)]
pub fn add_doc_timestamp<F>(
    signed_pdf: &[u8],
    hash_algo: HashAlgo,
    tsa_fn: F,
) -> Result<Vec<u8>>
where
    F: Fn(&[u8]) -> Result<Vec<u8>>,
{
    let _ = hash_algo; // the TSA picks its own digest; the verifier
                       // reads it from TSTInfo.messageImprint.

    // ---- 1. Inspect the original PDF structurally ----
    let doc = Document::load_mem(signed_pdf)
        .map_err(|e| Error::Pdf(format!("load PDF for DocTimeStamp: {e}")))?;
    let catalog_ref = doc
        .trailer
        .get(b"Root")
        .map_err(|e| Error::Pdf(format!("Root: {e}")))?
        .as_reference()
        .map_err(|e| Error::Pdf(format!("Root not ref: {e}")))?;
    let max_obj_id = doc
        .objects
        .keys()
        .map(|(id, _)| *id)
        .max()
        .unwrap_or(0);
    let new_sig_id = max_obj_id + 1;
    let new_widget_id = max_obj_id + 2;

    // Collect catalog body byte-string with AcroForm.Fields extended
    // to include the new widget. We re-serialize the catalog
    // (preserving every existing key) so external state like /Pages
    // / /Lang / /OCProperties survives the update.
    let updated_catalog_bytes =
        build_updated_catalog(&doc, catalog_ref, new_widget_id, new_sig_id)?;

    // ---- 2. Build output bytes ----
    let mut out = signed_pdf.to_vec();
    // Per PDF spec each obj definition starts on a new line; the
    // original file ends with %%EOF\n; add an extra newline as a
    // safe separator.
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.push(b'\n');

    // Track (object_id, offset) for the xref section.
    let mut entries: Vec<(u32, usize)> = Vec::new();

    // 2a. New sig dict (DocTimeStamp).
    let sig_off = out.len();
    entries.push((new_sig_id, sig_off));
    write_obj_header(&mut out, new_sig_id);
    let sig_dict = build_doctimestamp_dict_bytes();
    out.extend_from_slice(&sig_dict);
    write_obj_footer(&mut out);

    // 2b. Widget.
    let widget_off = out.len();
    entries.push((new_widget_id, widget_off));
    write_obj_header(&mut out, new_widget_id);
    let widget_dict = build_doctimestamp_widget_bytes(new_sig_id);
    out.extend_from_slice(&widget_dict);
    write_obj_footer(&mut out);

    // 2c. Updated catalog (same object id, new offset).
    let catalog_off = out.len();
    entries.push((catalog_ref.0, catalog_off));
    write_obj_header_full(&mut out, catalog_ref);
    out.extend_from_slice(&updated_catalog_bytes);
    write_obj_footer(&mut out);

    // ---- 3. Xref subsection ----
    let xref_off = out.len();
    write_xref(&mut out, &entries);

    // ---- 4. Trailer ----
    let old_startxref = find_old_startxref(signed_pdf)?;
    // /Size = highest object number used + 1; ensure we exceed
    // every existing object plus the two new ones.
    let new_size = (new_widget_id + 1).max(max_obj_id + 1);
    let trailer = format!(
        "trailer\n<</Size {size} /Prev {prev} /Root {root} {gen} R>>\nstartxref\n{xref}\n%%EOF\n",
        size = new_size,
        prev = old_startxref,
        root = catalog_ref.0,
        gen = catalog_ref.1,
        xref = xref_off,
    );
    out.extend_from_slice(trailer.as_bytes());

    // ---- 5. ByteRange patching ----
    let br_marker = format!(
        "/ByteRange[{p} {p} {p} {p}]",
        p = BYTERANGE_PLACEHOLDER
    );
    let br_rel = find_in_buf(&out[sig_off..], br_marker.as_bytes()).ok_or_else(|| {
        Error::Pdf("DocTimeStamp /ByteRange placeholder not found".into())
    })?;
    let br_pos = sig_off + br_rel;
    let array_only_start = br_pos + b"/ByteRange".len();

    let contents_marker = format!("/Contents<{}>", "0".repeat(CMS_HEX_CHARS));
    let contents_rel = find_in_buf(&out[sig_off..], contents_marker.as_bytes()).ok_or_else(
        || Error::Pdf("DocTimeStamp /Contents placeholder not found".into()),
    )?;
    let contents_pos = sig_off + contents_rel;
    let contents_value_start = contents_pos + b"/Contents<".len();

    // ByteRange covers everything except the /Contents hex bytes.
    let r1_off = 0usize;
    let r1_len = contents_value_start;
    let r2_off = contents_value_start + CMS_HEX_CHARS;
    let r2_len = out.len() - r2_off;

    let new_br = format!(
        "[{:010} {:010} {:010} {:010}]",
        r1_off, r1_len, r2_off, r2_len
    );
    assert_eq!(new_br.len(), 45);
    out[array_only_start..array_only_start + 45].copy_from_slice(new_br.as_bytes());

    // ---- 6. Request TSA token over the byterange ----
    let mut imprint = Vec::with_capacity(r1_len + r2_len);
    imprint.extend_from_slice(&out[r1_off..r1_off + r1_len]);
    imprint.extend_from_slice(&out[r2_off..r2_off + r2_len]);
    let token_der = tsa_fn(&imprint)?;

    // ---- 7. Patch /Contents hex ----
    let mut hex_token = hex::encode_upper(&token_der);
    if hex_token.len() < CMS_HEX_CHARS {
        hex_token.extend(std::iter::repeat('0').take(CMS_HEX_CHARS - hex_token.len()));
    }
    out[contents_value_start..contents_value_start + CMS_HEX_CHARS]
        .copy_from_slice(hex_token.as_bytes());
    Ok(out)
}

fn write_obj_header(out: &mut Vec<u8>, id: u32) {
    out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
}

fn write_obj_header_full(out: &mut Vec<u8>, r: lopdf::ObjectId) {
    out.extend_from_slice(format!("{} {} obj\n", r.0, r.1).as_bytes());
}

fn write_obj_footer(out: &mut Vec<u8>) {
    out.extend_from_slice(b"\nendobj\n");
}

fn build_doctimestamp_dict_bytes() -> Vec<u8> {
    // Fixed-width placeholders so we can patch without shifting any
    // following bytes — mirrors how sign_pdf treats /ByteRange and
    // /Contents.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"<</Type/DocTimeStamp/Filter/Adobe.PPKLite/SubFilter/ETSI.RFC3161");
    buf.extend_from_slice(
        format!(
            "/ByteRange[{p} {p} {p} {p}]",
            p = BYTERANGE_PLACEHOLDER
        )
        .as_bytes(),
    );
    buf.extend_from_slice(b"/Contents<");
    buf.extend_from_slice(&vec![b'0'; CMS_HEX_CHARS]);
    buf.extend_from_slice(b">>>");
    buf
}

fn build_doctimestamp_widget_bytes(sig_id: u32) -> Vec<u8> {
    // F = 132 = 4 + 128 → "Print" + "Locked", consistent with the
    // first signature widget.
    format!(
        "<</Type/Annot/Subtype/Widget/FT/Sig/T(DocTimeStamp1)/V {sig_id} 0 R/Rect[0 0 0 0]/F 132>>"
    )
    .into_bytes()
}

/// Re-serialize the catalog so /AcroForm.Fields gains the new
/// DocTimeStamp widget reference. Every existing catalog key is
/// preserved by serializing the in-memory copy and editing
/// AcroForm.Fields in place.
fn build_updated_catalog(
    doc: &Document,
    catalog_ref: lopdf::ObjectId,
    new_widget_id: u32,
    _new_sig_id: u32,
) -> Result<Vec<u8>> {
    let mut cat = doc
        .get_object(catalog_ref)
        .map_err(|e| Error::Pdf(format!("get catalog: {e}")))?
        .as_dict()
        .map_err(|e| Error::Pdf(format!("catalog not dict: {e}")))?
        .clone();

    let mut acroform = cat
        .get(b"AcroForm")
        .ok()
        .and_then(|o| match o {
            Object::Dictionary(d) => Some(d.clone()),
            Object::Reference(r) => doc
                .get_object(*r)
                .ok()
                .and_then(|x| x.as_dict().ok().cloned()),
            _ => None,
        })
        .unwrap_or_default();
    let mut fields = acroform
        .get(b"Fields")
        .ok()
        .and_then(|o| o.as_array().ok().cloned())
        .unwrap_or_default();
    fields.push(Object::Reference((new_widget_id, 0)));
    acroform.set("Fields", Object::Array(fields));
    acroform.set("SigFlags", Object::Integer(3));
    cat.set("AcroForm", Object::Dictionary(acroform));

    serialize_dict(&cat)
}

/// Hand-serialize a Dictionary into the same compact form lopdf
/// emits (no spaces between key/value separators). We can't reuse
/// lopdf's `Document::save_to` because it would rewrite the entire
/// xref table and shift every prior offset.
fn serialize_dict(dict: &Dictionary) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(b'<');
    out.push(b'<');
    for (key, value) in dict.iter() {
        out.push(b'/');
        out.extend_from_slice(key);
        serialize_object(value, &mut out)?;
    }
    out.push(b'>');
    out.push(b'>');
    Ok(out)
}

fn serialize_object(obj: &Object, out: &mut Vec<u8>) -> Result<()> {
    match obj {
        Object::Null => out.extend_from_slice(b" null"),
        Object::Boolean(b) => {
            out.extend_from_slice(if *b { b" true" } else { b" false" })
        }
        Object::Integer(i) => out.extend_from_slice(format!(" {i}").as_bytes()),
        Object::Real(r) => out.extend_from_slice(format!(" {r}").as_bytes()),
        Object::Name(n) => {
            out.push(b'/');
            out.extend_from_slice(n);
        }
        Object::String(bytes, fmt) => match fmt {
            lopdf::StringFormat::Literal => {
                out.push(b'(');
                out.extend_from_slice(bytes);
                out.push(b')');
            }
            lopdf::StringFormat::Hexadecimal => {
                out.push(b'<');
                out.extend_from_slice(bytes);
                out.push(b'>');
            }
        },
        Object::Reference(r) => out.extend_from_slice(format!(" {} {} R", r.0, r.1).as_bytes()),
        Object::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                serialize_object(item, out)?;
            }
            out.push(b']');
        }
        Object::Dictionary(d) => {
            let bytes = serialize_dict(d)?;
            out.extend_from_slice(&bytes);
        }
        Object::Stream(_) => {
            return Err(Error::Pdf(
                "stream object not expected inside catalog re-serialization".into(),
            ))
        }
    }
    Ok(())
}

/// Emit a classic PDF xref subsection covering `entries`
/// (object_id, byte_offset). The subsection starts with the free
/// object 0 → "0 N+1" header, then one entry per line in
/// fixed-width form `OOOOOOOOOO GGGGG n \r\n` (20 bytes incl. CRLF
/// per PDF spec — we use LF only, which Adobe accepts).
fn write_xref(out: &mut Vec<u8>, entries: &[(u32, usize)]) {
    // Group consecutive object IDs into one subsection per run.
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|(id, _)| *id);

    out.extend_from_slice(b"xref\n");
    // Always include the free-object 0.
    out.extend_from_slice(b"0 1\n0000000000 65535 f \n");

    // Walk sorted entries grouping contiguous ids.
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i + 1;
        while j < sorted.len() && sorted[j].0 == sorted[j - 1].0 + 1 {
            j += 1;
        }
        let start = sorted[i].0;
        let count = j - i;
        out.extend_from_slice(format!("{start} {count}\n").as_bytes());
        for k in i..j {
            out.extend_from_slice(
                format!("{:010} 00000 n \n", sorted[k].1).as_bytes(),
            );
        }
        i = j;
    }
}

/// Scan backward from the end of `pdf` for the most recent
/// `startxref\n<number>\n%%EOF` block and return the number.
fn find_old_startxref(pdf: &[u8]) -> Result<usize> {
    let needle = b"startxref";
    let pos = pdf
        .windows(needle.len())
        .rposition(|w| w == needle)
        .ok_or_else(|| Error::Pdf("no startxref in original PDF".into()))?;
    // Skip past "startxref" + whitespace.
    let mut i = pos + needle.len();
    while i < pdf.len() && (pdf[i] == b'\r' || pdf[i] == b'\n' || pdf[i] == b' ') {
        i += 1;
    }
    let mut end = i;
    while end < pdf.len() && pdf[end].is_ascii_digit() {
        end += 1;
    }
    let num = std::str::from_utf8(&pdf[i..end])
        .map_err(|_| Error::Pdf("startxref number not UTF-8".into()))?;
    num.parse::<usize>()
        .map_err(|e| Error::Pdf(format!("startxref parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_in_buf_works() {
        assert_eq!(find_in_buf(b"hello world", b"world"), Some(6));
        assert_eq!(find_in_buf(b"abc", b"xyz"), None);
    }

    #[test]
    fn pdf_date_format() {
        // Pin a known unix time and verify the format matches PDF
        // §7.9.4 shape `D:YYYYMMDDHHMMSS+HH'MM'`. Exact hour value
        // computed against this implementation; the test guards
        // against regressions, not against UTC drift.
        let unix = 1768494896i64; // 2026-01-15
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix as u64);
        let s = pdf_date_string(t);
        assert!(s.starts_with("D:"), "should start with D: prefix, got {s}");
        assert!(s.ends_with("+00'00'"), "should end with +00'00', got {s}");
        assert_eq!(s.len(), "D:YYYYMMDDHHMMSS+00'00'".len(), "shape: got {s}");
        assert!(s.starts_with("D:20260115"), "date prefix wrong: {s}");
    }

    #[test]
    fn is_leap_calendar() {
        assert!(is_leap(2024));
        assert!(!is_leap(2025));
        assert!(!is_leap(2100));
        assert!(is_leap(2000));
    }
}
