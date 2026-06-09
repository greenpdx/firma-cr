// SPDX-License-Identifier: GPL-3.0-or-later
//! XAdES-B-B signing (XMLDSig + ETSI EN 319 132-1).
//!
//! Three modes per the spec — enveloped (Signature element nested
//! inside the root), enveloping (signed content inside Signature),
//! detached (signature in a separate file). The MVP here implements
//! **enveloped** mode; enveloping/detached are TODO follow-ups.
//!
//! Structure produced (simplified):
//!
//! ```xml
//! <root>
//!   ...original content...
//!   <ds:Signature Id="sig-1" xmlns:ds="...xmldsig#">
//!     <ds:SignedInfo>
//!       <ds:CanonicalizationMethod Algorithm="...xml-exc-c14n#"/>
//!       <ds:SignatureMethod Algorithm="...rsa-sha256"/>
//!       <ds:Reference URI="">
//!         <ds:Transforms>
//!           <ds:Transform Algorithm="...enveloped-signature"/>
//!           <ds:Transform Algorithm="...xml-exc-c14n#"/>
//!         </ds:Transforms>
//!         <ds:DigestMethod Algorithm="...sha256"/>
//!         <ds:DigestValue>...</ds:DigestValue>
//!       </ds:Reference>
//!       <ds:Reference URI="#xades-properties-1">
//!         <ds:Transforms>
//!           <ds:Transform Algorithm="...xml-exc-c14n#"/>
//!         </ds:Transforms>
//!         <ds:DigestMethod Algorithm="...sha256"/>
//!         <ds:DigestValue>...</ds:DigestValue>
//!       </ds:Reference>
//!     </ds:SignedInfo>
//!     <ds:SignatureValue>BASE64</ds:SignatureValue>
//!     <ds:KeyInfo>
//!       <ds:X509Data>
//!         <ds:X509Certificate>BASE64-cert</ds:X509Certificate>
//!       </ds:X509Data>
//!     </ds:KeyInfo>
//!     <ds:Object>
//!       <xades:QualifyingProperties xmlns:xades="..." Target="#sig-1">
//!         <xades:SignedProperties Id="xades-properties-1">
//!           <xades:SignedSignatureProperties>
//!             <xades:SigningTime>2026-...</xades:SigningTime>
//!             <xades:SigningCertificateV2>
//!               <xades:Cert>
//!                 <xades:CertDigest>
//!                   <ds:DigestMethod Algorithm="...sha256"/>
//!                   <ds:DigestValue>BASE64</ds:DigestValue>
//!                 </xades:CertDigest>
//!               </xades:Cert>
//!             </xades:SigningCertificateV2>
//!           </xades:SignedSignatureProperties>
//!         </xades:SignedProperties>
//!       </xades:QualifyingProperties>
//!     </ds:Object>
//!   </ds:Signature>
//! </root>
//! ```

use std::time::SystemTime;

use crate::c14n::excl_c14n;
use crate::cert::SignerCert;
use crate::digest::HashAlgo;
use crate::error::{Error, Result};
use crate::pkcs11_client::build_digest_info;
use crate::revocation::RevocationData;
use crate::signer::Signer;

const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

pub type TimestampFn = Box<dyn Fn(&[u8]) -> crate::error::Result<Vec<u8>>>;

pub struct XadesBuilder<'a> {
    xml: &'a [u8],
    hash_algo: HashAlgo,
    cert: &'a SignerCert,
    chain: Vec<&'a SignerCert>,
    signing_time: SystemTime,
    sig_id: String,
    props_id: String,
    timestamp_fn: Option<TimestampFn>,
    revocation_data: Option<RevocationData>,
    archive_timestamp_fn: Option<TimestampFn>,
}

impl<'a> XadesBuilder<'a> {
    pub fn new(xml: &'a [u8], hash_algo: HashAlgo, cert: &'a SignerCert) -> Self {
        Self {
            xml,
            hash_algo,
            cert,
            chain: Vec::new(),
            signing_time: SystemTime::now(),
            sig_id: "sig-1".to_string(),
            props_id: "xades-properties-1".to_string(),
            timestamp_fn: None,
            revocation_data: None,
            archive_timestamp_fn: None,
        }
    }

    /// Lift to XAdES-B-LT by embedding pre-fetched OCSP + CRL data
    /// inside `<xades:RevocationValues>`.
    pub fn with_revocation_data(mut self, rev: RevocationData) -> Self {
        self.revocation_data = Some(rev);
        self
    }

    /// Lift to XAdES-B-LTA by attaching an `<xades:ArchiveTimeStamp>`
    /// (ETSI EN 319 132-1 §5.5.2). The callback receives the
    /// pre-hash imprint bytes (a concatenation of every covered
    /// reference + SignedInfo + SignatureValue + KeyInfo +
    /// preceding unsigned signature properties, each Exclusive
    /// c14n'd) and returns a TimeStampToken DER.
    pub fn with_archive_timestamp<F>(mut self, get_token: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>> + 'static,
    {
        self.archive_timestamp_fn = Some(Box::new(get_token));
        self
    }

    /// Lift to XAdES-B-T: after computing SignatureValue, request a
    /// TimeStampToken over the C14N(SignatureValue) bytes and embed
    /// it under `UnsignedSignatureProperties > SignatureTimeStamp`.
    pub fn with_timestamp<F>(mut self, get_token: F) -> Self
    where
        F: Fn(&[u8]) -> crate::error::Result<Vec<u8>> + 'static,
    {
        self.timestamp_fn = Some(Box::new(get_token));
        self
    }

    pub fn signing_time(mut self, t: SystemTime) -> Self {
        self.signing_time = t;
        self
    }

    /// Embed intermediate certs in `KeyInfo > X509Data`. Verifiers
    /// that don't have the issuer chain installed locally use these
    /// to build the trust path.
    pub fn include_chain(mut self, chain: Vec<&'a SignerCert>) -> Self {
        self.chain = chain;
        self
    }

    /// Build an enveloped XAdES-B-B signature: the Signature element
    /// is appended inside the source document just before the root's
    /// closing tag. Reference URI="" with the enveloped-signature
    /// transform per W3C XML-DSig.
    pub fn build_enveloped(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        let sig_element = self.build_signature_element(Mode::Enveloped, signer)?;
        insert_before_root_close(self.xml, sig_element.as_bytes())
    }

    /// Build an **enveloping** XAdES-B-B signature: `content` is
    /// wrapped inside `<ds:Object Id="obj-1">…</ds:Object>` of the
    /// Signature element, the URI="#obj-1" reference covers it via
    /// Exclusive c14n. Output is the standalone Signature XML.
    /// `content` MUST already be well-formed XML — the c14n
    /// transform requires that.
    pub fn build_enveloping(
        &self,
        content: &[u8],
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let s = self.build_signature_element(Mode::Enveloping { content }, signer)?;
        Ok(s.into_bytes())
    }

    /// Build a **detached** XAdES-B-B signature whose URI points at
    /// an external resource. `content` is the bytes that should be
    /// hashed for the digest (the verifier must supply the same
    /// bytes); `uri` is what literally appears as `URI="…"` on
    /// Reference 1. Output is the standalone Signature XML.
    pub fn build_detached(
        &self,
        content: &[u8],
        uri: &str,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let s = self.build_signature_element(Mode::Detached { content, uri }, signer)?;
        Ok(s.into_bytes())
    }

    /// Shared body: assembles the Signature element for any of the
    /// three XAdES modes. Differences live entirely in `mode`, which
    /// selects the URI value, the Transform list, the bytes that
    /// feed the Reference 1 digest, and whether `<ds:Object>` should
    /// wrap the content for enveloping mode.
    fn build_signature_element(
        &self,
        mode: Mode<'_>,
        signer: &dyn Signer,
    ) -> Result<String> {
        // --- Reference 1 — varies per mode. ---
        let (ref1_uri, ref1_transforms_inner, ref1_c14n_bytes) = match mode {
            Mode::Enveloped => {
                // The Signature element isn't in the document yet,
                // so c14n(original) == c14n(after stripping signature).
                let c14n = excl_c14n(self.xml)?;
                let xforms = format!(
                    r##"<ds:Transform Algorithm="{env}"></ds:Transform><ds:Transform Algorithm="{c14n_alg}"></ds:Transform>"##,
                    env = ALG_ENVELOPED,
                    c14n_alg = ALG_EXC_C14N,
                );
                (String::new(), xforms, c14n)
            }
            Mode::Enveloping { content } => {
                // The Object element gets its own xmlns:ds so its c14n
                // form is self-contained — the verifier extracts the
                // bytes between `<ds:Object` and `</ds:Object>` and
                // c14ns them directly, without needing to re-attach
                // namespace declarations.
                let content_str = std::str::from_utf8(content).map_err(|_| {
                    Error::Xml("enveloping content not UTF-8".into())
                })?;
                let wrapped = format!(
                    r##"<ds:Object xmlns:ds="{}" Id="{}">{}</ds:Object>"##,
                    NS_DS, ENVELOPING_OBJ_ID, content_str
                );
                let c14n = excl_c14n(wrapped.as_bytes())?;
                let xforms = format!(
                    r##"<ds:Transform Algorithm="{c14n_alg}"></ds:Transform>"##,
                    c14n_alg = ALG_EXC_C14N,
                );
                (format!("#{}", ENVELOPING_OBJ_ID), xforms, c14n)
            }
            Mode::Detached { content, uri } => {
                let c14n = excl_c14n(content)?;
                let xforms = format!(
                    r##"<ds:Transform Algorithm="{c14n_alg}"></ds:Transform>"##,
                    c14n_alg = ALG_EXC_C14N,
                );
                (uri.to_string(), xforms, c14n)
            }
        };
        let doc_c14n = ref1_c14n_bytes;
        let doc_digest = self.hash_algo.hash(&doc_c14n);
        let doc_digest_b64 = base64_encode(&doc_digest);

        // --- SignedProperties XML (independent block) ---
        let signing_time_iso = iso8601_z(self.signing_time);
        let cert_digest = self.cert.cert_digest(self.hash_algo);
        let cert_digest_b64 = base64_encode(&cert_digest);
        let cert_b64 = base64_encode(&self.cert.der);

        let signed_properties = format!(
            r#"<xades:SignedProperties xmlns:ds="{ds}" xmlns:xades="{xades}" Id="{pid}"><xades:SignedSignatureProperties><xades:SigningTime>{time}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="{dm}"></ds:DigestMethod><ds:DigestValue>{ch}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties>"#,
            ds = NS_DS,
            xades = NS_XADES,
            pid = self.props_id,
            time = signing_time_iso,
            dm = self.hash_algo.xmldsig_uri(),
            ch = cert_digest_b64,
        );
        let sp_c14n = excl_c14n(signed_properties.as_bytes())?;
        let sp_digest = self.hash_algo.hash(&sp_c14n);
        let sp_digest_b64 = base64_encode(&sp_digest);

        // --- SignedInfo (the bytes we actually sign) ---
        let signed_info = format!(
            r##"<ds:SignedInfo xmlns:ds="{ds}"><ds:CanonicalizationMethod Algorithm="{c14n}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{sigm}"></ds:SignatureMethod><ds:Reference URI="{ref1_uri}"><ds:Transforms>{ref1_transforms}</ds:Transforms><ds:DigestMethod Algorithm="{dm}"></ds:DigestMethod><ds:DigestValue>{dv1}</ds:DigestValue></ds:Reference><ds:Reference URI="#{pid}" Type="http://uri.etsi.org/01903#SignedProperties"><ds:Transforms><ds:Transform Algorithm="{c14n}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{dm}"></ds:DigestMethod><ds:DigestValue>{dv2}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
            ds = NS_DS,
            c14n = ALG_EXC_C14N,
            sigm = self.hash_algo.xmldsig_signature_uri(),
            dm = self.hash_algo.xmldsig_uri(),
            ref1_uri = ref1_uri,
            ref1_transforms = ref1_transforms_inner,
            dv1 = doc_digest_b64,
            pid = self.props_id,
            dv2 = sp_digest_b64,
        );

        let si_c14n = excl_c14n(signed_info.as_bytes())?;
        let si_digest = self.hash_algo.hash(&si_c14n);
        let digest_info = build_digest_info(self.hash_algo, &si_digest);
        let signature = signer.sign_digest_info(&digest_info)?;
        let sig_b64 = base64_encode(&signature);

        // KeyInfo X509Data with leaf + each chain cert as its own
        // <ds:X509Certificate> element. Order: leaf first, then any
        // intermediates the caller supplied via include_chain().
        let mut x509_certs = format!("<ds:X509Certificate>{cert_b64}</ds:X509Certificate>");
        for c in &self.chain {
            let chain_b64 = base64_encode(&c.der);
            x509_certs.push_str(&format!(
                "<ds:X509Certificate>{chain_b64}</ds:X509Certificate>"
            ));
        }

        // --- optional unsigned signature properties (T + LT + LTA) ---
        let mut usp_body = String::new();
        // C14N bytes of each preceding USP element, kept so the
        // archive-timestamp imprint computation below can include
        // them in document order.
        let mut preceding_usp_c14n: Vec<Vec<u8>> = Vec::new();

        if let Some(get_token) = &self.timestamp_fn {
            let sv_element = format!(
                "<ds:SignatureValue xmlns:ds=\"{}\">{}</ds:SignatureValue>",
                NS_DS, sig_b64,
            );
            let sv_c14n = excl_c14n(sv_element.as_bytes())?;
            let token_der = get_token(&sv_c14n)?;
            let token_b64 = base64_encode(&token_der);
            let sig_ts_element = format!(
                r##"<xades:SignatureTimeStamp xmlns:xades="{xades}" xmlns:ds="{ds}"><ds:CanonicalizationMethod Algorithm="{c14n}"></ds:CanonicalizationMethod><xades:EncapsulatedTimeStamp>{token}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>"##,
                xades = NS_XADES,
                ds = NS_DS,
                c14n = ALG_EXC_C14N,
                token = token_b64,
            );
            preceding_usp_c14n.push(excl_c14n(sig_ts_element.as_bytes())?);
            usp_body.push_str(&sig_ts_element);
        }
        if let Some(rev) = &self.revocation_data {
            if !rev.is_empty() {
                let rv_body = build_xades_revocation_values(rev)?;
                // Re-emit with xmlns:xades on the outer element so the
                // c14n bytes match what the verifier will reconstruct.
                let rv_with_ns = rv_body.replacen(
                    "<xades:RevocationValues>",
                    &format!("<xades:RevocationValues xmlns:xades=\"{NS_XADES}\">"),
                    1,
                );
                preceding_usp_c14n.push(excl_c14n(rv_with_ns.as_bytes())?);
                usp_body.push_str(&rv_body);
            }
        }
        if let Some(get_archive_token) = &self.archive_timestamp_fn {
            // --- Build the XAdES archive-time-stamp imprint per
            //     ETSI EN 319 132-1 §5.5.2. Concatenate, in document
            //     order, the Exclusive c14n of:
            //       1. each <ds:Reference>-covered data object
            //          (ref1 = the document, ref2 = SignedProperties)
            //       2. <ds:SignedInfo>
            //       3. <ds:SignatureValue>
            //       4. <ds:KeyInfo>
            //       5. every element already inside
            //          <UnsignedSignatureProperties> (collected above
            //          as preceding_usp_c14n).
            let mut imprint = Vec::new();
            imprint.extend_from_slice(&doc_c14n);
            imprint.extend_from_slice(&sp_c14n);
            imprint.extend_from_slice(&si_c14n);

            let sv_element = format!(
                "<ds:SignatureValue xmlns:ds=\"{}\">{}</ds:SignatureValue>",
                NS_DS, sig_b64,
            );
            imprint.extend_from_slice(&excl_c14n(sv_element.as_bytes())?);

            let ki_element = format!(
                "<ds:KeyInfo xmlns:ds=\"{}\"><ds:X509Data>{}</ds:X509Data></ds:KeyInfo>",
                NS_DS, x509_certs,
            );
            imprint.extend_from_slice(&excl_c14n(ki_element.as_bytes())?);

            for c14n in &preceding_usp_c14n {
                imprint.extend_from_slice(c14n);
            }

            let archive_token_der = get_archive_token(&imprint)?;
            let archive_token_b64 = base64_encode(&archive_token_der);
            usp_body.push_str(&format!(
                r##"<xades:ArchiveTimeStamp><ds:CanonicalizationMethod xmlns:ds="{ds}" Algorithm="{c14n}"></ds:CanonicalizationMethod><xades:EncapsulatedTimeStamp>{token}</xades:EncapsulatedTimeStamp></xades:ArchiveTimeStamp>"##,
                ds = NS_DS,
                c14n = ALG_EXC_C14N,
                token = archive_token_b64,
            ));
        }
        let unsigned_props = if usp_body.is_empty() {
            String::new()
        } else {
            format!(
                "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{usp_body}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
            )
        };

        // --- For enveloping mode, the signed payload lives inside a
        //     separate <ds:Object Id="…"> child of Signature. We emit
        //     it WITH its own xmlns:ds so that the bytes between
        //     `<ds:Object` and `</ds:Object>` are self-contained
        //     under Exclusive c14n. ---
        let content_object = match mode {
            Mode::Enveloping { content } => {
                let content_str = std::str::from_utf8(content).map_err(|_| {
                    Error::Xml("enveloping content not UTF-8".into())
                })?;
                format!(
                    r##"<ds:Object xmlns:ds="{}" Id="{}">{}</ds:Object>"##,
                    NS_DS, ENVELOPING_OBJ_ID, content_str
                )
            }
            _ => String::new(),
        };

        // --- assemble final Signature element ---
        let sig_element = format!(
            r##"<ds:Signature xmlns:ds="{ds}" Id="{sid}">{si}<ds:SignatureValue>{sv}</ds:SignatureValue><ds:KeyInfo><ds:X509Data>{x509}</ds:X509Data></ds:KeyInfo>{content_obj}<ds:Object><xades:QualifyingProperties xmlns:xades="{xades}" Target="#{sid}">{sp}{up}</xades:QualifyingProperties></ds:Object></ds:Signature>"##,
            ds = NS_DS,
            xades = NS_XADES,
            sid = self.sig_id,
            si = signed_info,
            sv = sig_b64,
            x509 = x509_certs,
            content_obj = content_object,
            sp = signed_properties,
            up = unsigned_props,
        );

        Ok(sig_element)
    }
}

/// Output mode for `XadesBuilder::build_signature_element`.
#[derive(Clone, Copy)]
enum Mode<'a> {
    Enveloped,
    Enveloping { content: &'a [u8] },
    Detached { content: &'a [u8], uri: &'a str },
}

const ENVELOPING_OBJ_ID: &str = "obj-1";

/// Find the *outermost* root element's closing tag and splice the
/// signature in just before it. Minimal byte-level surgery to avoid
/// re-serializing the entire document (which would risk changing the
/// digest the verifier computes against).
fn insert_before_root_close(xml: &[u8], to_insert: &[u8]) -> Result<Vec<u8>> {
    // Skip XML prolog if present and locate the first `<` of an
    // element name.
    let mut i = 0usize;
    if xml.starts_with(b"<?xml") {
        // skip past the closing `?>`
        let close = xml
            .windows(2)
            .position(|w| w == b"?>")
            .ok_or_else(|| Error::Xml("XML declaration missing closing ?>".into()))?;
        i = close + 2;
    }
    // Find the first '<' that begins a real element (not whitespace,
    // not a PI, not a comment).
    while i < xml.len() {
        match xml[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'<' if i + 1 < xml.len() && xml[i + 1] == b'?' => {
                // PI — skip
                let end = xml[i..].windows(2).position(|w| w == b"?>").ok_or_else(|| {
                    Error::Xml("PI missing closing ?>".into())
                })?;
                i += end + 2;
            }
            b'<' if xml[i..].starts_with(b"<!--") => {
                let end = xml[i..].windows(3).position(|w| w == b"-->").ok_or_else(|| {
                    Error::Xml("comment missing closing -->".into())
                })?;
                i += end + 3;
            }
            _ => break,
        }
    }
    let root_open_start = i;
    if root_open_start >= xml.len() || xml[root_open_start] != b'<' {
        return Err(Error::Xml("no root element found".into()));
    }
    // Read root element name (everything until whitespace or `>` or `/`)
    let mut j = root_open_start + 1;
    while j < xml.len() {
        let c = xml[j];
        if c == b'>' || c == b'/' || c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            break;
        }
        j += 1;
    }
    let root_name = &xml[root_open_start + 1..j];
    if root_name.is_empty() {
        return Err(Error::Xml("empty root element name".into()));
    }
    // Now find the matching closing tag `</root_name`. We do a
    // simple last-occurrence search, which is sufficient for the
    // single-root XAdES envelope shape. For nested duplicate names
    // a full parse would be needed.
    let needle: Vec<u8> = {
        let mut v = Vec::with_capacity(root_name.len() + 2);
        v.extend_from_slice(b"</");
        v.extend_from_slice(root_name);
        v
    };
    let close_pos = xml
        .windows(needle.len())
        .rposition(|w| w == needle.as_slice())
        .ok_or_else(|| {
            Error::Xml(format!(
                "could not find closing tag for root <{}>",
                std::str::from_utf8(root_name).unwrap_or("?")
            ))
        })?;

    let mut out = Vec::with_capacity(xml.len() + to_insert.len());
    out.extend_from_slice(&xml[..close_pos]);
    out.extend_from_slice(to_insert);
    out.extend_from_slice(&xml[close_pos..]);
    Ok(out)
}

/// Plain base64 encode (standard alphabet, no line wrapping).
fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(T[((n >> 18) & 0x3F) as usize] as char);
        out.push(T[((n >> 12) & 0x3F) as usize] as char);
        out.push(T[((n >> 6) & 0x3F) as usize] as char);
        out.push(T[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(T[((n >> 18) & 0x3F) as usize] as char);
        out.push(T[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(T[((n >> 18) & 0x3F) as usize] as char);
        out.push(T[((n >> 12) & 0x3F) as usize] as char);
        out.push(T[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

/// ISO 8601 UTC date string `YYYY-MM-DDTHH:MM:SSZ` (without fractional
/// seconds), used for SigningTime.
/// Build the `<xades:RevocationValues>` element body. Each
/// `EncapsulatedOCSPValue` carries base64 of a `BasicOCSPResponse`
/// (unwrapped from the outer `OCSPResponse`); each
/// `EncapsulatedCRLValue` carries base64 of a `CertificateList`.
fn build_xades_revocation_values(rev: &RevocationData) -> Result<String> {
    use der::Decode;
    use x509_ocsp::OcspResponse;
    let mut out = String::new();
    out.push_str("<xades:RevocationValues>");
    if !rev.crls.is_empty() {
        out.push_str("<xades:CRLValues>");
        for crl in &rev.crls {
            out.push_str(&format!(
                "<xades:EncapsulatedCRLValue>{}</xades:EncapsulatedCRLValue>",
                base64_encode(crl),
            ));
        }
        out.push_str("</xades:CRLValues>");
    }
    if !rev.ocsp_responses.is_empty() {
        out.push_str("<xades:OCSPValues>");
        for ocsp in &rev.ocsp_responses {
            let outer = OcspResponse::from_der(ocsp).map_err(|e| {
                Error::Xades(format!("re-decode OcspResponse for embedding: {e}"))
            })?;
            let bytes = outer.response_bytes.ok_or_else(|| {
                Error::Xades("OcspResponse missing responseBytes".into())
            })?;
            out.push_str(&format!(
                "<xades:EncapsulatedOCSPValue>{}</xades:EncapsulatedOCSPValue>",
                base64_encode(bytes.response.as_bytes()),
            ));
        }
        out.push_str("</xades:OCSPValues>");
    }
    out.push_str("</xades:RevocationValues>");
    Ok(out)
}

fn iso8601_z(t: SystemTime) -> String {
    let s = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d, h, mi, sec) = crate::pades::secs_to_utc_pub(s);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_known() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn insert_before_root_close_simple() {
        let xml = b"<root><child/></root>";
        let inserted = insert_before_root_close(xml, b"<sig/>").unwrap();
        assert_eq!(&inserted[..], b"<root><child/><sig/></root>");
    }

    #[test]
    fn insert_skips_xml_decl_and_pis() {
        let xml = b"<?xml version=\"1.0\"?><?style?><root>x</root>";
        let inserted = insert_before_root_close(xml, b"<sig/>").unwrap();
        let s = std::str::from_utf8(&inserted).unwrap();
        assert!(s.ends_with("x<sig/></root>"), "got {s}");
    }

    #[test]
    fn iso8601_shape() {
        let s = iso8601_z(SystemTime::UNIX_EPOCH);
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }
}
