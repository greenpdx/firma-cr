// SPDX-License-Identifier: GPL-3.0-or-later
//! RFC 6960 OCSP request building + response parsing.
//!
//! We wrap `x509-ocsp 0.2` (RustCrypto). Public surface:
//!
//!   * [`build_request`] — make an `OCSPRequest` for `cert` issued
//!     by `issuer`, optionally embedding a nonce extension.
//!   * [`parse_response`] — decode an `OCSPResponse`, locate the
//!     `SingleResponse` for `cert`'s CertID, and return its status.
//!
//! The `CertID.hashAlgorithm` field defaults to SHA-1 — that is the
//! RFC 6960 canonical hash and what virtually every public responder
//! still expects when computing `issuerNameHash` / `issuerKeyHash`.
//! It is unrelated to the cryptographic hash that protects the
//! signature itself.

use der::asn1::OctetString;
use der::{Decode, Encode};
use sha1::Sha1;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::ext::Nonce;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, Request,
    Version,
};

use crate::cert::SignerCert;
use crate::error::{Error, Result};

const OID_BASIC_OCSP_RESPONSE: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// Cert status as reported by a `SingleResponse`. We keep just the
/// fields the verifier actually consumes — the responder cert and
/// chain are inspected separately via the inner BasicOcspResponse.
#[derive(Debug, Clone)]
pub enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

/// Build an `OCSPRequest` DER asking about `cert`'s status from
/// `issuer`'s perspective. If `nonce` is `Some`, embed it as the
/// `id-pkix-ocsp-nonce` extension (RFC 6960 §4.4.1). The responder
/// is required to echo it iff it supports nonces.
pub fn build_request(
    cert: &SignerCert,
    issuer: &SignerCert,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let cert_id = CertId::from_cert::<Sha1>(&issuer.parsed, &cert.parsed)
        .map_err(|e| Error::Ocsp(format!("build CertID: {e}")))?;
    let req = Request {
        req_cert: cert_id,
        single_request_extensions: None,
    };
    let mut builder = OcspRequestBuilder::new(Version::V1).with_request(req);
    if let Some(n) = nonce {
        let nonce_ext = Nonce::new(n.to_vec())
            .map_err(|e| Error::Ocsp(format!("nonce: {e}")))?;
        builder = builder
            .with_extension(nonce_ext)
            .map_err(|e| Error::Ocsp(format!("attach nonce extension: {e}")))?;
    }
    let req = builder.build();
    req.to_der()
        .map_err(|e| Error::Ocsp(format!("encode OCSPRequest: {e}")))
}

/// What a verifier extracts from one OCSP response after status
/// checking. The DER bytes of the underlying `BasicOCSPResponse` are
/// preserved so we can re-validate signatures + chain elsewhere.
pub struct ParsedOcspResponse {
    pub status: OcspStatus,
    /// `BasicOCSPResponse` DER bytes (inner content of `responseBytes`).
    pub basic_response: BasicOcspResponse,
    /// Echoed nonce, if the responder supports the extension.
    pub echoed_nonce: Option<Vec<u8>>,
}

/// Parse an `OCSPResponse` DER blob and return the status of the
/// single response matching `cert` issued by `issuer`. Fails if the
/// status field isn't `successful(0)` or no matching SingleResponse
/// is found.
pub fn parse_response(
    response_der: &[u8],
    cert: &SignerCert,
    issuer: &SignerCert,
) -> Result<ParsedOcspResponse> {
    let outer = OcspResponse::from_der(response_der)
        .map_err(|e| Error::Ocsp(format!("OCSPResponse decode: {e}")))?;
    if outer.response_status != OcspResponseStatus::Successful {
        return Err(Error::Ocsp(format!(
            "OCSP responseStatus = {:?}",
            outer.response_status
        )));
    }
    let bytes = outer.response_bytes.ok_or_else(|| {
        Error::Ocsp("OCSPResponse status=successful but responseBytes missing".into())
    })?;
    if bytes.response_type != OID_BASIC_OCSP_RESPONSE {
        return Err(Error::Ocsp(format!(
            "responseType {} is not id-pkix-ocsp-basic",
            bytes.response_type
        )));
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())
        .map_err(|e| Error::Ocsp(format!("BasicOCSPResponse decode: {e}")))?;

    let want = CertId::from_cert::<Sha1>(&issuer.parsed, &cert.parsed)
        .map_err(|e| Error::Ocsp(format!("rebuild CertID for lookup: {e}")))?;
    let want_der = want
        .to_der()
        .map_err(|e| Error::Ocsp(format!("CertID to_der: {e}")))?;
    let sr = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|s| {
            s.cert_id
                .to_der()
                .map(|d| d == want_der)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            Error::Ocsp("no SingleResponse matches signer cert's CertID".into())
        })?;
    let status = match &sr.cert_status {
        CertStatus::Good(_) => OcspStatus::Good,
        CertStatus::Revoked(_) => OcspStatus::Revoked,
        CertStatus::Unknown(_) => OcspStatus::Unknown,
    };

    let echoed_nonce = basic
        .tbs_response_data
        .response_extensions
        .as_deref()
        .and_then(extract_nonce);

    Ok(ParsedOcspResponse {
        status,
        basic_response: basic,
        echoed_nonce,
    })
}

/// Check that the responder echoed back our nonce. `strict` selects
/// whether a missing echo is an error (per RFC 6960 §4.4.1) or
/// tolerated (the "opportunistic" mode many real desktop verifiers
/// use because CR/EU public responders often omit nonces).
pub fn check_nonce(
    parsed: &ParsedOcspResponse,
    expected: &[u8],
    strict: bool,
) -> Result<()> {
    match (&parsed.echoed_nonce, strict) {
        (Some(echoed), _) if echoed.as_slice() == expected => Ok(()),
        (Some(echoed), _) => Err(Error::Ocsp(format!(
            "OCSP nonce mismatch — sent {} bytes, got {} bytes",
            expected.len(),
            echoed.len()
        ))),
        (None, true) => Err(Error::Ocsp(
            "responder omitted nonce extension in strict mode".into(),
        )),
        (None, false) => Ok(()),
    }
}

fn extract_nonce(exts: &[x509_cert::ext::Extension]) -> Option<Vec<u8>> {
    let nonce_oid: der::oid::ObjectIdentifier =
        der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
    let ext = exts.iter().find(|e| e.extn_id == nonce_oid)?;
    let inner = OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(inner.as_bytes().to_vec())
}
