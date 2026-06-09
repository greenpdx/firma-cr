//! OCSP / CRL / AIA — revocation data acquisition for ETSI -LT
//! profiles.
//!
//! Submodules:
//!
//!   * [`ocsp`] — build OCSP requests and parse responses
//!     (RFC 6960). Wraps `x509-ocsp 0.2`.
//!   * [`crl`] — parse a DER-encoded `CertificateList` (RFC 5280)
//!     and answer "is this serial revoked".
//!   * [`aia`] — pull OCSP responder URLs from a cert's
//!     `AuthorityInfoAccess` extension and CRL distribution-point
//!     URLs from its `CRLDistributionPoints` extension.

pub mod aia;
pub mod crl;
pub mod ocsp;

use crate::error::{Error, Result};

/// Aggregated revocation evidence to be embedded in -LT signatures.
/// `ocsp_responses` are full OCSPResponse DER blobs (the bytes the
/// responder returned to us). `crls` are full CertificateList DER
/// blobs.
#[derive(Default, Debug, Clone)]
pub struct RevocationData {
    pub ocsp_responses: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

impl RevocationData {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn is_empty(&self) -> bool {
        self.ocsp_responses.is_empty() && self.crls.is_empty()
    }
}

/// POST an OCSP request to a responder URL and return the raw
/// `OCSPResponse` DER bytes.
pub fn fetch_ocsp(responder_url: &str, request_der: &[u8]) -> Result<Vec<u8>> {
    log::info!("ocsp: POST {responder_url} ({} bytes)", request_der.len());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Ocsp(format!("HTTP client: {e}")))?;
    let resp = client
        .post(responder_url)
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .body(request_der.to_vec())
        .send()
        .map_err(|e| Error::Ocsp(format!("POST {responder_url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Ocsp(format!(
            "HTTP {} from OCSP responder",
            resp.status()
        )));
    }
    Ok(resp
        .bytes()
        .map_err(|e| Error::Ocsp(format!("read response: {e}")))?
        .to_vec())
}

/// GET a CRL from a CDP URL and return the raw `CertificateList`
/// DER bytes. Rejects PEM-encoded CRLs; the caller should
/// pre-convert if needed.
pub fn fetch_crl(cdp_url: &str) -> Result<Vec<u8>> {
    log::info!("crl: GET {cdp_url}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| Error::Crl(format!("HTTP client: {e}")))?;
    let resp = client
        .get(cdp_url)
        .send()
        .map_err(|e| Error::Crl(format!("GET {cdp_url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Crl(format!("HTTP {} from CDP", resp.status())));
    }
    let body = resp
        .bytes()
        .map_err(|e| Error::Crl(format!("read body: {e}")))?
        .to_vec();
    if body.starts_with(b"-----BEGIN") {
        return Err(Error::Crl("PEM-encoded CRL not supported".into()));
    }
    Ok(body)
}
