//! AuthorityInfoAccess + CRLDistributionPoints extension parsing.
//!
//! RFC 5280 §4.2.2.1 (AIA, OID 1.3.6.1.5.5.7.1.1) lists per-purpose
//! access descriptions; we pull out the OCSP responder URLs (purpose
//! OID `id-ad-ocsp` = 1.3.6.1.5.5.7.48.1). RFC 5280 §4.2.1.13
//! (CRLDP, OID 2.5.29.31) lists distribution points; we pull out
//! fullName URIs.

use der::Decode;
use der::oid::ObjectIdentifier;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};

use crate::cert::SignerCert;
use crate::error::{Error, Result};

const OID_AIA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_CRLDP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_AD_OCSP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const OID_AD_CA_ISSUERS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

/// Return every OCSP responder URL listed in `cert`'s AIA extension.
pub fn ocsp_urls(cert: &SignerCert) -> Vec<String> {
    let exts = match cert.parsed.tbs_certificate.extensions.as_ref() {
        Some(e) => e,
        None => return Vec::new(),
    };
    let aia_ext = match exts.iter().find(|e| e.extn_id == OID_AIA) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let aia = match AuthorityInfoAccessSyntax::from_der(aia_ext.extn_value.as_bytes()) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    aia.0
        .iter()
        .filter(|ad| ad.access_method == OID_AD_OCSP)
        .filter_map(|ad| match &ad.access_location {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// Return every `id-ad-caIssuers` URL from `cert`'s AIA extension.
/// These point at the cert that signed `cert` — handy when a leaf
/// arrives without its issuer chain attached.
pub fn ca_issuer_urls(cert: &SignerCert) -> Vec<String> {
    let exts = match cert.parsed.tbs_certificate.extensions.as_ref() {
        Some(e) => e,
        None => return Vec::new(),
    };
    let aia_ext = match exts.iter().find(|e| e.extn_id == OID_AIA) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let aia = match AuthorityInfoAccessSyntax::from_der(aia_ext.extn_value.as_bytes()) {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    aia.0
        .iter()
        .filter(|ad| ad.access_method == OID_AD_CA_ISSUERS)
        .filter_map(|ad| match &ad.access_location {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// HTTP-GET one cert URL and return raw bytes (DER, PEM, or
/// PKCS#7 — caller decides how to parse).
pub fn fetch_issuer(url: &str) -> Result<Vec<u8>> {
    log::info!("aia: GET {url}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::CertParse(format!("HTTP client: {e}")))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| Error::CertParse(format!("GET {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::CertParse(format!(
            "HTTP {} fetching {url}",
            resp.status()
        )));
    }
    Ok(resp
        .bytes()
        .map_err(|e| Error::CertParse(format!("read body: {e}")))?
        .to_vec())
}

/// Walk `leaf`'s AIA chain upward, fetching each parent cert from
/// the URL embedded in `id-ad-caIssuers`. Stops when:
///   * we reach a self-signed cert (root),
///   * a cert has no AIA URLs to follow, or
///   * `max_depth` is exhausted.
///
/// Returns the list of fetched certs in order: first intermediate,
/// then grandparent, ..., possibly ending in the root. The caller
/// can pass this to `XadesBuilder::include_chain` etc.
pub fn fetch_issuer_chain(leaf: &SignerCert, max_depth: usize) -> Result<Vec<SignerCert>> {
    let mut out: Vec<SignerCert> = Vec::new();
    let mut current = leaf.clone();
    for _step in 0..max_depth {
        if current.parsed.tbs_certificate.issuer == current.parsed.tbs_certificate.subject
        {
            break; // self-signed root
        }
        let urls = ca_issuer_urls(&current);
        if urls.is_empty() {
            break;
        }
        let bytes = fetch_issuer(&urls[0])?;
        let parsed = parse_cert_bytes(&bytes)?;
        out.push(parsed.clone());
        current = parsed;
    }
    Ok(out)
}

/// Parse a fetched body as DER or PEM and wrap as SignerCert.
fn parse_cert_bytes(bytes: &[u8]) -> Result<SignerCert> {
    if bytes.starts_with(b"-----BEGIN") {
        let s = std::str::from_utf8(bytes)
            .map_err(|_| Error::CertParse("fetched PEM not UTF-8".into()))?;
        SignerCert::from_pem_str(s)
    } else {
        SignerCert::from_der(bytes.to_vec())
    }
}

/// Return every CRL distribution point URL listed in `cert`'s
/// CRLDP extension. Only `fullName` URIs are returned —
/// `nameRelativeToCRLIssuer` is ignored.
pub fn crl_urls(cert: &SignerCert) -> Vec<String> {
    let exts = match cert.parsed.tbs_certificate.extensions.as_ref() {
        Some(e) => e,
        None => return Vec::new(),
    };
    let cdp_ext = match exts.iter().find(|e| e.extn_id == OID_CRLDP) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let cdp = match CrlDistributionPoints::from_der(cdp_ext.extn_value.as_bytes()) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for dp in &cdp.0 {
        if let Some(dp_name) = &dp.distribution_point {
            if let x509_cert::ext::pkix::name::DistributionPointName::FullName(names) = dp_name
            {
                for n in names {
                    if let GeneralName::UniformResourceIdentifier(uri) = n {
                        out.push(uri.as_str().to_string());
                    }
                }
            }
        }
    }
    out
}
