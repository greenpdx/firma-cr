// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared HTTP-fetch guards for the revocation (OCSP / CRL / AIA) and TSA paths.
//!
//! The URLs these fetchers hit come from attacker-influenced sources — a cert's
//! `AuthorityInfoAccess` / `CRLDistributionPoints` extensions, or a
//! caller-supplied TSA URL — so before we touch the network we:
//!
//!   * [`require_web_scheme`] — for OCSP / CRL / AIA, whose URLs come straight
//!     from a cert's extensions: allow `http`/`https` but reject every other
//!     scheme (`file://`, `ftp://`, `gopher://`, …) so a hostile cert cannot make
//!     us read local files or hit non-HTTP services. Cleartext `http` is allowed
//!     here because OCSP/CRL/AIA payloads are themselves signed (confidentiality
//!     isn't required) and real CA endpoints — including BCCR's — publish plain
//!     `http` distribution points.
//!   * [`require_https`] — stricter: `https` only. Used for the TSA endpoint,
//!     which is operator-configured (not attacker-supplied), so we can mandate
//!     transport security there without breaking real-world verification.
//!   * [`read_capped`] — bound how many bytes we will buffer from a response, so
//!     a hostile or buggy endpoint cannot exhaust memory (DoS).
//!
//! Both return `Result<_, String>` so each caller can wrap the message in its own
//! domain error variant (`Error::Ocsp`, `Error::Crl`, `Error::CertParse`,
//! `Error::Tsa`) without this module depending on all of them.

use std::io::Read;

/// Per-endpoint response-size ceilings (bytes). A normal OCSP response is a few
/// hundred bytes and a CRL a few MiB; these caps are generous headroom, not tight
/// limits — they exist only to stop unbounded growth.
pub const MAX_OCSP_BYTES: u64 = 1 << 20; //  1 MiB
pub const MAX_CRL_BYTES: u64 = 16 << 20; // 16 MiB
pub const MAX_AIA_BYTES: u64 = 256 << 10; // 256 KiB (one issuer cert / small P7)
pub const MAX_TSA_BYTES: u64 = 256 << 10; // 256 KiB (one TimeStampResp)

/// Allow only `http`/`https` URLs (reject `file`, `ftp`, `gopher`, …). For the
/// revocation/AIA fetchers, whose URLs come from attacker-influenced cert
/// extensions — the point is to block scheme-confusion / local-file / non-HTTP
/// SSRF, not to mandate TLS (the payloads are signed).
pub fn require_web_scheme(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url.trim()).map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    let scheme = parsed.scheme();
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        Ok(())
    } else {
        Err(format!("refusing non-http(s) URL (scheme {scheme:?}): {url}"))
    }
}

/// Reject any URL whose scheme is not `https`. Used for the operator-configured
/// TSA endpoint, where mandating TLS is reasonable and low-compat-risk.
pub fn require_https(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url.trim()).map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    if parsed.scheme().eq_ignore_ascii_case("https") {
        Ok(())
    } else {
        Err(format!(
            "refusing non-https URL (scheme {:?}): {url}",
            parsed.scheme()
        ))
    }
}

/// Read a blocking HTTP response body into a `Vec`, failing if it exceeds `max`
/// bytes. Checks `Content-Length` first (cheap reject of an honest oversize body)
/// and then bounds the actual read at `max + 1` so a missing or lying
/// `Content-Length` cannot get past the cap.
pub fn read_capped(resp: reqwest::blocking::Response, max: u64) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length()
        && len > max
    {
        return Err(format!("response too large: {len} B > {max} B cap"));
    }
    let mut buf = Vec::new();
    resp.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body: {e}"))?;
    if buf.len() as u64 > max {
        return Err(format!("response exceeds {max} B cap"));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_https_accepts_https_only() {
        assert!(require_https("https://tsa.example.cr/").is_ok());
        assert!(require_https("HTTPS://tsa.example.cr/").is_ok());
        assert!(require_https("http://tsa.example.cr/").is_err());
        assert!(require_https("file:///etc/passwd").is_err());
        assert!(require_https("not a url").is_err());
    }

    #[test]
    fn require_web_scheme_allows_http_and_https_blocks_others() {
        assert!(require_web_scheme("http://ocsp.example.cr/").is_ok());
        assert!(require_web_scheme("https://ocsp.example.cr/").is_ok());
        assert!(require_web_scheme("http://127.0.0.1:8080/issuer.crt").is_ok());
        assert!(require_web_scheme("file:///etc/passwd").is_err());
        assert!(require_web_scheme("ftp://x/").is_err());
        assert!(require_web_scheme("gopher://x/").is_err());
        assert!(require_web_scheme("not a url").is_err());
    }
}
