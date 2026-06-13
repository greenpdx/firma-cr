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
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

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
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return Err(format!("refusing non-http(s) URL (scheme {scheme:?}): {url}"));
    }
    reject_internal_host(&parsed)
}

/// Reject any URL whose scheme is not `https`. Used for the operator-configured
/// TSA endpoint, where mandating TLS is reasonable and low-compat-risk.
pub fn require_https(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url.trim()).map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err(format!("refusing non-https URL (scheme {:?}): {url}", parsed.scheme()));
    }
    reject_internal_host(&parsed)
}

/// SSRF guard: reject URLs whose host resolves to a loopback / private /
/// link-local / otherwise non-public address. URLs come from attacker-influenced
/// cert extensions (AIA/CRL-DP) and the site-supplied TSA, so this stops them
/// pointing the fetch at internal services or cloud metadata (169.254.169.254).
/// (Note: this resolves now; it does not fully close DNS-rebinding TOCTOU.)
fn reject_internal_host(parsed: &url::Url) -> Result<(), String> {
    // Escape hatch for local responders / test mock servers on loopback.
    if std::env::var_os("FIRMA_CR_ALLOW_PRIVATE_FETCH").is_some() {
        return Ok(());
    }
    let host = parsed.host_str().ok_or_else(|| "URL has no host".to_string())?;
    // IP literal: check directly. Hostname: resolve and check every address.
    let addrs: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        (host, parsed.port_or_known_default().unwrap_or(443))
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve host {host:?}: {e}"))?
            .map(|sa| sa.ip())
            .collect()
    };
    if addrs.is_empty() {
        return Err(format!("host {host:?} resolved to no addresses"));
    }
    for ip in addrs {
        if is_blocked_ip(ip) {
            return Err(format!("refusing URL to non-public address {ip} (host {host:?})"));
        }
    }
    Ok(())
}

/// True for addresses that must never be fetched from a cert/site-supplied URL:
/// loopback, private/RFC1918, CGNAT, link-local (incl. 169.254.0.0/16 metadata),
/// unspecified, multicast/broadcast, documentation ranges, and IPv6 ULA/link-local.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

fn is_blocked_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || v4 == Ipv4Addr::new(169, 254, 169, 254) // cloud metadata (also link-local)
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

    // IP literals only — no DNS — so these are hermetic.
    #[test]
    fn require_https_accepts_https_only() {
        assert!(require_https("https://8.8.8.8/").is_ok());
        assert!(require_https("HTTPS://8.8.8.8/").is_ok());
        assert!(require_https("http://8.8.8.8/").is_err()); // wrong scheme
        assert!(require_https("file:///etc/passwd").is_err());
        assert!(require_https("not a url").is_err());
    }

    #[test]
    fn require_web_scheme_allows_http_and_https_blocks_others() {
        assert!(require_web_scheme("http://8.8.8.8/").is_ok());
        assert!(require_web_scheme("https://8.8.8.8/").is_ok());
        assert!(require_web_scheme("file:///etc/passwd").is_err());
        assert!(require_web_scheme("ftp://x/").is_err());
        assert!(require_web_scheme("gopher://x/").is_err());
        assert!(require_web_scheme("not a url").is_err());
    }

    #[test]
    fn ssrf_internal_addresses_blocked() {
        for u in [
            "http://127.0.0.1/x",
            "https://127.0.0.1/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data/", // cloud metadata
            "http://[::1]/x",
            "http://0.0.0.0/x",
        ] {
            assert!(require_web_scheme(u).is_err(), "should block {u}");
        }
    }

    #[test]
    fn ssrf_block_classifier() {
        use std::net::IpAddr;
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "::1", "fe80::1", "fc00::1"] {
            assert!(is_blocked_ip(ip.parse::<IpAddr>().unwrap()), "{ip} should be blocked");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(!is_blocked_ip(ip.parse::<IpAddr>().unwrap()), "{ip} should be allowed");
        }
    }
}
