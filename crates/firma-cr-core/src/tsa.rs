// SPDX-License-Identifier: GPL-3.0-or-later
//! RFC 3161 Time-Stamp Protocol client.
//!
//! Builds a `TimeStampReq` DER over the hash of arbitrary bytes
//! (typically the signature value of an existing CMS / PAdES / XAdES
//! signature — for ETSI -T profiles the timestamp is computed over
//! the signature value, embedded as an unsigned attribute).
//!
//! POSTs to a TSA endpoint with Content-Type
//! `application/timestamp-query` and parses the `TimeStampResp`
//! returning the embedded `TimeStampToken` (itself a CMS
//! `SignedData`) as DER bytes ready for injection.
//!
//! Wire formats:
//!
//!   TimeStampReq ::= SEQUENCE {
//!     version            INTEGER  { v1(1) },
//!     messageImprint     MessageImprint,
//!     reqPolicy          TSAPolicyId  OPTIONAL,
//!     nonce              INTEGER  OPTIONAL,
//!     certReq            BOOLEAN  DEFAULT FALSE,
//!     extensions         [0] IMPLICIT Extensions OPTIONAL
//!   }
//!
//!   MessageImprint ::= SEQUENCE {
//!     hashAlgorithm  AlgorithmIdentifier,
//!     hashedMessage  OCTET STRING
//!   }
//!
//!   TimeStampResp ::= SEQUENCE {
//!     status         PKIStatusInfo,
//!     timeStampToken TimeStampToken  OPTIONAL
//!   }

use der::asn1::{BitString, Int, OctetString};
use der::{Any, Encode, oid::ObjectIdentifier};
use spki::AlgorithmIdentifierOwned;

use crate::digest::HashAlgo;
use crate::error::{Error, Result};

/// `id-tsp-tst` content type — the OID of TimeStampToken's inner content.
const OID_ID_TSP_TST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

pub struct TimestampRequest {
    pub hash_algo: HashAlgo,
    pub message_hash: Vec<u8>,
    pub nonce: Option<u64>,
    pub cert_req: bool,
}

impl TimestampRequest {
    pub fn new(data_to_timestamp: &[u8], hash_algo: HashAlgo) -> Self {
        Self {
            hash_algo,
            message_hash: hash_algo.hash(data_to_timestamp),
            nonce: Some(rand_u64()),
            cert_req: true,
        }
    }

    /// DER-encode the TimeStampReq.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // version INTEGER (1)
        let mut body = Vec::new();
        body.extend_from_slice(&der_int(1));

        // messageImprint SEQUENCE
        let mut mi = Vec::new();
        let alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(self.hash_algo.oid_str()),
            parameters: Some(Any::null()),
        };
        mi.extend_from_slice(
            &alg.to_der()
                .map_err(|e| Error::Tsa(format!("hash algo to_der: {e}")))?,
        );
        let oct = OctetString::new(self.message_hash.clone())
            .map_err(|e| Error::Tsa(format!("OctetString: {e}")))?;
        mi.extend_from_slice(
            &oct.to_der()
                .map_err(|e| Error::Tsa(format!("OctetString to_der: {e}")))?,
        );
        body.extend_from_slice(&seq(&mi));

        // nonce INTEGER (optional)
        if let Some(n) = self.nonce {
            body.extend_from_slice(&der_int_u64(n));
        }

        // certReq BOOLEAN (optional, DEFAULT FALSE — emit only when TRUE)
        if self.cert_req {
            body.extend_from_slice(&[0x01, 0x01, 0xFF]); // BOOLEAN TRUE
        }

        Ok(seq(&body))
    }
}

/// Result of a successful TSA round-trip — the bytes of the
/// TimeStampToken (a CMS SignedData ContentInfo), ready to embed as
/// an unsigned attribute on the original signature.
pub struct TimestampToken {
    pub token_der: Vec<u8>,
}

/// POST `req_der` to `url` and parse the response. The HTTP client is
/// `reqwest` blocking (rustls TLS). Returns `Err` if the TSA rejects
/// the request or if the response is malformed.
pub fn request_token(url: &str, req_der: &[u8]) -> Result<TimestampToken> {
    crate::net::require_https(url).map_err(Error::Tsa)?;
    log::info!("tsa: POST {} ({} bytes)", url, req_der.len());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Tsa(format!("HTTP client: {e}")))?;
    let resp = client
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .body(req_der.to_vec())
        .send()
        .map_err(|e| Error::Tsa(format!("POST {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(Error::Tsa(format!("HTTP {} from TSA", status)));
    }
    let body = crate::net::read_capped(resp, crate::net::MAX_TSA_BYTES).map_err(Error::Tsa)?;
    parse_response(&body)
}

/// Parse a TimeStampResp DER into the embedded TimeStampToken.
fn parse_response(resp: &[u8]) -> Result<TimestampToken> {
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
    // PKIStatusInfo ::= SEQUENCE { status PKIStatus, ... }
    // PKIStatus ::= INTEGER { granted(0), grantedWithMods(1), ... }
    //
    // We do a minimal hand-walk rather than pulling a full PKIX
    // decoder.
    let (outer, _) = read_tlv(resp)?;
    if outer.tag != 0x30 {
        return Err(Error::Tsa(format!("response not SEQUENCE (tag {:#x})", outer.tag)));
    }
    let mut inner = outer.value;

    // status: PKIStatusInfo SEQUENCE
    let (status_seq, rest) = read_tlv(inner)?;
    inner = rest;
    if status_seq.tag != 0x30 {
        return Err(Error::Tsa("PKIStatusInfo not SEQUENCE".into()));
    }
    let (status_int, _) = read_tlv(status_seq.value)?;
    if status_int.tag != 0x02 {
        return Err(Error::Tsa("PKIStatus not INTEGER".into()));
    }
    let status_val = status_int
        .value
        .iter()
        .fold(0u32, |acc, b| (acc << 8) | (*b as u32));
    if status_val > 1 {
        return Err(Error::Tsa(format!(
            "TSA rejected (PKIStatus = {status_val})"
        )));
    }

    // timeStampToken (CMS ContentInfo SEQUENCE)
    if inner.is_empty() {
        return Err(Error::Tsa("TimeStampToken missing".into()));
    }
    let (token_tlv, _) = read_tlv(inner)?;
    if token_tlv.tag != 0x30 {
        return Err(Error::Tsa("TimeStampToken not SEQUENCE".into()));
    }
    // The token is itself a full SEQUENCE; we want the entire
    // top-level TLV bytes (re-serialize the slice).
    let token_der = inner[..tlv_total_len(token_tlv)].to_vec();
    Ok(TimestampToken { token_der })
}

// ---------- minimal DER helpers ----------

struct Tlv<'a> {
    tag: u8,
    /// Inclusive of identifier + length octets.
    header_len: usize,
    value: &'a [u8],
}

fn tlv_total_len(t: Tlv) -> usize {
    t.header_len + t.value.len()
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
    Ok((
        Tlv {
            tag,
            header_len: hdr,
            value: &b[hdr..hdr + len],
        },
        &b[hdr + len..],
    ))
}

fn der_int(v: i64) -> Vec<u8> {
    let int = Int::new(&v.to_be_bytes()).unwrap();
    int.to_der().unwrap()
}

fn der_int_u64(v: u64) -> Vec<u8> {
    // Strip leading zeros except keep the MSB-sign byte.
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    let body = &bytes[start..];
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x02);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
    out
}

fn seq(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30);
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else if body.len() <= 0xFF {
        out.push(0x81);
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.push((body.len() >> 8) as u8);
        out.push((body.len() & 0xFF) as u8);
    }
    out.extend_from_slice(body);
    out
}

/// A cryptographically-random 64-bit RFC 3161 nonce, drawn from the OS CSPRNG via
/// `getrandom`. The nonce ties our request to the TSA's response (replay / mix-up
/// resistance), so it must be unpredictable — a time-seeded PRNG (the previous
/// implementation) was guessable. If the OS RNG is somehow unavailable we fall
/// back to a time-derived value rather than panic: a worse-but-nonzero nonce on a
/// path that is already best-effort.
fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    match getrandom::getrandom(&mut b) {
        Ok(()) => u64::from_le_bytes(b),
        Err(_) => {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                .wrapping_add(0x9E3779B97F4A7C15)
        }
    }
}

// Suppress unused-import warnings on the OID const + BitString import
// while the LTA archive-timestamp path is still a stub.
#[allow(dead_code)]
const _UNUSED_OID: ObjectIdentifier = OID_ID_TSP_TST;
#[allow(dead_code)]
fn _unused_bitstring() -> Result<BitString> {
    BitString::new(0, vec![]).map_err(|e| Error::Tsa(format!("bs: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_request_round_trip_shape() {
        let req = TimestampRequest::new(b"hello", HashAlgo::Sha256);
        let der = req.to_der().unwrap();
        // First byte = SEQUENCE
        assert_eq!(der[0], 0x30);
        // Body length is at least 50 bytes (version + messageImprint
        // + nonce + certReq).
        assert!(der.len() > 50);
        // Bytes include the SHA-256 hash of "hello":
        //   2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hash = hex::encode(HashAlgo::Sha256.hash(b"hello"));
        let der_hex = hex::encode(&der);
        assert!(der_hex.contains(&hash), "expected hash in DER, got {der_hex}");
    }
}
