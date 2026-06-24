// SPDX-License-Identifier: GPL-3.0-or-later
//! Signer-certificate handling.
//!
//! A `SignerCert` holds the DER bytes plus the parsed `x509-cert`
//! view, exposing the fields CAdES / PAdES / XAdES need: serial,
//! issuer DN, subject DN, validity window, SubjectKeyIdentifier,
//! tbs-cert SHA-256 (for `signingCertificateV2`), and the cert
//! bytes themselves.

use std::path::Path;

// Use the `der` re-exported by x509-cert so trait bounds match the
// Certificate type we receive from it. (The crate also has a top-level
// `der` dependency for our own encoders, but that's a different
// generation and would refuse to decode here.)
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _, Reader as _, SliceReader};

use crate::digest::HashAlgo;
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct SignerCert {
    pub der: Vec<u8>,
    pub parsed: Certificate,
}

impl SignerCert {
    /// Parse a certificate from raw DER bytes (typical: what came
    /// back from `CardClient::read_certificate()`).
    ///
    /// Smart-card certificate EFs are fixed-size: the card returns the
    /// whole file, so the cert is followed by padding (the BCCR cards
    /// return ~3 KB files holding a ~1.5 KB cert). `Certificate::from_der`
    /// is strict and rejects that trailing data, so we decode the leading
    /// DER message via a reader and truncate `der` to exactly the bytes
    /// the cert occupies. Truncating is not just cosmetic: `cert_digest`
    /// hashes `self.der` for `signingCertificateV2` / XAdES, so any
    /// padding left here would corrupt that digest.
    pub fn from_der(mut der: Vec<u8>) -> Result<Self> {
        let mut reader = SliceReader::new(&der).map_err(|e| {
            Error::CertParse(format!("X.509 DER decode failed: {e}"))
        })?;
        let parsed = Certificate::decode(&mut reader).map_err(|e| {
            Error::CertParse(format!("X.509 DER decode failed: {e}"))
        })?;
        let consumed = usize::try_from(u32::from(reader.position())).map_err(|e| {
            Error::CertParse(format!("X.509 DER length overflow: {e}"))
        })?;
        der.truncate(consumed);
        Ok(Self { der, parsed })
    }

    /// Load a cert from a file on disk. Accepts DER or PEM.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.starts_with(b"-----BEGIN") {
            Self::from_pem_str(std::str::from_utf8(&bytes).map_err(|_| {
                Error::CertParse("file PEM not UTF-8".into())
            })?)
        } else {
            Self::from_der(bytes)
        }
    }

    /// Parse a PEM-encoded certificate string.
    pub fn from_pem_str(pem: &str) -> Result<Self> {
        let parsed = Certificate::from_pem(pem.as_bytes())
            .map_err(|e| Error::CertParse(format!("PEM decode: {e}")))?;
        let der = parsed
            .to_der()
            .map_err(|e| Error::CertParse(format!("re-DER-encode after PEM: {e}")))?;
        Ok(Self { der, parsed })
    }

    /// Parse every `CERTIFICATE` block in a PEM string, in order. Blocks that
    /// don't parse are skipped. Used to load a multi-cert trust chain (root +
    /// policy CAs) from one PEM.
    pub fn chain_from_pem_str(pem: &str) -> Vec<Self> {
        const B: &str = "-----BEGIN CERTIFICATE-----";
        const E: &str = "-----END CERTIFICATE-----";
        let mut out = Vec::new();
        let mut rest = pem;
        while let Some(bi) = rest.find(B) {
            let after = &rest[bi..];
            let Some(ei) = after.find(E) else { break };
            let end = ei + E.len();
            if let Ok(c) = Self::from_pem_str(&after[..end]) {
                out.push(c);
            }
            rest = &after[end..];
        }
        out
    }

    /// True if subject == issuer (a self-signed root certificate).
    pub fn is_self_signed(&self) -> bool {
        self.parsed.tbs_certificate.subject == self.parsed.tbs_certificate.issuer
    }

    /// Subject DN as a printable RFC 4514 string.
    pub fn subject_string(&self) -> String {
        self.parsed.tbs_certificate.subject.to_string()
    }

    /// Issuer DN as a printable RFC 4514 string.
    pub fn issuer_string(&self) -> String {
        self.parsed.tbs_certificate.issuer.to_string()
    }

    /// Certificate serial number as a big-endian hex string
    /// (no leading 0s collapsed; preserves the over-the-wire form
    /// CMS / PAdES need).
    pub fn serial_hex(&self) -> String {
        hex::encode(self.parsed.tbs_certificate.serial_number.as_bytes())
    }

    /// notBefore / notAfter as RFC 3339 strings (human readable).
    pub fn validity_window(&self) -> (String, String) {
        let v = &self.parsed.tbs_certificate.validity;
        (v.not_before.to_string(), v.not_after.to_string())
    }

    /// Digest of the full DER-encoded certificate. Used by ESS
    /// `signingCertificateV2` and by XAdES `SigningCertificate`.
    pub fn cert_digest(&self, algo: HashAlgo) -> Vec<u8> {
        algo.hash(&self.der)
    }

    /// Load every `-----BEGIN CERTIFICATE-----` block from a PEM
    /// bundle on disk, in file order. Used by `--include-chain`
    /// to supply intermediates the smart card doesn't store.
    ///
    /// The bundle is typically: `intermediate.pem` then `root.pem`
    /// concatenated. Order doesn't matter for the verifier — the
    /// chain-builder reorders by issuer/subject linkage — but it
    /// affects the order the certs appear in the produced CMS /
    /// XAdES `certificates` set.
    pub fn load_chain_from_pem(path: &Path) -> Result<Vec<Self>> {
        let bytes = std::fs::read(path)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::CertParse("chain PEM not UTF-8".into()))?;
        let mut chain = Vec::new();
        for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
            let end = block
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| Error::CertParse("chain PEM block missing END marker".into()))?;
            // Reconstruct a single-cert PEM so x509-cert::Certificate::from_pem
            // accepts it.
            let single = format!(
                "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----\n",
                &block[..end],
            );
            let parsed = Certificate::from_pem(single.as_bytes())
                .map_err(|e| Error::CertParse(format!("chain PEM block: {e}")))?;
            let der = parsed
                .to_der()
                .map_err(|e| Error::CertParse(format!("re-DER chain entry: {e}")))?;
            chain.push(Self { der, parsed });
        }
        if chain.is_empty() {
            return Err(Error::CertParse(
                "no CERTIFICATE blocks found in chain PEM file".into(),
            ));
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Committed fixture (any valid X.509 cert works here), so this compiles on a
    // clean checkout / CI without the gitignored, generated test_ca/out/ tree.
    const LEAF_PEM: &str = include_str!("../tests/fixtures/sample-cert.pem");

    /// A cert read from a card EF arrives with trailing padding (the EF
    /// is fixed-size and the card returns the whole file). `from_der`
    /// must parse it and truncate `self.der` to exactly the cert bytes,
    /// so `cert_digest` hashes the cert and not the padding.
    #[test]
    fn from_der_strips_trailing_padding() {
        let exact = SignerCert::from_pem_str(LEAF_PEM).unwrap().der;

        for pad in [&[0u8; 1407][..], &[0xFFu8; 64][..], &[0x00u8; 1][..]] {
            let mut padded = exact.clone();
            padded.extend_from_slice(pad);
            let cert = SignerCert::from_der(padded).unwrap();
            assert_eq!(
                cert.der, exact,
                "from_der must truncate {} padding bytes back to the cert",
                pad.len()
            );
        }
    }

    /// A cert with no padding round-trips unchanged.
    #[test]
    fn from_der_accepts_exact_der() {
        let exact = SignerCert::from_pem_str(LEAF_PEM).unwrap().der;
        let cert = SignerCert::from_der(exact.clone()).unwrap();
        assert_eq!(cert.der, exact);
    }
}
