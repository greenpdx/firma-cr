//! Hash-algorithm registry + dispatch helper.
//!
//! Centralises the algo-name ↔ OID ↔ XMLDSig-URI ↔ digest-impl
//! mapping so CAdES/PAdES/XAdES don't each reimplement it. SHA-1
//! is intentionally absent — every ETSI baseline since 2016
//! deprecates it.

use sha2::{Digest as _, Sha256, Sha384, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgo {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha384" | "sha-384" => Some(Self::Sha384),
            "sha512" | "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Canonical short name (used in CLI output + logs).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// RFC 8017 OID (used in CMS / X.509 AlgorithmIdentifier).
    pub fn oid_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// Reverse of [`HashAlgo::oid_str`].
    pub fn from_oid_str(s: &str) -> Option<Self> {
        match s {
            "2.16.840.1.101.3.4.2.1" => Some(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// XMLDSig DigestMethod URI (W3C XML Signature).
    pub fn xmldsig_uri(&self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    /// RSA-with-this-hash SignatureMethod URI for XMLDSig.
    pub fn xmldsig_signature_uri(&self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn output_bytes(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // FIPS 180-2 §B.1
        let h = HashAlgo::Sha256.hash(b"abc");
        assert_eq!(
            hex::encode(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn parse_round_trip() {
        for v in ["sha256", "SHA-256", "sha384", "SHA-512"] {
            assert!(HashAlgo::parse(v).is_some(), "should parse {v}");
        }
        assert!(HashAlgo::parse("md5").is_none());
        assert!(HashAlgo::parse("sha1").is_none(), "sha1 must not be a parseable option");
    }

    #[test]
    fn output_bytes_matches_hash_length() {
        for a in [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512] {
            assert_eq!(a.hash(b"test").len(), a.output_bytes());
        }
    }
}
