// SPDX-License-Identifier: GPL-3.0-or-later
//! CAdES-B-B detached CMS signing.
//!
//! Builds a `SignedData` (RFC 5652) with the four signed attributes
//! ETSI EN 319 122-1 §5.2.1 requires for the baseline B profile:
//!
//!   * content-type           (OID 1.2.840.113549.1.9.3)
//!   * message-digest         (OID 1.2.840.113549.1.9.4)
//!   * signing-time           (OID 1.2.840.113549.1.9.5)
//!   * signing-certificate-v2 (ESS, OID 1.2.840.113549.1.9.16.2.47)
//!
//! The signature is RSA-PKCS#1 v1.5; the hash is whatever `HashAlgo`
//! the caller picked (SHA-256 by default). The signing operation is
//! delegated to the on-card RSA key via `CardClient::sign` — we
//! compute `SHA(SignedAttributes-SET-OF-encoding)`, wrap it in a
//! PKCS#1 `DigestInfo`, and feed that to `CKM_RSA_PKCS`.

use std::time::SystemTime;

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{GeneralizedTime, OctetString, SetOfVec};
use der::{Any, Decode, Encode, oid::ObjectIdentifier};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue};

use crate::cert::SignerCert;
use crate::digest::HashAlgo;
use crate::error::{Error, Result};
use crate::pkcs11_client::build_digest_info;
use crate::revocation::RevocationData;
use crate::signer::Signer;

/// CMS `id-signedData` content-type OID.
const OID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// ESS `id-aa-signatureTimeStampToken` — unsigned attribute carrying
/// the RFC 3161 TimeStampToken that proves *when* the signature was
/// made. Required for the ETSI -T profile.
const OID_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// `id-aa-ets-revocationValues` (RFC 5126 §6.3.4) — unsigned
/// attribute carrying embedded CRL + OCSP responses, required for
/// the ETSI -LT profile.
const OID_REVOCATION_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.24");
/// `id-aa-ets-archiveTimestamp` (RFC 5126 §6.4.1, "v1") — unsigned
/// attribute carrying the archive TimeStampToken that elevates the
/// signature to the ETSI -LTA profile.
const OID_ARCHIVE_TIMESTAMP_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.27");
/// CMS `id-data` content-type OID (what the EncapsulatedContentInfo
/// references for arbitrary data).
const OID_ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// PKCS#9 `contentType` signed-attribute OID.
const OID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// PKCS#9 `messageDigest` signed-attribute OID.
const OID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// PKCS#9 `signingTime` signed-attribute OID.
const OID_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// ESS `signing-certificate-v2` (RFC 5035) — mandatory ESS binding.
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// PKCS#1 `rsaEncryption` (used as the SignerInfo.signatureAlgorithm
/// per RFC 5754 §3.2 — "the rsaEncryption OID identifies the
/// PKCS#1 v1.5 signature scheme regardless of the digest").
const OID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Callback that requests a TimeStampToken (DER bytes, CMS
/// ContentInfo) for a given signature value. Used to lift a CAdES-B-B
/// signature to CAdES-B-T by injecting the returned token as an
/// unsigned attribute on the SignerInfo.
pub type TimestampFn = Box<dyn Fn(&[u8]) -> Result<Vec<u8>>>;

/// CAdES-B-B / B-T / B-LT / B-LTA builder.
pub struct CadesBuilder<'a> {
    data: &'a [u8],
    hash_algo: HashAlgo,
    cert: &'a SignerCert,
    additional_certs: Vec<&'a SignerCert>,
    signing_time: SystemTime,
    timestamp_fn: Option<TimestampFn>,
    revocation_data: Option<RevocationData>,
    archive_timestamp_fn: Option<TimestampFn>,
}

impl<'a> CadesBuilder<'a> {
    pub fn new(data: &'a [u8], hash_algo: HashAlgo, cert: &'a SignerCert) -> Self {
        Self {
            data,
            hash_algo,
            cert,
            additional_certs: Vec::new(),
            signing_time: SystemTime::now(),
            timestamp_fn: None,
            revocation_data: None,
            archive_timestamp_fn: None,
        }
    }

    /// Lift to CAdES-B-LT by embedding pre-fetched OCSP + CRL data
    /// as the `id-aa-ets-revocationValues` unsigned attribute.
    pub fn with_revocation_data(mut self, rev: RevocationData) -> Self {
        self.revocation_data = Some(rev);
        self
    }

    /// Lift to CAdES-B-LTA by attaching an archive-time-stamp-v1
    /// unsigned attribute (RFC 5126 §6.4.1). The callback receives
    /// the bytes whose hash the TSA must imprint and returns a
    /// TimeStampToken DER.
    pub fn with_archive_timestamp<F>(mut self, get_token: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>> + 'static,
    {
        self.archive_timestamp_fn = Some(Box::new(get_token));
        self
    }

    pub fn include_chain(mut self, certs: Vec<&'a SignerCert>) -> Self {
        self.additional_certs = certs;
        self
    }

    pub fn signing_time(mut self, time: SystemTime) -> Self {
        self.signing_time = time;
        self
    }

    /// Lift the signature to CAdES-B-T by calling `get_token(sig)`
    /// after the base signature is computed. The closure must return
    /// the DER bytes of a CMS-shaped TimeStampToken (typically the
    /// output of `tsa::request_token`).
    pub fn with_timestamp<F>(mut self, get_token: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>> + 'static,
    {
        self.timestamp_fn = Some(Box::new(get_token));
        self
    }

    /// Produce a detached CMS `SignedData` wrapped in a `ContentInfo`.
    /// Output is DER-encoded bytes ready for `.p7s`.
    pub fn build(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        // ---------- signed attributes ----------
        let mut attrs: Vec<Attribute> = Vec::new();
        attrs.push(self.attr_content_type()?);
        attrs.push(self.attr_message_digest()?);
        attrs.push(self.attr_signing_time()?);
        attrs.push(self.attr_signing_cert_v2()?);

        // RFC 5652 §11.1: attrs must be DER-encoded in canonical
        // order (sorted by DER encoding). `SetOfVec` does that for us.
        let signed_attrs_set: SetOfVec<Attribute> = SetOfVec::try_from(attrs.clone())
            .map_err(|e| Error::Cms(format!("SignedAttributes set sort: {e}")))?;

        // RFC 5652 §5.4: the to-be-signed bytes are the SET OF
        // encoding of SignedAttributes (NOT the [0] IMPLICIT form
        // that appears inside SignerInfo).
        let to_sign_bytes = signed_attrs_set
            .to_der()
            .map_err(|e| Error::Cms(format!("encode SignedAttributes as SET: {e}")))?;
        let attrs_hash = self.hash_algo.hash(&to_sign_bytes);
        let digest_info = build_digest_info(self.hash_algo, &attrs_hash);
        let signature_bytes = signer.sign_digest_info(&digest_info)?;

        // ---------- SignerInfo ----------
        let issuer = self.cert.parsed.tbs_certificate.issuer.clone();
        let serial = self.cert.parsed.tbs_certificate.serial_number.clone();
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer,
            serial_number: serial,
        });

        let digest_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(self.hash_algo.oid_str()),
            parameters: None,
        };
        let signature_alg = AlgorithmIdentifierOwned {
            oid: OID_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        };
        let sig_value = der::asn1::OctetString::new(signature_bytes.clone())
            .map_err(|e| Error::Cms(format!("OctetString for signature: {e}")))?;

        // ---------- optional CAdES-B-T timestamp + B-LT revocation values ----------
        let mut unsigned_vec: Vec<Attribute> = Vec::new();
        if let Some(get_token) = &self.timestamp_fn {
            log::info!("cades: requesting -T timestamp over signature value");
            let token_der = get_token(&signature_bytes)?;
            let tst_value = AttributeValue::from_der(&token_der)
                .map_err(|e| Error::Cms(format!("TimeStampToken AttributeValue: {e}")))?;
            unsigned_vec.push(Attribute {
                oid: OID_SIGNATURE_TIME_STAMP_TOKEN,
                values: SetOfVec::try_from(vec![tst_value])
                    .map_err(|e| Error::Cms(format!("TST attribute SET: {e}")))?,
            });
        }
        if let Some(rev) = &self.revocation_data {
            if !rev.is_empty() {
                log::info!(
                    "cades: embedding -LT revocation values ({} OCSP, {} CRL)",
                    rev.ocsp_responses.len(),
                    rev.crls.len(),
                );
                let rev_der = encode_revocation_values(rev)?;
                let rev_value = AttributeValue::from_der(&rev_der).map_err(|e| {
                    Error::Cms(format!("revocation-values AttributeValue: {e}"))
                })?;
                unsigned_vec.push(Attribute {
                    oid: OID_REVOCATION_VALUES,
                    values: SetOfVec::try_from(vec![rev_value]).map_err(|e| {
                        Error::Cms(format!("revocation-values attribute SET: {e}"))
                    })?,
                });
            }
        }
        let unsigned_attrs = if unsigned_vec.is_empty() {
            None
        } else {
            Some(
                SetOfVec::try_from(unsigned_vec)
                    .map_err(|e| Error::Cms(format!("UnsignedAttributes SET: {e}")))?,
            )
        };

        let mut signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg: digest_alg.clone(),
            signed_attrs: Some(signed_attrs_set),
            signature_algorithm: signature_alg,
            signature: sig_value,
            unsigned_attrs,
        };

        // ---------- SignedData scaffolding (certs/crls first so the
        // archive-timestamp imprint computation can reach them) ----------
        let digest_algorithms = der::asn1::SetOfVec::try_from(vec![digest_alg])
            .map_err(|e| Error::Cms(format!("DigestAlgorithmIdentifiers: {e}")))?;

        let mut all_certs: Vec<&Certificate> = vec![&self.cert.parsed];
        for c in &self.additional_certs {
            all_certs.push(&c.parsed);
        }
        let cert_set = build_cert_set(&all_certs)?;

        // ---------- optional CAdES-B-LTA archive timestamp ----------
        //
        // RFC 5126 §6.4.1 specifies the message imprint input as the
        // concatenation, in order:
        //   1. encapContentInfo eContent — or, for detached
        //      signatures, the detached content bytes.
        //   2. The DER of `SignedData.certificates`, if present.
        //   3. The DER of `SignedData.crls`, if present.
        //   4. The DER of each preceding SignerInfo. We have one
        //      signer, so this is empty.
        //   5. The DER of the current SignerInfo's components in
        //      order, EXCLUDING the archive-time-stamp attribute
        //      being added (so all -T / -LT attrs that landed above
        //      ARE included).
        //
        // The receiver applies the same hash algorithm declared
        // inside the TST's TSTInfo.messageImprint to verify.
        if let Some(get_archive_token) = &self.archive_timestamp_fn {
            log::info!("cades: requesting -LTA archive timestamp");
            let pre_si_der = signer_info
                .to_der()
                .map_err(|e| Error::Cms(format!("pre-archive SignerInfo to_der: {e}")))?;
            let cert_set_der = cert_set
                .to_der()
                .map_err(|e| Error::Cms(format!("cert set to_der for archive imprint: {e}")))?;
            let imprint = build_archive_imprint(self.data, &cert_set_der, &[], &pre_si_der);
            let token_der = get_archive_token(&imprint)?;
            let ats_value = AttributeValue::from_der(&token_der).map_err(|e| {
                Error::Cms(format!("archive timestamp AttributeValue: {e}"))
            })?;
            let ats_attr = Attribute {
                oid: OID_ARCHIVE_TIMESTAMP_V1,
                values: SetOfVec::try_from(vec![ats_value]).map_err(|e| {
                    Error::Cms(format!("archive-time-stamp attribute SET: {e}"))
                })?,
            };
            let mut new_unsigned: Vec<Attribute> = signer_info
                .unsigned_attrs
                .as_ref()
                .map(|s| s.as_slice().to_vec())
                .unwrap_or_default();
            new_unsigned.push(ats_attr);
            signer_info.unsigned_attrs = Some(
                SetOfVec::try_from(new_unsigned)
                    .map_err(|e| Error::Cms(format!("re-sort unsigned attrs after ATS: {e}")))?,
            );
        }

        let signer_infos = SignerInfos(
            SetOfVec::try_from(vec![signer_info])
                .map_err(|e| Error::Cms(format!("SignerInfos: {e}")))?,
        );

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: OID_ID_DATA,
                econtent: None, // detached
            },
            certificates: Some(cert_set),
            crls: None,
            signer_infos,
        };

        // ---------- ContentInfo wrapper ----------
        let sd_der = signed_data
            .to_der()
            .map_err(|e| Error::Cms(format!("encode SignedData: {e}")))?;
        let ci = ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::from_der(&sd_der)
                .map_err(|e| Error::Cms(format!("wrap SignedData in Any: {e}")))?,
        };
        ci.to_der()
            .map_err(|e| Error::Cms(format!("encode ContentInfo: {e}")))
    }

    // ---------- per-attribute builders ----------

    fn attr_content_type(&self) -> Result<Attribute> {
        let v = AttributeValue::from_der(
            &OID_ID_DATA
                .to_der()
                .map_err(|e| Error::Cms(format!("OID to_der: {e}")))?,
        )
        .map_err(|e| Error::Cms(format!("content-type AttributeValue: {e}")))?;
        let values: SetOfVec<AttributeValue> = SetOfVec::try_from(vec![v])
            .map_err(|e| Error::Cms(format!("content-type SET: {e}")))?;
        Ok(Attribute {
            oid: OID_CONTENT_TYPE,
            values,
        })
    }

    fn attr_message_digest(&self) -> Result<Attribute> {
        let md = self.hash_algo.hash(self.data);
        let octet = OctetString::new(md)
            .map_err(|e| Error::Cms(format!("OctetString messageDigest: {e}")))?;
        let v = AttributeValue::from_der(
            &octet
                .to_der()
                .map_err(|e| Error::Cms(format!("OctetString to_der: {e}")))?,
        )
        .map_err(|e| Error::Cms(format!("message-digest AttributeValue: {e}")))?;
        Ok(Attribute {
            oid: OID_MESSAGE_DIGEST,
            values: SetOfVec::try_from(vec![v])
                .map_err(|e| Error::Cms(format!("message-digest SET: {e}")))?,
        })
    }

    fn attr_signing_time(&self) -> Result<Attribute> {
        // PKCS#9 §5.4.1: dates ≤ 2049 use UTCTime, ≥ 2050 use
        // GeneralizedTime. We always use GeneralizedTime to keep the
        // encoding simple and forward-compatible.
        let gt = GeneralizedTime::from_system_time(self.signing_time)
            .map_err(|e| Error::Cms(format!("GeneralizedTime: {e}")))?;
        let v = AttributeValue::from_der(
            &gt.to_der()
                .map_err(|e| Error::Cms(format!("GeneralizedTime to_der: {e}")))?,
        )
        .map_err(|e| Error::Cms(format!("signing-time AttributeValue: {e}")))?;
        Ok(Attribute {
            oid: OID_SIGNING_TIME,
            values: SetOfVec::try_from(vec![v])
                .map_err(|e| Error::Cms(format!("signing-time SET: {e}")))?,
        })
    }

    fn attr_signing_cert_v2(&self) -> Result<Attribute> {
        // ESS SigningCertificateV2 (RFC 5035):
        //   SigningCertificateV2 ::= SEQUENCE {
        //       certs    SEQUENCE OF ESSCertIDv2,
        //       policies SEQUENCE OF PolicyInformation OPTIONAL
        //   }
        //   ESSCertIDv2 ::= SEQUENCE {
        //       hashAlgorithm AlgorithmIdentifier DEFAULT id-sha256,
        //       certHash      OCTET STRING,
        //       issuerSerial  IssuerSerial OPTIONAL
        //   }
        //
        // We emit certs only (no policies), and inside ESSCertIDv2 we
        // omit hashAlgorithm when it's the default (sha256) — that's
        // what every TR-03110 / ETSI verifier expects.
        let cert_hash = self.cert.cert_digest(self.hash_algo);
        let mut ess_cert_id_v2 = Vec::new();
        if self.hash_algo != HashAlgo::Sha256 {
            // Emit explicit AlgorithmIdentifier when not the default.
            let algid = AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(self.hash_algo.oid_str()),
                parameters: None,
            };
            ess_cert_id_v2.extend_from_slice(
                &algid
                    .to_der()
                    .map_err(|e| Error::Cms(format!("ESS AlgId: {e}")))?,
            );
        }
        let octet = OctetString::new(cert_hash)
            .map_err(|e| Error::Cms(format!("ESS certHash OctetString: {e}")))?;
        ess_cert_id_v2.extend_from_slice(
            &octet
                .to_der()
                .map_err(|e| Error::Cms(format!("certHash to_der: {e}")))?,
        );
        // Wrap as SEQUENCE
        let ess_cert_id_v2_seq = wrap_sequence(&ess_cert_id_v2);
        // certs SEQUENCE OF ESSCertIDv2 — wrap that one element
        let certs_seq_of = wrap_sequence(&ess_cert_id_v2_seq);
        // outer SigningCertificateV2 SEQUENCE
        let outer = wrap_sequence(&certs_seq_of);

        let v = AttributeValue::from_der(&outer)
            .map_err(|e| Error::Cms(format!("SigningCertificateV2 AttributeValue: {e}")))?;
        Ok(Attribute {
            oid: OID_SIGNING_CERTIFICATE_V2,
            values: SetOfVec::try_from(vec![v])
                .map_err(|e| Error::Cms(format!("signing-cert-v2 SET: {e}")))?,
        })
    }
}

// ---------- DER plumbing helpers ----------

/// Concatenate the bytes that feed the archive-time-stamp-v1 message
/// imprint, per RFC 5126 §6.4.1. Exposed `pub(crate)` so the
/// verifier can reproduce the exact same byte sequence.
pub(crate) fn build_archive_imprint(
    content: &[u8],
    cert_set_der: &[u8],
    crls_der: &[u8],
    signer_info_der: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(content.len() + cert_set_der.len() + crls_der.len() + signer_info_der.len());
    out.extend_from_slice(content);
    out.extend_from_slice(cert_set_der);
    out.extend_from_slice(crls_der);
    out.extend_from_slice(signer_info_der);
    out
}

/// Encode a `RevocationValues` SEQUENCE (RFC 5126 §6.3.4):
///
/// ```text
/// RevocationValues ::= SEQUENCE {
///   crlVals  [0] EXPLICIT SEQUENCE OF CertificateList OPTIONAL,
///   ocspVals [1] EXPLICIT SEQUENCE OF BasicOCSPResponse OPTIONAL
/// }
/// ```
///
/// We unwrap each stored `OcspResponse` DER to its inner
/// `BasicOcspResponse` here, since RFC 5126 embeds the Basic form.
fn encode_revocation_values(rev: &RevocationData) -> Result<Vec<u8>> {
    use x509_ocsp::OcspResponse;
    let mut body = Vec::new();

    if !rev.crls.is_empty() {
        let mut crl_seq = Vec::new();
        for crl_der in &rev.crls {
            crl_seq.extend_from_slice(crl_der);
        }
        // [0] EXPLICIT SEQUENCE OF CertificateList
        body.push(0xA0);
        push_len(&mut body, crl_seq.len() + sequence_header_len(crl_seq.len()));
        body.extend_from_slice(&wrap_sequence(&crl_seq));
    }
    if !rev.ocsp_responses.is_empty() {
        let mut ocsp_seq = Vec::new();
        for ocsp_der in &rev.ocsp_responses {
            // Unwrap OcspResponse → BasicOcspResponse DER.
            let outer = OcspResponse::from_der(ocsp_der)
                .map_err(|e| Error::Cms(format!("re-decode OcspResponse: {e}")))?;
            let bytes = outer
                .response_bytes
                .ok_or_else(|| Error::Cms("OcspResponse missing responseBytes".into()))?;
            ocsp_seq.extend_from_slice(bytes.response.as_bytes());
        }
        // [1] EXPLICIT SEQUENCE OF BasicOCSPResponse
        body.push(0xA1);
        push_len(&mut body, ocsp_seq.len() + sequence_header_len(ocsp_seq.len()));
        body.extend_from_slice(&wrap_sequence(&ocsp_seq));
    }
    Ok(wrap_sequence(&body))
}

fn sequence_header_len(body_len: usize) -> usize {
    if body_len < 0x80 {
        2
    } else if body_len <= 0xFF {
        3
    } else if body_len <= 0xFFFF {
        4
    } else {
        5
    }
}

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.push(0x81);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0x82);
        out.push((n >> 8) as u8);
        out.push((n & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push((n & 0xFF) as u8);
    }
}

/// Build a `CertificateSet` from owned `Certificate` references.
fn build_cert_set(certs: &[&Certificate]) -> Result<CertificateSet> {
    let choices: Vec<CertificateChoices> = certs
        .iter()
        .map(|c| CertificateChoices::Certificate((*c).clone()))
        .collect();
    let set = SetOfVec::try_from(choices)
        .map_err(|e| Error::Cms(format!("CertificateSet: {e}")))?;
    Ok(CertificateSet(set))
}

/// Prepend a `SEQUENCE` (0x30) tag + DER length to a body slice.
fn wrap_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30);
    out.extend_from_slice(&encode_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// DER definite-length encoder (short form < 128, long form ≥ 128).
fn encode_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n <= 0xFF {
        vec![0x81, n as u8]
    } else if n <= 0xFFFF {
        vec![0x82, (n >> 8) as u8, (n & 0xFF) as u8]
    } else if n <= 0xFFFFFF {
        vec![
            0x83,
            (n >> 16) as u8,
            (n >> 8) as u8 & 0xFF,
            (n & 0xFF) as u8,
        ]
    } else {
        vec![
            0x84,
            (n >> 24) as u8,
            (n >> 16) as u8 & 0xFF,
            (n >> 8) as u8 & 0xFF,
            (n & 0xFF) as u8,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_length_short_form() {
        assert_eq!(encode_length(0x10), vec![0x10]);
        assert_eq!(encode_length(0x7F), vec![0x7F]);
    }

    #[test]
    fn encode_length_long_form() {
        assert_eq!(encode_length(0x80), vec![0x81, 0x80]);
        assert_eq!(encode_length(0xFF), vec![0x81, 0xFF]);
        assert_eq!(encode_length(0x0100), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_length(0xFFFF), vec![0x82, 0xFF, 0xFF]);
        assert_eq!(encode_length(0x10000), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn wrap_sequence_shape() {
        let body = vec![0x01, 0x02, 0x03];
        let s = wrap_sequence(&body);
        assert_eq!(s, vec![0x30, 0x03, 0x01, 0x02, 0x03]);
    }
}
