// SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 9 round-trip — sign with our crate, verify with our crate.
//!
//! Covers all three families (CAdES, PAdES, XAdES) plus the negative
//! case where the trust root doesn't match.
//!
//! Run with:
//!     cargo test --features test-signer -- --ignored

#![cfg(feature = "test-signer")]

use std::path::PathBuf;
use std::time::SystemTime;

use firma_cr_core::cades::CadesBuilder;
use firma_cr_core::cert::SignerCert;
use firma_cr_core::digest::HashAlgo;
use firma_cr_core::pades;
use firma_cr_core::signer::SoftwareSigner;
use firma_cr_core::verify;
use firma_cr_core::xades::XadesBuilder;

fn ca_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_ca/out")
}
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Test-only RFC 3161 TimeStampToken issuer. Produces a real
/// `id-signedData` CMS over a TSTInfo SEQUENCE — same shape a real
/// TSA would return — so `verify::tsa::verify_token` exercises every
/// step of its decode + validate path.
mod test_tsa {
    use std::time::SystemTime;

    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier,
        SignerInfo, SignerInfos,
    };
    use der::asn1::{OctetString, SetOfVec};
    use der::{Any, Decode, Encode, oid::ObjectIdentifier};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::Certificate;
    use x509_cert::attr::{Attribute, AttributeValue};

    use firma_cr_core::cert::SignerCert;
    use firma_cr_core::digest::HashAlgo;
    use firma_cr_core::pkcs11_client::build_digest_info;
    use firma_cr_core::signer::{Signer, SoftwareSigner};

    const OID_SIGNED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    const OID_ID_CT_TST_INFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
    const OID_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const OID_CONTENT_TYPE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    const OID_MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

    /// Issue a TimeStampToken DER over `payload`, signed by
    /// `tsa_signer` with `tsa_cert` as the TSA cert. `chain_certs`
    /// are extra certs (intermediates) to embed in `certificates`
    /// so the verifier can build a path.
    pub fn issue(
        payload: &[u8],
        hash_algo: HashAlgo,
        tsa_signer: &SoftwareSigner,
        tsa_cert: &SignerCert,
        chain_certs: &[&SignerCert],
    ) -> Vec<u8> {
        // ---- 1. TSTInfo DER (hand-rolled) ----
        let imprint = hash_algo.hash(payload);
        let tst_info_der = build_tst_info(hash_algo, &imprint);

        // ---- 2. signedAttrs over TSTInfo ----
        let content_type_value =
            AttributeValue::from_der(&OID_ID_CT_TST_INFO.to_der().unwrap()).unwrap();
        let content_type_attr = Attribute {
            oid: OID_CONTENT_TYPE,
            values: SetOfVec::try_from(vec![content_type_value]).unwrap(),
        };
        let md_oct = OctetString::new(hash_algo.hash(&tst_info_der)).unwrap();
        let md_value = AttributeValue::from_der(&md_oct.to_der().unwrap()).unwrap();
        let md_attr = Attribute {
            oid: OID_MESSAGE_DIGEST,
            values: SetOfVec::try_from(vec![md_value]).unwrap(),
        };
        let signed_attrs_set: SetOfVec<Attribute> =
            SetOfVec::try_from(vec![content_type_attr, md_attr]).unwrap();

        // ---- 3. sign(SET-OF DER) ----
        let attrs_der = signed_attrs_set.to_der().unwrap();
        let attrs_hash = hash_algo.hash(&attrs_der);
        let digest_info = build_digest_info(hash_algo, &attrs_hash);
        let signature_bytes = tsa_signer
            .sign_digest_info(&digest_info)
            .expect("test TSA sign");

        // ---- 4. SignerInfo ----
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tsa_cert.parsed.tbs_certificate.issuer.clone(),
            serial_number: tsa_cert.parsed.tbs_certificate.serial_number.clone(),
        });
        let digest_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(hash_algo.oid_str()),
            parameters: None,
        };
        let signature_alg = AlgorithmIdentifierOwned {
            oid: OID_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        };
        let sig_value = OctetString::new(signature_bytes).unwrap();
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg: digest_alg.clone(),
            signed_attrs: Some(signed_attrs_set),
            signature_algorithm: signature_alg,
            signature: sig_value,
            unsigned_attrs: None,
        };
        let signer_infos =
            SignerInfos(SetOfVec::try_from(vec![signer_info]).unwrap());

        // ---- 5. SignedData ----
        let digest_algorithms = SetOfVec::try_from(vec![digest_alg]).unwrap();
        let mut all_certs: Vec<&Certificate> = vec![&tsa_cert.parsed];
        for c in chain_certs {
            all_certs.push(&c.parsed);
        }
        let cert_set = build_cert_set(&all_certs);

        let tst_info_oct = OctetString::new(tst_info_der.clone()).unwrap();
        let econtent_any = Any::from_der(&tst_info_oct.to_der().unwrap()).unwrap();
        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: OID_ID_CT_TST_INFO,
                econtent: Some(econtent_any),
            },
            certificates: Some(cert_set),
            crls: None,
            signer_infos,
        };

        // ---- 6. ContentInfo wrap ----
        let sd_der = signed_data.to_der().unwrap();
        let ci = ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::from_der(&sd_der).unwrap(),
        };
        ci.to_der().unwrap()
    }

    fn build_cert_set(certs: &[&Certificate]) -> CertificateSet {
        let choices: Vec<CertificateChoices> = certs
            .iter()
            .map(|c| CertificateChoices::Certificate((*c).clone()))
            .collect();
        CertificateSet(SetOfVec::try_from(choices).unwrap())
    }

    /// Hand-roll the TSTInfo SEQUENCE DER.
    fn build_tst_info(hash_algo: HashAlgo, imprint: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();

        // version INTEGER 1
        body.extend_from_slice(&[0x02, 0x01, 0x01]);

        // policy OID 1.2.3.4.5 → 06 04 2A 03 04 05
        body.extend_from_slice(&[0x06, 0x04, 0x2A, 0x03, 0x04, 0x05]);

        // messageImprint SEQUENCE
        let mut mi = Vec::new();
        // hashAlgorithm SEQUENCE { OID, NULL }
        let mut alg = Vec::new();
        let alg_oid_der = ObjectIdentifier::new_unwrap(hash_algo.oid_str())
            .to_der()
            .unwrap();
        alg.extend_from_slice(&alg_oid_der);
        alg.extend_from_slice(&[0x05, 0x00]); // NULL
        mi.extend_from_slice(&seq(&alg));
        // hashedMessage OCTET STRING
        mi.push(0x04);
        push_len(&mut mi, imprint.len());
        mi.extend_from_slice(imprint);
        body.extend_from_slice(&seq(&mi));

        // serialNumber INTEGER 1
        body.extend_from_slice(&[0x02, 0x01, 0x01]);

        // genTime GeneralizedTime "YYYYMMDDHHMMSSZ"
        let gt = fmt_generalized_time(SystemTime::now());
        body.push(0x18);
        push_len(&mut body, gt.len());
        body.extend_from_slice(gt.as_bytes());

        seq(&body)
    }

    fn seq(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 4);
        out.push(0x30);
        push_len(&mut out, body.len());
        out.extend_from_slice(body);
        out
    }

    fn push_len(out: &mut Vec<u8>, n: usize) {
        if n < 0x80 {
            out.push(n as u8);
        } else if n <= 0xFF {
            out.push(0x81);
            out.push(n as u8);
        } else {
            out.push(0x82);
            out.push((n >> 8) as u8);
            out.push((n & 0xFF) as u8);
        }
    }

    fn fmt_generalized_time(t: SystemTime) -> String {
        // RFC 5280 wants YYYYMMDDHHMMSSZ with no fractional seconds.
        // We don't need accuracy for a synthetic token — fix a known
        // timestamp.
        let _ = t;
        "20260601150000Z".to_string()
    }
}

/// Test-only OCSP responder. Issues a real signed `OcspResponse` DER
/// that reports the requested cert as `good`, using the supplied
/// responder cert + key.
mod mock_ocsp {
    use der::DateTime;
    use der::Encode;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::RsaPrivateKey;
    use sha1::Sha1;
    use x509_ocsp::builder::OcspResponseBuilder;
    use x509_ocsp::{
        CertId, CertStatus, OcspGeneralizedTime, ResponderId, SingleResponse,
    };

    use firma_cr_core::cert::SignerCert;

    pub fn issue_good(
        cert: &SignerCert,
        issuer: &SignerCert,
        responder_cert: &SignerCert,
        responder_key_pem: &std::path::Path,
    ) -> Vec<u8> {
        let key_pem = std::fs::read_to_string(responder_key_pem).expect("read responder key");
        let rsa_key =
            RsaPrivateKey::from_pkcs8_pem(&key_pem).expect("parse responder PKCS#8 key");
        let mut signer = SigningKey::<Sha256>::new(rsa_key);

        let cert_id = CertId::from_cert::<Sha1>(&issuer.parsed, &cert.parsed)
            .expect("build CertId");
        let produced = OcspGeneralizedTime::from(
            DateTime::new(2026, 6, 1, 12, 0, 0).expect("DateTime"),
        );
        let single = SingleResponse::new(cert_id, CertStatus::good(), produced.clone())
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2026, 12, 1, 12, 0, 0).expect("DateTime"),
            ));

        let responder_id =
            ResponderId::ByName(responder_cert.parsed.tbs_certificate.subject.clone());
        let outer = OcspResponseBuilder::new(responder_id)
            .with_single_response(single)
            .sign(
                &mut signer,
                Some(vec![responder_cert.parsed.clone()]),
                produced,
            )
            .expect("sign OCSP response");
        outer.to_der().expect("encode OcspResponse")
    }
}

#[test]
#[ignore]
fn verify_round_trip_cades() {
    let ca = ca_dir();
    let leaf_crt = ca.join("test-leaf.crt");
    let leaf_key = ca.join("test-leaf.key");
    let chain_pem = ca.join("test-chain.pem");
    let root_crt = ca.join("test-root.crt");
    let payload = fixtures_dir().join("small.dat");

    assert!(leaf_crt.exists(), "run tests/test_ca/gen-test-ca.sh first");

    let cert = SignerCert::from_file(&leaf_crt).expect("leaf cert");
    let chain = SignerCert::load_chain_from_pem(&chain_pem).expect("chain");
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&leaf_key).expect("leaf key");
    let data = std::fs::read(&payload).expect("read payload");
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain_refs)
        .build(&signer)
        .expect("build cms");

    let root = SignerCert::from_file(&root_crt).expect("root cert");
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(report.ok, "round-trip verification should pass: {report:?}");
    assert!(report.signer_subject.is_some());
}

/// A -B-B CAdES carries no embedded revocation data. With the default policy it
/// verifies; with `require_revocation` it must hard-fail (3f).
#[test]
#[ignore]
fn verify_cades_require_revocation_hard_fails_without_data() {
    let ca = ca_dir();
    let leaf_crt = ca.join("test-leaf.crt");
    let leaf_key = ca.join("test-leaf.key");
    let chain_pem = ca.join("test-chain.pem");
    let root_crt = ca.join("test-root.crt");
    let payload = fixtures_dir().join("small.dat");

    assert!(leaf_crt.exists(), "run tests/test_ca/gen-test-ca.sh first");

    let cert = SignerCert::from_file(&leaf_crt).expect("leaf cert");
    let chain = SignerCert::load_chain_from_pem(&chain_pem).expect("chain");
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&leaf_key).expect("leaf key");
    let data = std::fs::read(&payload).expect("read payload");
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain_refs)
        .build(&signer)
        .expect("build cms");
    let root = SignerCert::from_file(&root_crt).expect("root cert");

    // Default policy: -B-B (no revocation data) passes.
    let lenient = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    assert!(lenient.ok, "default policy should accept -B-B: {lenient:?}");

    // require_revocation: the same signature must now fail.
    let opts = verify::VerifyOptions { require_revocation: true, ..Default::default() };
    let strict = verify::cms::verify_detached(&cms_der, &data, &root, opts)
        .expect("verify_detached");
    assert!(
        !strict.ok,
        "require_revocation must reject a signature with no revocation data: {strict:?}"
    );
}

#[test]
#[ignore]
fn verify_cades_rejects_tampered_content() {
    let ca = ca_dir();
    let leaf_crt = ca.join("test-leaf.crt");
    let leaf_key = ca.join("test-leaf.key");
    let chain_pem = ca.join("test-chain.pem");
    let root_crt = ca.join("test-root.crt");
    let payload = fixtures_dir().join("small.dat");

    let cert = SignerCert::from_file(&leaf_crt).unwrap();
    let chain = SignerCert::load_chain_from_pem(&chain_pem).unwrap();
    let signer = SoftwareSigner::from_file(&leaf_key).unwrap();
    let data = std::fs::read(&payload).unwrap();
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .build(&signer)
        .unwrap();

    let root = SignerCert::from_file(&root_crt).unwrap();
    let mut tampered = data.clone();
    tampered[0] ^= 0x01;
    let report = verify::cms::verify_detached(&cms_der, &tampered, &root, Default::default())
        .expect("verify_detached");
    assert!(!report.ok, "tampered content must FAIL verification");
}

/// Minimal lopdf-parseable PDF for round-trip — same recipe as
/// `integration_pades.rs` so we don't depend on a fixture file.
fn make_test_pdf() -> Vec<u8> {
    use lopdf::content::{Content, Operation};
    use lopdf::dictionary;
    use lopdf::{Document, Object, Stream};

    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Courier",
    });
    let resources_id = doc.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 24.into()]),
            Operation::new("Td", vec![100.into(), 600.into()]),
            Operation::new("Tj", vec![Object::string_literal("verify round-trip")]),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => content_id,
        "Resources" => resources_id,
    });
    doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
        "Type" => "Pages",
        "Kids" => vec![page_id.into()],
        "Count" => 1,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
    }));
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).expect("encode pdf");
    buf
}

#[test]
#[ignore]
fn verify_round_trip_pades() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let pdf_in = make_test_pdf();

    let signed = pades::sign_pdf(
        &pdf_in,
        &cert,
        &chain_refs,
        HashAlgo::Sha256,
        Some("round-trip verify"),
        None,
        None,
        SystemTime::now(),
        &signer,
        None,
        None,
        false,
        None,
    )
    .expect("sign pdf");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::pades::verify_pdf(&signed, &root, Default::default()).expect("verify_pdf");
    println!("{}", report.pretty());
    assert!(report.ok, "PAdES round-trip should verify: {report:?}");
}

/// Appending content after a validly-signed PDF (the classic PAdES added-content
/// forgery) must be rejected — the signature's /ByteRange no longer reaches EOF.
#[test]
#[ignore]
fn verify_pades_rejects_appended_content() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();

    let signed = pades::sign_pdf(
        &make_test_pdf(),
        &cert,
        &chain_refs,
        HashAlgo::Sha256,
        None,
        None,
        None,
        SystemTime::now(),
        &signer,
        None,
        None,
        false,
        None,
    )
    .expect("sign pdf");
    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();

    // Baseline: the untouched signature verifies.
    assert!(verify::pades::verify_pdf(&signed, &root, Default::default()).unwrap().ok);

    // Attack: append an unsigned incremental update / arbitrary bytes after EOF.
    let mut tampered = signed.clone();
    tampered.extend_from_slice(b"\n%% appended unsigned content\n9999 0 obj\n<< /Evil true >>\nendobj\n");
    let report = verify::pades::verify_pdf(&tampered, &root, Default::default()).expect("verify_pdf");
    assert!(
        !report.ok,
        "appending content after the signature must fail verification: {report:?}"
    );
}

#[test]
#[ignore]
fn verify_pades_rejects_tampered_pdf() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let pdf_in = make_test_pdf();
    let signed = pades::sign_pdf(
        &pdf_in,
        &cert,
        &chain.iter().collect::<Vec<_>>(),
        HashAlgo::Sha256,
        None,
        None,
        None,
        SystemTime::now(),
        &signer,
        None,
        None,
        false,
        None,
    )
    .expect("sign pdf");

    // Flip a byte inside the first half of the byte-range (the
    // pre-signature region). We need a byte that's neither inside
    // /ByteRange nor /Contents — pick offset 100 which lands in the
    // PDF header/body well before the signature dict.
    let mut tampered = signed.clone();
    tampered[100] ^= 0x01;

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::pades::verify_pdf(&tampered, &root, Default::default()).expect("verify_pdf");
    assert!(!report.ok, "tampered PDF must FAIL verification");
}

#[test]
#[ignore]
fn verify_round_trip_xades() {
    let ca = ca_dir();
    let fx = fixtures_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let xml_in = std::fs::read(fx.join("small.xml")).expect("read fixture xml");

    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &cert)
        .include_chain(chain_refs)
        .build_enveloped(&signer)
        .expect("build xades");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(&signed, &root, Default::default()).expect("verify_xml");
    println!("{}", report.pretty());
    assert!(report.ok, "XAdES round-trip should verify: {report:?}");
}

#[test]
#[ignore]
fn verify_xades_rejects_tampered_document_body() {
    // After Phase 9-followup, the URI="" Reference is recomputed; a
    // byte flipped in the document body before the Signature element
    // must FAIL the per-reference digest check (even though the
    // SignedInfo RSA signature itself is still valid).
    let ca = ca_dir();
    let fx = fixtures_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let xml_in = std::fs::read(fx.join("small.xml")).expect("read fixture xml");
    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .build_enveloped(&signer)
        .expect("build xades");

    // Flip a single char inside the body content of the first
    // text element. Our fixture has something like "<msg>…</msg>";
    // change a letter inside the msg payload before the Signature
    // element appears.
    let mut s = String::from_utf8(signed).expect("utf-8");
    let sig_start = s.find("<ds:Signature").expect("signature present");
    // Find the first lowercase ASCII letter in [0..sig_start) and
    // bump it to its successor.
    let body = &s[..sig_start];
    let flip_pos = body
        .find(|c: char| c.is_ascii_lowercase() && c != 'z')
        .expect("a lowercase letter to tamper with");
    let new_char = (body.as_bytes()[flip_pos] + 1) as char;
    let mut bytes = s.into_bytes();
    bytes[flip_pos] = new_char as u8;
    s = String::from_utf8(bytes).unwrap();

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(s.as_bytes(), &root, Default::default()).expect("verify_xml");
    assert!(
        !report.ok,
        "tampered document body must FAIL verification: {report:?}"
    );
    let combined = report.warnings.join("|");
    assert!(
        combined.contains("DigestValue mismatch"),
        "expected a DigestValue mismatch warning, got: {combined}"
    );
}

#[test]
#[ignore]
fn verify_xades_rejects_tampered_signature_value() {
    let ca = ca_dir();
    let fx = fixtures_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let xml_in = std::fs::read(fx.join("small.xml")).expect("read fixture xml");
    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .build_enveloped(&signer)
        .expect("build xades");

    // Corrupt one base64 char inside <ds:SignatureValue>. Flipping
    // a payload byte (the document body) won't fail this verifier
    // yet because the URI="" Reference digest check is TODO; the
    // SignatureValue RSA check IS implemented, so corrupting a sig
    // char is the cleanest negative case.
    let mut s = String::from_utf8(signed).expect("utf-8");
    let start = s.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
    // Replace the char at position start+1 with a different valid
    // base64 char so length stays even.
    let mut bytes = s.into_bytes();
    bytes[start + 1] = if bytes[start + 1] == b'A' { b'B' } else { b'A' };
    s = String::from_utf8(bytes).unwrap();

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(s.as_bytes(), &root, Default::default()).expect("verify_xml");
    assert!(!report.ok, "tampered SignatureValue must FAIL");
}

/// Re-encode a CMS so its single SignerInfo carries a
/// `SubjectKeyIdentifier`-form SignerIdentifier instead of
/// IssuerAndSerial. The signature itself is unaffected (signedAttrs
/// don't reference the sid), so verification should still succeed —
/// but now exercising verify::cms's SKI branch.
fn rewrite_cms_to_ski_form(cms_der: &[u8]) -> Vec<u8> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::{SignedData, SignerIdentifier, SignerInfos};
    use der::asn1::{OctetString, SetOfVec};
    use der::{Any, Decode, Encode, oid::ObjectIdentifier};
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

    let ci = ContentInfo::from_der(cms_der).expect("parse CI");
    let mut sd: SignedData = ci.content.decode_as().expect("decode SignedData");

    // Look at the current SignerInfo's IssuerAndSerial to know which
    // embedded cert is the leaf, then pull THAT cert's SKI extension.
    let leaf_ias = match &sd.signer_infos.0.as_slice()[0].sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => ias.clone(),
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            panic!("test fixture unexpectedly already in SKI form")
        }
    };
    let cert_choice = sd
        .certificates
        .as_ref()
        .expect("no certs in SignedData")
        .0
        .as_slice()
        .iter()
        .find_map(|c| match c {
            CertificateChoices::Certificate(x)
                if x.tbs_certificate.issuer == leaf_ias.issuer
                    && x.tbs_certificate.serial_number == leaf_ias.serial_number =>
            {
                Some(x.clone())
            }
            _ => None,
        })
        .expect("no x509 cert in CMS matches the SignerInfo IssuerAndSerial");
    let exts = cert_choice
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("no extensions in test cert");
    let ski_outer = exts
        .iter()
        .find(|e| e.extn_id == OID_SKI)
        .expect("test leaf cert has no SKI extension — regenerate via gen-test-ca.sh?")
        .extn_value
        .clone();
    let ski_inner =
        OctetString::from_der(ski_outer.as_bytes()).expect("decode SKI inner OctetString");
    let ski_struct = SubjectKeyIdentifier(ski_inner);

    // Rebuild SignerInfos with the new sid form.
    let mut new_sis_vec: Vec<_> = Vec::new();
    for si in sd.signer_infos.0.as_slice() {
        let mut new_si = si.clone();
        new_si.sid = SignerIdentifier::SubjectKeyIdentifier(ski_struct.clone());
        new_sis_vec.push(new_si);
    }
    let new_sis = SignerInfos(SetOfVec::try_from(new_sis_vec).expect("rebuild SignerInfos"));
    sd.signer_infos = new_sis;

    // Re-wrap in ContentInfo and re-emit.
    let sd_der = sd.to_der().expect("encode SignedData");
    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: Any::from_der(&sd_der).expect("Any::from_der"),
    };
    new_ci.to_der().expect("encode ContentInfo")
}

#[test]
#[ignore]
fn verify_cades_accepts_signer_identifier_ski_form() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let payload = fixtures_dir().join("small.dat");
    let data = std::fs::read(&payload).unwrap();
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .build(&signer)
        .expect("build cms");

    let ski_cms = rewrite_cms_to_ski_form(&cms_der);
    assert_ne!(cms_der, ski_cms, "rewrite should change DER bytes");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&ski_cms, &data, &root, Default::default())
        .expect("verify_detached over SKI-form CMS");
    println!("{}", report.pretty());
    assert!(
        report.ok,
        "SKI-form SignerIdentifier should verify: {report:?}"
    );
}

#[test]
#[ignore]
fn verify_cades_rejects_wrong_trust_root() {
    let ca = ca_dir();
    let leaf_crt = ca.join("test-leaf.crt");
    let leaf_key = ca.join("test-leaf.key");
    let chain_pem = ca.join("test-chain.pem");
    let payload = fixtures_dir().join("small.dat");

    let cert = SignerCert::from_file(&leaf_crt).unwrap();
    let chain = SignerCert::load_chain_from_pem(&chain_pem).unwrap();
    let signer = SoftwareSigner::from_file(&leaf_key).unwrap();
    let data = std::fs::read(&payload).unwrap();
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .build(&signer)
        .unwrap();

    // Use the leaf cert AS the "root" — chain build will fail since
    // the leaf isn't self-signed and we have no real root anchor.
    let bad_root = SignerCert::from_file(&leaf_crt).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &bad_root, Default::default())
        .expect("verify_detached");
    assert!(
        !report.ok,
        "wrong trust root must FAIL verification: {report:?}"
    );
}

// ==========================================================
// Phase 9 follow-up — TimeStampToken (CAdES-T / XAdES-T)
// ==========================================================

fn build_tsa_callback(
    hash_algo: HashAlgo,
    leaf_key: &std::path::Path,
    leaf_crt: &std::path::Path,
    chain_pem: &std::path::Path,
) -> impl Fn(&[u8]) -> firma_cr_core::Result<Vec<u8>> + 'static {
    // Load the materials once; the callback owns clones so the
    // closure can be 'static.
    let tsa_signer = SoftwareSigner::from_file(leaf_key).expect("tsa signer");
    let tsa_cert = SignerCert::from_file(leaf_crt).expect("tsa cert");
    let tsa_chain =
        SignerCert::load_chain_from_pem(chain_pem).expect("tsa chain bundle");
    move |payload: &[u8]| {
        let chain_refs: Vec<&SignerCert> = tsa_chain.iter().collect();
        Ok(test_tsa::issue(
            payload,
            hash_algo,
            &tsa_signer,
            &tsa_cert,
            &chain_refs,
        ))
    }
}

#[test]
#[ignore]
fn verify_round_trip_cades_t() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .build(&signer)
        .expect("build CAdES-T");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(report.ok, "CAdES-T round-trip should verify: {report:?}");
    assert!(report.has_timestamp, "report should record presence of timestamp");
    let tv = report
        .timestamp
        .as_ref()
        .expect("timestamp verdict should be populated");
    assert!(tv.ok, "TSA validation should succeed: {tv:?}");
    assert!(tv.gen_time.is_some(), "genTime should be reported");
}

#[test]
#[ignore]
fn verify_cades_t_rejects_tampered_token() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .build(&signer)
        .expect("build CAdES-T");

    // Flip a byte deep inside the CMS — it'll land inside the
    // unsigned-attribute TimeStampToken's signature region with
    // high probability and trip token verification.
    let mut tampered = cms_der.clone();
    let mid = tampered.len() - 200;
    tampered[mid] ^= 0x01;

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&tampered, &data, &root, Default::default())
        .expect("verify_detached");
    assert!(
        !report.ok,
        "tampered token must FAIL verification: {report:?}"
    );
}

#[test]
#[ignore]
fn verify_round_trip_cades_lt() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    // The OCSP "responder" is the intermediate cert — the intermediate
    // signs status statements about its own children. Test-CA
    // generation produces a key file for that cert.
    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_revocation_data(rev)
        .build(&signer)
        .expect("build CAdES-LT");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(report.ok, "CAdES-LT round-trip should verify: {report:?}");
    let rv = report
        .revocation
        .as_ref()
        .expect("revocation verdict should be populated");
    assert!(rv.ok, "embedded revocation data should validate: {rv:?}");
    assert_eq!(rv.ocsp_status.as_deref(), Some("good"));
}

#[test]
#[ignore]
fn verify_round_trip_cades_lta() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };

    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let archive_tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .with_revocation_data(rev)
        .with_archive_timestamp(archive_tsa_fn)
        .build(&signer)
        .expect("build CAdES-LTA");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(report.ok, "CAdES-LTA round-trip should verify: {report:?}");
    let at = report
        .archive_timestamp
        .as_ref()
        .expect("archive timestamp verdict should be populated");
    assert!(at.ok, "embedded archive timestamp should validate: {at:?}");
    assert!(at.gen_time.is_some(), "archive TS genTime should be reported");
}

#[test]
#[ignore]
fn verify_round_trip_pades_lt() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let pdf_in = make_test_pdf();

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };

    let signed = pades::sign_pdf(
        &pdf_in,
        &leaf_crt,
        &chain.iter().collect::<Vec<_>>(),
        HashAlgo::Sha256,
        Some("round-trip LT"),
        None,
        None,
        SystemTime::now(),
        &signer,
        None,
        None,
        false,
        Some(&rev),
    )
    .expect("sign PAdES-LT");

    // Confirm the /DSS catalog entry actually landed.
    let pos = signed.windows(4).position(|w| w == b"/DSS");
    assert!(pos.is_some(), "expected /DSS dict in signed PDF");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::pades::verify_pdf(&signed, &root, Default::default())
        .expect("verify_pdf");
    println!("{}", report.pretty());
    assert!(report.ok, "PAdES-LT round-trip should verify: {report:?}");
    let rv = report.revocation.as_ref().expect("revocation verdict");
    assert!(rv.ok, "PDF /DSS revocation data should validate: {rv:?}");
    assert_eq!(rv.ocsp_status.as_deref(), Some("good"));
}

#[test]
#[ignore]
fn verify_round_trip_xades_lt() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let xml_in = std::fs::read(fixtures_dir().join("small.xml")).unwrap();

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };

    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_revocation_data(rev)
        .build_enveloped(&signer)
        .expect("build XAdES-LT");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(&signed, &root, Default::default())
        .expect("verify_xml");
    println!("{}", report.pretty());
    assert!(report.ok, "XAdES-LT round-trip should verify: {report:?}");
    let rv = report.revocation.as_ref().expect("revocation verdict");
    assert!(rv.ok, "XAdES revocation data should validate: {rv:?}");
    assert_eq!(rv.ocsp_status.as_deref(), Some("good"));
}

#[test]
#[ignore]
fn verify_round_trip_xades_t() {
    let ca = ca_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let xml_in = std::fs::read(fixtures_dir().join("small.xml")).unwrap();

    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &cert)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .build_enveloped(&signer)
        .expect("build XAdES-T");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(&signed, &root, Default::default())
        .expect("verify_xml");
    println!("{}", report.pretty());
    assert!(report.ok, "XAdES-T round-trip should verify: {report:?}");
    assert!(report.has_timestamp);
    let tv = report
        .timestamp
        .as_ref()
        .expect("timestamp verdict should be populated");
    assert!(tv.ok, "XAdES TSA validation should succeed: {tv:?}");
}

// ==========================================================
// Phase 12f — XAdES enveloping / detached × -T / -LT / -LTA
// ==========================================================

#[test]
#[ignore]
fn verify_round_trip_xades_enveloping_lta() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let content = b"<payload><amount>9999.99</amount></payload>";

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };
    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let archive_tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );

    let signed = XadesBuilder::new(b"", HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .with_revocation_data(rev)
        .with_archive_timestamp(archive_tsa_fn)
        .build_enveloping(content, &signer)
        .expect("build_enveloping with full -LTA");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(&signed, &root, Default::default())
        .expect("verify_xml");
    println!("{}", report.pretty());
    assert!(
        report.ok,
        "XAdES enveloping -LTA round-trip should verify: {report:?}"
    );
    assert!(
        report.revocation.as_ref().is_some_and(|r| r.ok),
        "revocation should be OK"
    );
    assert!(
        report.archive_timestamp.as_ref().is_some_and(|a| a.ok),
        "archive ts should be OK"
    );
}

#[test]
#[ignore]
fn verify_round_trip_xades_detached_lta() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let content = b"<invoice><number>2026-001</number></invoice>";

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };
    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let archive_tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );

    let signed = XadesBuilder::new(b"", HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .with_revocation_data(rev)
        .with_archive_timestamp(archive_tsa_fn)
        .build_detached(content, "invoice.xml", &signer)
        .expect("build_detached with full -LTA");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report =
        verify::xades::verify_xml_detached(&signed, content, &root, Default::default())
            .expect("verify_xml_detached");
    println!("{}", report.pretty());
    assert!(
        report.ok,
        "XAdES detached -LTA round-trip should verify: {report:?}"
    );
    assert!(
        report.archive_timestamp.as_ref().is_some_and(|a| a.ok),
        "archive ts should be OK"
    );
}

// ==========================================================
// Phase 12e — JSON verdict output
// ==========================================================

#[test]
#[ignore]
fn verify_report_serializes_to_json() {
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .build(&signer)
        .expect("build cms");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");

    let json = serde_json::to_string_pretty(&report).expect("serialize");
    // Spot-check schema: top-level + per-signer fields are present.
    assert!(json.contains("\"ok\""), "missing ok field");
    assert!(json.contains("\"signers\""), "missing signers field");
    assert!(
        json.contains("\"signer_subject\""),
        "missing signer_subject"
    );
    assert!(
        json.contains("\"has_timestamp\""),
        "missing has_timestamp"
    );

    // Round-trip via a serde_json::Value to confirm valid JSON.
    let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse");
    assert!(v["ok"].as_bool().unwrap_or(false));
    assert_eq!(v["signers"].as_array().map(|a| a.len()), Some(1));
}

// ==========================================================
// Phase 12c — time-shift validation
// ==========================================================

#[test]
#[ignore]
fn verify_cades_validation_time_outside_window_fails() {
    use firma_cr_core::verify::VerifyOptions;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .build(&signer)
        .expect("build cms");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();

    // Default (validation_time=None) uses "now" — the test-leaf
    // cert was generated <2y ago, so it's in window: PASS.
    let report_now =
        verify::cms::verify_detached(&cms_der, &data, &root, VerifyOptions::default())
            .expect("verify_detached");
    assert!(
        report_now.ok,
        "default validation_time should pass: {report_now:?}"
    );

    // 100 years in the future: cert long expired → FAIL.
    let far_future =
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(60 * 365 * 86_400);
    let report_future = verify::cms::verify_detached(
        &cms_der,
        &data,
        &root,
        VerifyOptions {
            validation_time: Some(far_future),
            ..Default::default()
        },
    )
    .expect("verify_detached");
    println!("{}", report_future.pretty());
    assert!(
        !report_future.ok,
        "validation_time far in future must FAIL on cert validity: {report_future:?}"
    );
    let warnings = &report_future.signers[0].warnings;
    assert!(
        warnings.iter().any(|w| w.contains("signer cert validity")),
        "expected 'signer cert validity' warning, got: {:?}",
        warnings
    );
}

// ==========================================================
// Phase 12b — multiple SignerInfo support
// ==========================================================

/// Re-encode a single-signer CMS into a two-signer CMS by cloning
/// the existing SignerInfo and flipping one byte inside the clone's
/// signature BIT STRING. Both SignerInfos share the same
/// (issuer, serial) → same signer cert; their DER differs only by
/// the tampered signature bytes, so SET-OF uniqueness still holds.
fn duplicate_signer_with_one_tampered(cms_der: &[u8]) -> Vec<u8> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::{SignedData, SignerInfos};
    use der::asn1::{OctetString, SetOfVec};
    use der::{Any, Decode, Encode};

    let ci = ContentInfo::from_der(cms_der).expect("parse CI");
    let mut sd: SignedData = ci.content.decode_as().expect("decode SignedData");

    let orig = sd.signer_infos.0.as_slice()[0].clone();
    let mut tampered = orig.clone();
    let mut sig = tampered.signature.as_bytes().to_vec();
    sig[10] ^= 0x01;
    tampered.signature = OctetString::new(sig).expect("tampered sig OctetString");

    let new_sis_vec = vec![orig, tampered];
    let new_sis = SignerInfos(SetOfVec::try_from(new_sis_vec).expect("two-element SET"));
    sd.signer_infos = new_sis;

    let sd_der = sd.to_der().expect("encode SignedData");
    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: Any::from_der(&sd_der).expect("wrap"),
    };
    new_ci.to_der().expect("encode CI")
}

#[test]
#[ignore]
fn verify_cades_multi_signer_one_tampered() {
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let single_cms = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .build(&signer)
        .expect("build cms");
    let multi_cms = duplicate_signer_with_one_tampered(&single_cms);

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&multi_cms, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(
        !report.ok,
        "multi-signer with one tampered must FAIL overall: {report:?}"
    );
    assert_eq!(
        report.signers.len(),
        2,
        "report should expose both signer verdicts"
    );
    let ok_count = report.signers.iter().filter(|s| s.ok).count();
    let failed_count = report.signers.iter().filter(|s| !s.ok).count();
    assert_eq!(ok_count, 1, "exactly one signer must verify OK");
    assert_eq!(failed_count, 1, "exactly one signer must FAIL");
    let bad = report.signers.iter().find(|s| !s.ok).unwrap();
    assert!(
        bad.warnings
            .iter()
            .any(|w| w.contains("RSA verification failed")),
        "tampered signer's warnings should mention RSA verification, got: {:?}",
        bad.warnings
    );
}

// ==========================================================
// Phase 12a — CRL signature verification
// ==========================================================

/// Test-only CRL issuer. Builds a `CertificateList` with an empty
/// `revokedCertificates` field, signed by the supplied issuer key
/// with sha256WithRSAEncryption.
mod mock_crl {
    use der::asn1::BitString;
    use der::{DateTime, Encode};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::signature::{Signer as _, SignatureEncoding as _};
    use rsa::RsaPrivateKey;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::crl::{CertificateList, TbsCertList};
    use x509_cert::time::Time;
    use x509_cert::Version;

    use firma_cr_core::cert::SignerCert;

    const OID_SHA256_RSA: der::oid::ObjectIdentifier =
        der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

    pub fn issue_empty(
        issuer_cert: &SignerCert,
        issuer_key_pem: &std::path::Path,
    ) -> Vec<u8> {
        let key_pem = std::fs::read_to_string(issuer_key_pem).expect("read CRL issuer key");
        let rsa_key =
            RsaPrivateKey::from_pkcs8_pem(&key_pem).expect("parse CRL issuer PKCS#8");

        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_RSA,
            parameters: Some(der::Any::null()),
        };
        let this_update = Time::GeneralTime(
            DateTime::new(2026, 6, 1, 12, 0, 0).expect("DateTime").into(),
        );
        let next_update = Some(Time::GeneralTime(
            DateTime::new(2027, 6, 1, 12, 0, 0).expect("DateTime").into(),
        ));
        let tbs = TbsCertList {
            version: Version::V2,
            signature: sig_alg.clone(),
            issuer: issuer_cert.parsed.tbs_certificate.subject.clone(),
            this_update,
            next_update,
            revoked_certificates: None,
            crl_extensions: None,
        };
        let tbs_der = tbs.to_der().expect("encode TbsCertList");
        let signer = SigningKey::<Sha256>::new(rsa_key);
        let signature_bytes = signer.sign(&tbs_der).to_bytes().to_vec();
        let signature = BitString::from_bytes(&signature_bytes).expect("BitString");
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sig_alg,
            signature,
        };
        crl.to_der().expect("encode CertificateList")
    }

    /// Flip one byte inside the BIT STRING signature so the
    /// CertificateList still decodes but its RSA signature no
    /// longer matches.
    pub fn flip_signature_byte(crl_der: &[u8]) -> Vec<u8> {
        use der::Decode;
        let mut crl = CertificateList::from_der(crl_der).expect("decode CRL");
        let mut sig = crl.signature.raw_bytes().to_vec();
        sig[20] ^= 0x01;
        crl.signature = BitString::from_bytes(&sig).expect("tampered BitString");
        crl.to_der().expect("re-encode tampered CRL")
    }
}

#[test]
#[ignore]
fn verify_cades_lt_rejects_tampered_crl_signature() {
    // No OCSP data, only a tampered CRL → the signer has no
    // remaining revocation coverage and verification must fail
    // with a "CRL signature verification failed" warning. Asserts
    // that the new RSA-verify path on the CRL is actually invoked.
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let crl_good = mock_crl::issue_empty(
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let crl_bad = mock_crl::flip_signature_byte(&crl_good);

    let rev = RevocationData {
        ocsp_responses: Vec::new(),
        crls: vec![crl_bad],
    };

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_revocation_data(rev)
        .build(&signer)
        .expect("build CAdES-LT with tampered CRL");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(
        !report.ok,
        "tampered CRL signature must FAIL verification: {report:?}"
    );
    let rv = report
        .revocation
        .as_ref()
        .expect("revocation verdict populated");
    assert!(
        rv.warnings
            .iter()
            .any(|w| w.contains("CRL signature verification failed")),
        "expected 'CRL signature verification failed' warning, got: {:?}",
        rv.warnings
    );
}

#[test]
#[ignore]
fn verify_cades_lt_accepts_valid_crl_signature() {
    // Sanity check: a properly-signed empty CRL should be accepted
    // and cover the signer cert (since the signer isn't on the
    // revoked list). Combined with no OCSP, this exercises only
    // the CRL path.
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let crl_good = mock_crl::issue_empty(
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );

    let rev = RevocationData {
        ocsp_responses: Vec::new(),
        crls: vec![crl_good],
    };

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_revocation_data(rev)
        .build(&signer)
        .expect("build CAdES-LT with valid CRL");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(
        report.ok,
        "valid CRL-only revocation should verify: {report:?}"
    );
}

// ==========================================================
// Phase 12d — OCSP delegated-signer EKU check
// ==========================================================

#[test]
#[ignore]
fn verify_cades_lt_rejects_ocsp_signer_without_ocspsigning_eku() {
    // Make the mock OCSP responder use test-leaf (which lacks the
    // id-kp-OCSPSigning EKU) instead of the issuer cert. This
    // simulates an attacker who got hold of a non-OCSP cert
    // signed by the same CA and tries to forge revocation answers.
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    // Confirm test-leaf does NOT carry id-kp-OCSPSigning so the
    // assertion below is meaningful, not a tautology.
    assert!(
        !test_leaf_has_ocsp_signing_eku(&leaf_crt),
        "test setup error: test-leaf already has OCSPSigning EKU"
    );

    let bad_ocsp = mock_ocsp::issue_good(
        &leaf_crt,           // the cert being asked about
        &intermediate_crt,   // its real issuer
        &leaf_crt,           // RESPONDER — delegated, EKU missing
        &ca.join("test-leaf.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![bad_ocsp],
        crls: Vec::new(),
    };

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_revocation_data(rev)
        .build(&signer)
        .expect("build CAdES-LT with delegated responder");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(
        !report.ok,
        "delegated OCSP signer without OCSPSigning EKU must FAIL: {report:?}"
    );
    let rv = report
        .revocation
        .as_ref()
        .expect("revocation verdict populated");
    assert!(
        rv.warnings
            .iter()
            .any(|w| w.contains("id-kp-OCSPSigning EKU")),
        "expected EKU-missing warning, got: {:?}",
        rv.warnings
    );
}

/// Tiny helper: peek at a cert's ExtendedKeyUsage extension and
/// say whether `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9) is listed.
fn test_leaf_has_ocsp_signing_eku(cert: &SignerCert) -> bool {
    use der::Decode;
    let exts = match cert.parsed.tbs_certificate.extensions.as_ref() {
        Some(e) => e,
        None => return false,
    };
    let eku_oid =
        der::oid::ObjectIdentifier::new_unwrap("2.5.29.37");
    let ocsp_signing =
        der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
    let ext = match exts.iter().find(|e| e.extn_id == eku_oid) {
        Some(e) => e,
        None => return false,
    };
    match x509_cert::ext::pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
        Ok(e) => e.0.iter().any(|o| *o == ocsp_signing),
        Err(_) => false,
    }
}

// ==========================================================
// Phase 11f — AIA chain-fetching
// ==========================================================

#[test]
#[ignore]
fn aia_fetch_issuer_chain_walks_one_hop() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::thread;

    use der::Encode;
    use der::pem::LineEnding;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::sha2::Sha256;
    use rsa::RsaPrivateKey;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    use firma_cr_core::cert::SignerCert;
    use firma_cr_core::revocation::aia;

    // ---- 1. Spin up a tiny single-shot HTTP server. ----
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/issuer.crt");

    // ---- 2. Generate root + leaf, with leaf carrying an AIA
    //         extension pointing at the URL above. ----
    let mut rng = rand::thread_rng();
    let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
    let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("leaf key");

    let root_subject =
        Name::from_str("CN=AIA Test Root,O=phase11f,C=ZZ").expect("root name");
    let root_spki = SubjectPublicKeyInfoOwned::try_from(
        root_key.to_public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .expect("root spki");
    let root_signer = SigningKey::<Sha256>::new(root_key.clone());
    let root_builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(std::time::Duration::new(365 * 24 * 3600, 0)).unwrap(),
        root_subject.clone(),
        root_spki,
        &root_signer,
    )
    .expect("root builder");
    let root_cert = root_builder.build().expect("root cert");
    let root_der = root_cert.to_der().expect("root to_der");

    let leaf_subject =
        Name::from_str("CN=AIA Test Leaf,O=phase11f,C=ZZ").expect("leaf name");
    let leaf_spki = SubjectPublicKeyInfoOwned::try_from(
        leaf_key.to_public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .expect("leaf spki");
    let issuer_for_leaf_signer = SigningKey::<Sha256>::new(root_key.clone());
    let mut leaf_builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        Validity::from_now(std::time::Duration::new(180 * 24 * 3600, 0)).unwrap(),
        leaf_subject,
        leaf_spki,
        &issuer_for_leaf_signer,
    )
    .expect("leaf builder");

    // AIA extension: one entry pointing at our HTTP server.
    let aia_value = AuthorityInfoAccessSyntax(vec![AccessDescription {
        access_method: der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2"),
        access_location: GeneralName::UniformResourceIdentifier(
            der::asn1::Ia5String::new(url.as_bytes()).expect("URL as IA5"),
        ),
    }]);
    leaf_builder
        .add_extension(&aia_value)
        .expect("attach AIA extension");
    let leaf_cert = leaf_builder.build().expect("leaf cert");

    // ---- 3. Serve the root cert from the listener. ----
    let pem = der::pem::encode_string("CERTIFICATE", LineEnding::LF, &root_der)
        .expect("PEM encode root");
    let pem_arc = Arc::new(pem);
    let pem_for_thread = Arc::clone(&pem_arc);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let body = pem_for_thread.as_str();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-pem-file\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        let _ = stream.write_all(resp.as_bytes());
    });

    // ---- 4. Resolve via aia::fetch_issuer_chain. ----
    let leaf_signer_cert = SignerCert {
        der: leaf_cert.to_der().unwrap(),
        parsed: leaf_cert,
    };
    let fetched = aia::fetch_issuer_chain(&leaf_signer_cert, 4).expect("fetch");

    server.join().expect("server thread joined");

    assert_eq!(fetched.len(), 1, "expected one fetched issuer cert");
    assert_eq!(
        fetched[0].subject_string(),
        "CN=AIA Test Root,O=phase11f,C=ZZ",
        "fetched cert should be the root",
    );
}

// ==========================================================
// Phase 11e — XAdES enveloping + detached modes
// ==========================================================

#[test]
#[ignore]
fn verify_round_trip_xades_enveloping() {
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    // The "content" we wrap inside <ds:Object> can be any XML.
    let content = b"<payload><msg>hello enveloping</msg></payload>";

    let signed = XadesBuilder::new(b"", HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .build_enveloping(content, &signer)
        .expect("build_enveloping");

    let s = std::str::from_utf8(&signed).unwrap();
    assert!(
        s.contains(r##"Id="obj-1""##),
        "expected enveloped Object element"
    );
    assert!(
        s.contains("<msg>hello enveloping</msg>"),
        "embedded content preserved"
    );

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(&signed, &root, Default::default())
        .expect("verify_xml");
    println!("{}", report.pretty());
    assert!(report.ok, "XAdES enveloping round-trip should verify: {report:?}");
}

#[test]
#[ignore]
fn verify_round_trip_xades_detached() {
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let content = b"<invoice><total>4567.89</total></invoice>";

    let signed = XadesBuilder::new(b"", HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .build_detached(content, "invoice.xml", &signer)
        .expect("build_detached");

    let s = std::str::from_utf8(&signed).unwrap();
    assert!(
        s.contains(r##"URI="invoice.xml""##),
        "expected detached URI in Reference"
    );
    // The signed file MUST NOT contain the invoice body — it lives
    // elsewhere.
    assert!(
        !s.contains("4567.89"),
        "detached signature must not embed content"
    );

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();

    // Passing the wrong content should FAIL.
    let bad_report = verify::xades::verify_xml_detached(
        &signed,
        b"<invoice><total>0.00</total></invoice>",
        &root,
        Default::default(),
    )
    .expect("verify_xml_detached");
    assert!(
        !bad_report.ok,
        "wrong external content must FAIL: {bad_report:?}"
    );

    // Passing the original content should PASS.
    let good_report = verify::xades::verify_xml_detached(
        &signed,
        content,
        &root,
        Default::default(),
    )
    .expect("verify_xml_detached");
    println!("{}", good_report.pretty());
    assert!(
        good_report.ok,
        "XAdES detached round-trip should verify: {good_report:?}"
    );
}

// ==========================================================
// Phase 11b — XAdES-LTA ArchiveTimeStamp round-trip
// ==========================================================

#[test]
#[ignore]
fn verify_round_trip_xades_lta() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let xml_in = std::fs::read(fixtures_dir().join("small.xml")).unwrap();

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };

    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let archive_tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .with_revocation_data(rev)
        .with_archive_timestamp(archive_tsa_fn)
        .build_enveloped(&signer)
        .expect("build XAdES-LTA");

    // The element should exist in the output.
    let s = std::str::from_utf8(&signed).unwrap();
    assert!(
        s.contains("<xades:ArchiveTimeStamp"),
        "expected ArchiveTimeStamp in output"
    );

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::xades::verify_xml(&signed, &root, Default::default())
        .expect("verify_xml");
    println!("{}", report.pretty());
    assert!(report.ok, "XAdES-LTA round-trip should verify: {report:?}");
    let at = report
        .archive_timestamp
        .as_ref()
        .expect("archive timestamp verdict populated");
    assert!(at.ok, "ArchiveTimeStamp should validate: {at:?}");
    assert!(at.gen_time.is_some());
}

// ==========================================================
// Phase 11a — PAdES-LTA /DocTimeStamp round-trip
// ==========================================================

#[test]
#[ignore]
fn verify_round_trip_pades_lta() {
    use firma_cr_core::pades::add_doc_timestamp;
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let pdf_in = make_test_pdf();

    let ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let rev = RevocationData {
        ocsp_responses: vec![ocsp],
        crls: Vec::new(),
    };

    // 1. Sign as PAdES-LT first.
    let signed_lt = pades::sign_pdf(
        &pdf_in,
        &leaf_crt,
        &chain.iter().collect::<Vec<_>>(),
        HashAlgo::Sha256,
        Some("round-trip LTA"),
        None,
        None,
        SystemTime::now(),
        &signer,
        None,
        None,
        false,
        Some(&rev),
    )
    .expect("sign PAdES-LT");

    // 2. Append a DocTimeStamp using the in-process mock TSA.
    let tsa_fn = build_tsa_callback(
        HashAlgo::Sha256,
        &ca.join("test-leaf.key"),
        &ca.join("test-leaf.crt"),
        &ca.join("test-chain.pem"),
    );
    let signed_lta = add_doc_timestamp(&signed_lt, HashAlgo::Sha256, tsa_fn)
        .expect("add DocTimeStamp");

    // Confirm the DocTimeStamp dict actually landed.
    let pos = signed_lta
        .windows(b"/Type/DocTimeStamp".len())
        .position(|w| w == b"/Type/DocTimeStamp");
    assert!(pos.is_some(), "expected /Type/DocTimeStamp in output");

    // 3. Verify — should pass with archive timestamp populated.
    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::pades::verify_pdf(&signed_lta, &root, Default::default())
        .expect("verify_pdf");
    println!("{}", report.pretty());
    assert!(report.ok, "PAdES-LTA round-trip should verify: {report:?}");
    let at = report
        .archive_timestamp
        .as_ref()
        .expect("archive timestamp verdict should be populated");
    assert!(at.ok, "DocTimeStamp should validate: {at:?}");
    assert!(at.gen_time.is_some(), "genTime should be reported");
}

// ==========================================================
// Phase 11c — OCSP signer + signature verification
// ==========================================================

/// Re-encode a clean OcspResponse DER with one bit of the embedded
/// BasicOcspResponse signature flipped. The result still parses
/// cleanly but the RSA signature no longer matches the responder
/// cert's public key.
fn tamper_ocsp_signature(ocsp_der: &[u8]) -> Vec<u8> {
    use der::asn1::{BitString, OctetString};
    use der::{Decode, Encode};
    use x509_ocsp::{BasicOcspResponse, OcspResponse};

    let mut outer = OcspResponse::from_der(ocsp_der).expect("parse OcspResponse");
    let mut bytes = outer
        .response_bytes
        .clone()
        .expect("OcspResponse missing responseBytes");
    let mut basic =
        BasicOcspResponse::from_der(bytes.response.as_bytes()).expect("decode BasicOcsp");
    let mut sig = basic.signature.raw_bytes().to_vec();
    sig[10] ^= 0x01;
    basic.signature = BitString::from_bytes(&sig).expect("encode tampered signature");
    bytes.response = OctetString::new(basic.to_der().expect("re-encode BasicOcsp"))
        .expect("rewrap response OCTET STRING");
    outer.response_bytes = Some(bytes);
    outer.to_der().expect("re-encode OcspResponse")
}

#[test]
#[ignore]
fn verify_cades_lt_rejects_tampered_ocsp_signature() {
    use firma_cr_core::revocation::RevocationData;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let intermediate_crt =
        SignerCert::from_file(&ca.join("test-intermediate.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    let good_ocsp = mock_ocsp::issue_good(
        &leaf_crt,
        &intermediate_crt,
        &intermediate_crt,
        &ca.join("test-intermediate.key"),
    );
    let bad_ocsp = tamper_ocsp_signature(&good_ocsp);
    let rev = RevocationData {
        ocsp_responses: vec![bad_ocsp],
        crls: Vec::new(),
    };

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_revocation_data(rev)
        .build(&signer)
        .expect("build CAdES-LT with tampered OCSP");

    let root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();
    let report = verify::cms::verify_detached(&cms_der, &data, &root, Default::default())
        .expect("verify_detached");
    println!("{}", report.pretty());
    assert!(
        !report.ok,
        "tampered OCSP signature must FAIL verification: {report:?}"
    );
    let rv = report
        .revocation
        .as_ref()
        .expect("revocation verdict populated");
    assert!(
        rv.warnings
            .iter()
            .any(|w| w.contains("OCSP signature verification failed")),
        "expected 'OCSP signature verification failed' warning, got: {:?}",
        rv.warnings
    );
}

// ==========================================================
// Phase 11d — cert_internal coverage
//
// Generate a foreign two-tier CA in-memory and use its leaf as the
// TSA that issues the -T timestamp token. The signer cert remains
// the existing test-leaf whose chain ends at test-root, so the
// outer-signer chain succeeds either way. The TSA cert chains only
// to the FOREIGN root, so strict verification must fail; with
// cert_internal: true it must pass and surface a warning.
// ==========================================================

mod foreign_tsa {
    use std::time::Duration;

    use der::pem::LineEnding;
    use der::{DecodePem, Encode};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::RsaPrivateKey;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;
    use x509_cert::Certificate;

    use firma_cr_core::cert::SignerCert;

    pub struct ForeignTsa {
        pub root: SignerCert,
        pub leaf: SignerCert,
        /// PKCS#8 PEM of the leaf's private key, written to a tempfile.
        pub leaf_key_pem: tempfile::NamedTempFile,
    }

    /// Build a self-signed root + a leaf cert signed by it, both
    /// RSA-2048 / SHA-256. ~2 s of RSA key generation per test run.
    pub fn build() -> ForeignTsa {
        let mut rng = rand::thread_rng();
        let root_key = RsaPrivateKey::new(&mut rng, 2048).expect("foreign root key");
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).expect("foreign leaf key");

        let root_cert = build_root(&root_key);
        let leaf_cert = build_leaf(&leaf_key, &root_cert, &root_key);

        let leaf_key_pem = write_pkcs8_pem(&leaf_key);
        let root_signer = signercert_from(root_cert);
        let leaf_signer = signercert_from(leaf_cert);
        ForeignTsa {
            root: root_signer,
            leaf: leaf_signer,
            leaf_key_pem,
        }
    }

    fn build_root(key: &RsaPrivateKey) -> Certificate {
        use std::str::FromStr;
        let subject = Name::from_str(
            "CN=FOREIGN Test Root CA,O=phase11d-foreign,C=ZZ",
        )
        .expect("root name");
        let spki = SubjectPublicKeyInfoOwned::try_from(
            rsa::pkcs8::EncodePublicKey::to_public_key_der(&key.to_public_key())
                .unwrap()
                .as_bytes(),
        )
        .expect("root spki");
        let signer = SigningKey::<Sha256>::new(key.clone());
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::new(365 * 24 * 3600, 0)).unwrap(),
            subject,
            spki,
            &signer,
        )
        .expect("root CertificateBuilder");
        builder.build().expect("root cert build")
    }

    fn build_leaf(
        leaf_key: &RsaPrivateKey,
        root_cert: &Certificate,
        root_key: &RsaPrivateKey,
    ) -> Certificate {
        use std::str::FromStr;
        let subject = Name::from_str(
            "CN=FOREIGN Test TSA,O=phase11d-foreign,C=ZZ",
        )
        .expect("leaf name");
        let spki = SubjectPublicKeyInfoOwned::try_from(
            rsa::pkcs8::EncodePublicKey::to_public_key_der(&leaf_key.to_public_key())
                .unwrap()
                .as_bytes(),
        )
        .expect("leaf spki");
        let issuer_signer = SigningKey::<Sha256>::new(root_key.clone());
        let profile = Profile::Leaf {
            issuer: root_cert.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        };
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(2u32),
            Validity::from_now(Duration::new(180 * 24 * 3600, 0)).unwrap(),
            subject,
            spki,
            &issuer_signer,
        )
        .expect("leaf CertificateBuilder");
        builder.build().expect("leaf cert build")
    }

    fn write_pkcs8_pem(key: &RsaPrivateKey) -> tempfile::NamedTempFile {
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode leaf key as PKCS#8 PEM");
        let tmp = tempfile::Builder::new()
            .prefix("foreign-tsa-key-")
            .suffix(".pem")
            .tempfile()
            .expect("create tempfile");
        std::fs::write(tmp.path(), pem.as_bytes()).expect("write key tempfile");
        tmp
    }

    fn signercert_from(cert: Certificate) -> SignerCert {
        // Round-trip via DER+PEM so we end up with the exact same
        // shape SignerCert::from_file produces. (SignerCert's struct
        // fields are public, so we could construct directly, but
        // going via PEM keeps the parser path identical.)
        let der = cert.to_der().expect("cert to_der");
        let pem = der::pem::encode_string("CERTIFICATE", LineEnding::LF, &der)
            .expect("cert to PEM");
        let parsed = Certificate::from_pem(pem.as_bytes()).expect("from_pem");
        SignerCert { der, parsed }
    }

}

#[test]
#[ignore]
fn verify_cades_t_strict_rejects_foreign_tsa() {
    use firma_cr_core::verify::VerifyOptions;
    let ca = ca_dir();
    let leaf_crt = SignerCert::from_file(&ca.join("test-leaf.crt")).unwrap();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).unwrap();
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem")).unwrap();
    let data = std::fs::read(fixtures_dir().join("small.dat")).unwrap();

    // Generate a foreign TSA whose root is NOT in our trust bundle.
    let foreign = foreign_tsa::build();
    let foreign_tsa_signer = SoftwareSigner::from_file(foreign.leaf_key_pem.path())
        .expect("load foreign TSA key");
    let foreign_leaf_clone = SignerCert::from_der(foreign.leaf.der.clone()).unwrap();
    let foreign_root_clone = SignerCert::from_der(foreign.root.der.clone()).unwrap();
    let tsa_fn = move |payload: &[u8]| {
        let chain_refs: Vec<&SignerCert> = vec![&foreign_root_clone];
        Ok(test_tsa::issue(
            payload,
            HashAlgo::Sha256,
            &foreign_tsa_signer,
            &foreign_leaf_clone,
            &chain_refs,
        ))
    };

    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &leaf_crt)
        .include_chain(chain.iter().collect())
        .with_timestamp(tsa_fn)
        .build(&signer)
        .expect("build CAdES-T with foreign TSA");

    // Trust root = signer's real test-root. TSA chain will not anchor.
    let trust_root = SignerCert::from_file(&ca.join("test-root.crt")).unwrap();

    // ---- strict mode ----
    let strict_report = verify::cms::verify_detached(
        &cms_der,
        &data,
        &trust_root,
        VerifyOptions::default(),
    )
    .expect("verify strict");
    println!("STRICT:\n{}", strict_report.pretty());
    assert!(
        !strict_report.ok,
        "strict mode must FAIL with foreign-anchored TSA"
    );
    let tv = strict_report
        .timestamp
        .as_ref()
        .expect("timestamp verdict present");
    assert!(
        tv.warnings.iter().any(|w| w.contains("TSA chain build failed")),
        "expected 'TSA chain build failed' warning, got: {:?}",
        tv.warnings
    );

    // ---- lenient mode ----
    let lenient_report = verify::cms::verify_detached(
        &cms_der,
        &data,
        &trust_root,
        VerifyOptions {
            cert_internal: true,
            ..Default::default()
        },
    )
    .expect("verify lenient");
    println!("LENIENT:\n{}", lenient_report.pretty());
    assert!(
        lenient_report.ok,
        "cert_internal: true should PASS with warning: {lenient_report:?}"
    );
    let tv = lenient_report
        .timestamp
        .as_ref()
        .expect("timestamp verdict present in lenient");
    assert!(
        tv.ok,
        "lenient timestamp verdict should be ok (warning-only): {tv:?}"
    );
    assert!(
        tv.warnings.iter().any(|w| w.contains("cert_internal")),
        "expected a cert_internal warning, got: {:?}",
        tv.warnings
    );
}
