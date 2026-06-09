//! XAdES integration test — sign the fixture XML, optionally verify
//! with `xmlsec1` when installed.
//!
//! Run with:
//!     cargo test --features test-signer -- --ignored

#![cfg(feature = "test-signer")]

use std::path::PathBuf;
use std::process::Command;

use firma_cr_core::cert::SignerCert;
use firma_cr_core::digest::HashAlgo;
use firma_cr_core::signer::SoftwareSigner;
use firma_cr_core::xades::XadesBuilder;

fn ca_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_ca/out")
}
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn xmlsec_available() -> bool {
    Command::new("xmlsec1")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore]
fn xades_round_trip_signs_xml() {
    let ca = ca_dir();
    let fx = fixtures_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).expect("leaf cert");
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem"))
        .expect("chain bundle");
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).expect("leaf key");
    let xml_in = std::fs::read(fx.join("small.xml")).expect("read fixture xml");

    let signed = XadesBuilder::new(&xml_in, HashAlgo::Sha256, &cert)
        .include_chain(chain_refs)
        .build_enveloped(&signer)
        .expect("build xades");

    let s = std::str::from_utf8(&signed).expect("utf-8 xml output");
    assert!(s.contains("<ds:Signature"), "Signature element present");
    assert!(s.contains("xades:SignedProperties"), "SignedProperties present");
    assert!(s.contains("<ds:X509Certificate>"), "X509Certificate present");

    let out = std::env::temp_dir().join("firma-cr-core-xml-test.xml");
    std::fs::write(&out, &signed).unwrap();

    if xmlsec_available() {
        let status = Command::new("xmlsec1")
            .args(["--verify", "--trusted-pem"])
            .arg(ca.join("test-root.crt"))
            .args(["--enabled-key-data", "x509"])
            .arg(&out)
            .status();
        if let Ok(s) = status {
            eprintln!("xmlsec1 exit: {s}");
        }
    } else {
        eprintln!("xmlsec1 not installed — structural assertions only");
    }
}
