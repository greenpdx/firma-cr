// SPDX-License-Identifier: GPL-3.0-or-later
//! CAdES integration test — drive CadesBuilder end-to-end with a
//! software signer + the test CA, verify the produced .p7s with
//! `openssl cms`.
//!
//! Run with:
//!     cargo test --features test-signer -- --ignored
//!
//! Requires `tests/test_ca/out/` to be populated; run
//! `tests/test_ca/gen-test-ca.sh` first.

#![cfg(feature = "test-signer")]

use std::path::PathBuf;
use std::process::Command;

use firma_cr_core::cades::CadesBuilder;
use firma_cr_core::cert::SignerCert;
use firma_cr_core::digest::HashAlgo;
use firma_cr_core::signer::SoftwareSigner;

fn ca_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_ca/out")
}
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore]
fn cades_round_trip_verifies_with_openssl_cms() {
    if !openssl_available() {
        eprintln!("openssl not installed — skipping");
        return;
    }
    let ca = ca_dir();
    let fx = fixtures_dir();
    let leaf_crt = ca.join("test-leaf.crt");
    let leaf_key = ca.join("test-leaf.key");
    let chain_pem = ca.join("test-chain.pem");
    let root_crt = ca.join("test-root.crt");
    let payload = fx.join("small.dat");

    assert!(
        leaf_crt.exists(),
        "run tests/test_ca/gen-test-ca.sh first",
    );

    // Load leaf cert + the chain bundle.
    let cert = SignerCert::from_file(&leaf_crt).expect("leaf cert");
    let chain = SignerCert::load_chain_from_pem(&chain_pem).expect("chain bundle");
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();

    // Software signer over the leaf private key.
    let signer = SoftwareSigner::from_file(&leaf_key).expect("leaf key");

    // Read payload, build CAdES-B-B detached.
    let data = std::fs::read(&payload).expect("read payload");
    let cms_der = CadesBuilder::new(&data, HashAlgo::Sha256, &cert)
        .include_chain(chain_refs)
        .build(&signer)
        .expect("build cms");

    let cms_out = std::env::temp_dir().join("firma-cr-core-cades-test.p7s");
    std::fs::write(&cms_out, &cms_der).unwrap();

    // openssl cms -verify treats the signed data as detached when
    // -content is supplied. -CAfile gives the trust anchor; the
    // intermediate must come from the signedData itself (we put it
    // there via include_chain).
    // `-binary` is critical: without it openssl normalizes line
    // endings on the -content payload in text mode (CRLF → LF), so
    // the digest it recomputes diverges from what we signed over
    // the raw file bytes.
    let status = Command::new("openssl")
        .args(["cms", "-verify", "-inform", "DER", "-binary"])
        .arg("-in")
        .arg(&cms_out)
        .arg("-content")
        .arg(&payload)
        .arg("-CAfile")
        .arg(&root_crt)
        .arg("-out")
        .arg("/dev/null")
        .status()
        .expect("run openssl");

    assert!(
        status.success(),
        "openssl cms -verify failed for {}",
        cms_out.display(),
    );
}
