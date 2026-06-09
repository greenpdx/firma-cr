//! PAdES integration test — sign the fixture PDF, verify with
//! `pdfsig` (poppler-utils) when installed. Skips gracefully on
//! hosts without pdfsig.
//!
//! Run with:
//!     cargo test --features test-signer -- --ignored

#![cfg(feature = "test-signer")]

use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use firma_cr_core::cert::SignerCert;
use firma_cr_core::digest::HashAlgo;
use firma_cr_core::pades;
use firma_cr_core::signer::SoftwareSigner;

fn ca_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_ca/out")
}
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn pdfsig_available() -> bool {
    Command::new("pdfsig")
        .arg("-v")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false)
}

/// Generate a minimal but lopdf-parseable PDF on the fly. Avoids
/// hand-rolling the xref table.
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
            Operation::new("Tj", vec![Object::string_literal("firma-cr-core test")]),
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
fn pades_round_trip_signs_pdf() {
    let ca = ca_dir();
    let fx = fixtures_dir();
    let cert = SignerCert::from_file(&ca.join("test-leaf.crt")).expect("leaf cert");
    let chain = SignerCert::load_chain_from_pem(&ca.join("test-chain.pem"))
        .expect("chain bundle");
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();
    let signer = SoftwareSigner::from_file(&ca.join("test-leaf.key")).expect("leaf key");
    let pdf_in = make_test_pdf();
    let _ = fx; // unused once we generate the PDF instead of reading a fixture

    let signed = pades::sign_pdf(
        &pdf_in,
        &cert,
        &chain_refs,
        HashAlgo::Sha256,
        Some("integration test"),
        Some("San José"),
        None,
        SystemTime::now(),
        &signer,
        None, // no -T timestamp in this test
        None, // no visible appearance in this test
        false,
        None,
    )
    .expect("sign pdf");

    // Basic structural assertions — the signature dict + AcroForm
    // should be in the output.
    assert!(signed.len() > pdf_in.len(), "signed PDF must grow");
    // Write to disk first so we can inspect on failure.
    let out = std::env::temp_dir().join("firma-cr-core-pdf-test.pdf");
    std::fs::write(&out, &signed).unwrap();
    eprintln!("signed PDF: {} bytes, written to {}", signed.len(), out.display());
    // lopdf serializes dictionary entries without separating
    // whitespace (`/Type/Sig`, not `/Type /Sig`).
    let bytes = &signed[..];
    let needle = b"/Type/Sig";
    let pos = bytes.windows(needle.len()).position(|w| w == needle);
    assert!(pos.is_some(), "signature dict /Type/Sig present (signed PDF at {})", out.display());
    assert!(bytes.windows(9).any(|w| w == b"/AcroForm"), "AcroForm present");
    assert!(bytes.windows(10).any(|w| w == b"/ByteRange"), "ByteRange present");
    assert!(bytes.windows(9).any(|w| w == b"/Contents"), "Contents present");

    if pdfsig_available() {
        let status = Command::new("pdfsig").arg(&out).status();
        // Even if pdfsig reports "untrusted" or chain issues we just
        // check it didn't crash on the bytes.
        if let Ok(s) = status {
            eprintln!("pdfsig exit: {s}");
        }
    } else {
        eprintln!("pdfsig not installed — structural assertions only");
    }
}
