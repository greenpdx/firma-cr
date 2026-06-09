//! The cryptoshell file pipeline (DESIGN.md, reports/29 §5):
//! `cryptoshell_add_file` stores an uploaded document per env;
//! `cryptoshell_build type=SIGN` PAdES-signs each one via the [`TokenSession`]
//! (firma-cr-core). Output naming follows `foo.pdf → foo-firmado.pdf`.

use std::collections::HashMap;

use crate::agent::token::TokenSession;

/// A document uploaded for signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A signed output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Per-env store for `cryptoshell_add_file` uploads.
#[derive(Default)]
pub struct FileStore {
    by_env: HashMap<String, Vec<InputFile>>,
}

impl FileStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// `cryptoshell_add_file`: stage a document under an env.
    pub fn add_file(&mut self, env: &str, name: &str, bytes: Vec<u8>) {
        self.by_env
            .entry(env.to_string())
            .or_default()
            .push(InputFile { name: name.to_string(), bytes });
    }

    /// Files staged for an env (in upload order).
    pub fn files(&self, env: &str) -> &[InputFile] {
        self.by_env.get(env).map(Vec::as_slice).unwrap_or(&[])
    }

    /// `cryptoshell_clean`: drop an env's staged files.
    pub fn clear(&mut self, env: &str) -> bool {
        self.by_env.remove(env).is_some()
    }
}

/// `cryptoshell_build type=SIGN`: PAdES-sign each staged file with the token's
/// key. Returns the signed outputs (or the first error).
pub fn build_sign(
    token: &TokenSession,
    files: &[InputFile],
    reason: Option<&str>,
) -> Result<Vec<SignedFile>, String> {
    files
        .iter()
        .map(|f| {
            let bytes = token.sign_pdf(&f.bytes, reason, None).map_err(|e| e.to_string())?;
            Ok(SignedFile { name: signed_name(&f.name), bytes })
        })
        .collect()
}

/// Output filename convention: `foo.pdf → foo-firmado.pdf`.
pub fn signed_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}-firmado.{ext}"),
        None => format!("{name}-firmado"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_name_inserts_firmado() {
        assert_eq!(signed_name("doc.pdf"), "doc-firmado.pdf");
        assert_eq!(signed_name("a.b.pdf"), "a.b-firmado.pdf");
        assert_eq!(signed_name("noext"), "noext-firmado");
    }

    #[test]
    fn file_store_stages_per_env() {
        let mut s = FileStore::new();
        s.add_file("E1", "a.pdf", vec![1, 2, 3]);
        s.add_file("E1", "b.pdf", vec![4]);
        s.add_file("E2", "c.pdf", vec![5]);
        assert_eq!(s.files("E1").len(), 2);
        assert_eq!(s.files("E1")[0].name, "a.pdf");
        assert_eq!(s.files("E2").len(), 1);
        assert!(s.files("nope").is_empty());
    }

    #[test]
    fn file_store_clear() {
        let mut s = FileStore::new();
        s.add_file("E", "a.pdf", vec![1]);
        assert!(s.clear("E"));
        assert!(s.files("E").is_empty());
        assert!(!s.clear("E"));
    }

    // Integration: needs the card-sim running + crfirma. crfirma's PKCS#11
    // module is a process-global singleton (one C_Initialize per process), so
    // each card integration test must run in its OWN cargo invocation — they
    // can't share a process (token + sign together trips ALREADY_INITIALIZED).
    // Run with the sim up:
    //   cargo test -p firma-cr-agent build_sign_produces -- --ignored
    //
    // Verification uses firma-cr-core's own verifier (all-Rust). NOTE: poppler
    // /pdfsig can't parse firma-cr-core's lopdf-built PDFs ("no trailer") — a
    // signing-backend output-compat question, not the agent's /dyn concern.
    /// A minimal valid PDF (same approach as firma-cr-core's PAdES test).
    fn make_test_pdf() -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream};

        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier",
        });
        let resources_id = doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 24.into()]),
                Operation::new("Td", vec![100.into(), 600.into()]),
                Operation::new("Tj", vec![Object::string_literal("firma-cr-agent test")]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "Contents" => content_id, "Resources" => resources_id,
        });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        }));
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).expect("encode pdf");
        buf
    }

    #[test]
    #[ignore = "needs card-sim + crfirma + pdfsig (run with --ignored)"]
    fn build_sign_produces_valid_pades_against_sim() {
        use crate::agent::token::{default_module_path, TokenSession};

        let pdf = make_test_pdf();
        let pdf_len = pdf.len();

        let mut t = TokenSession::connect(&default_module_path()).expect("connect");
        t.login("1234").expect("login");

        let mut store = FileStore::new();
        store.add_file("E", "small.pdf", pdf);
        let signed =
            build_sign(&t, store.files("E"), Some("Prueba firma-cr-agent")).expect("sign");

        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].name, "small-firmado.pdf");

        // Structural: a PAdES signature dict was appended (upstream's bar).
        let bytes = &signed[0].bytes;
        assert!(bytes.len() > pdf_len, "signed PDF must grow");
        assert!(bytes.windows(9).any(|w| w == b"/Type/Sig"), "/Type/Sig present");
        assert!(bytes.windows(10).any(|w| w == b"/ByteRange"), "/ByteRange present");
        assert!(bytes.windows(9).any(|w| w == b"/Contents"), "/Contents present");

        // Cryptographic: the card's signature verifies against its certificate
        // (the sim's firma cert is self-signed, so it is its own trust root).
        let report = crate::verify::pades::verify_pdf(
            bytes,
            t.signer_cert().expect("signer cert"),
            crate::verify::VerifyOptions::default(),
        )
        .expect("verify_pdf");
        assert!(report.ok, "signature did not verify:\n{}", report.pretty());

        std::fs::write(std::env::temp_dir().join("agent-signed.pdf"), bytes).ok();
    }
}
