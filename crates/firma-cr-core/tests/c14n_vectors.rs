// SPDX-License-Identifier: GPL-3.0-or-later
//! Exclusive-C14N conformance: our pure-Rust `c14n::excl_c14n` must byte-match
//! the **libxml2** reference (`xmllint --exc-c14n`) across a corpus of normative
//! cases — namespace exclusivity, redundant-decl removal, attribute ordering,
//! empty-element expansion, comment removal, text/attr escaping, CDATA folding,
//! default namespaces, and XML-declaration stripping.
//!
//! The golden `*.out.xml` files were produced by libxml2 once and committed, so
//! this test is hermetic (no xmllint at run time). Regenerate after editing an
//! input with: `tests/c14n_vectors/regen.sh`.

use std::fs;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/c14n_vectors")
}

#[test]
fn excl_c14n_matches_libxml2_golden_vectors() {
    let dir = vectors_dir();
    let mut inputs: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("read vectors dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".in.xml"))
        .collect();
    inputs.sort();
    assert!(!inputs.is_empty(), "no c14n vectors found in {dir:?}");

    let mut failures = Vec::new();
    for inp in &inputs {
        let name = inp.file_name().unwrap().to_string_lossy().to_string();
        let golden = inp.with_file_name(name.replace(".in.xml", ".out.xml"));
        let xml = fs::read(inp).expect("read input");
        let want = fs::read(&golden).unwrap_or_else(|_| panic!("missing golden for {name}"));
        match firma_cr_core::c14n::excl_c14n(&xml) {
            Ok(got) if got == want => {}
            Ok(got) => failures.push(format!(
                "{name}: MISMATCH\n    want (libxml2): {:?}\n    got  (ours):    {:?}",
                String::from_utf8_lossy(&want),
                String::from_utf8_lossy(&got)
            )),
            Err(e) => failures.push(format!("{name}: ERROR {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "exc-c14n divergences from the libxml2 reference:\n{}",
        failures.join("\n")
    );
}
