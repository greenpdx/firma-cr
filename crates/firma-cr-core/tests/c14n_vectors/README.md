# Exclusive-C14N conformance vectors

Golden corpus that differentially validates our pure-Rust `c14n::excl_c14n`
against the **libxml2** reference. Each case is a pair:

- `NN-name.in.xml`  — input XML
- `NN-name.out.xml` — expected canonical output

The test `tests/c14n_vectors.rs` canonicalizes every `*.in.xml` and asserts the
bytes equal the matching `*.out.xml`. It is hermetic — no `xmllint` at run time.

## Regenerating

`./regen.sh` rebuilds the goldens from the inputs with `xmllint --exc-c14n`.

**Caveat — comments:** `xmllint --exc-c14n` emits the *with-comments* profile
(there is no CLI flag for without-comments). XML-DSig / XAdES — and our impl —
use the *without-comments* profile (`http://www.w3.org/2001/10/xml-exc-c14n#`).
The two differ only on comment nodes, so `regen.sh` fixes up any comment-bearing
vector (currently `05-comment-dropped`) to the without-comments form.

## What this corpus caught

Building it surfaced (and we fixed) two real conformance bugs in `excl_c14n`:

1. attribute whitespace escaped as decimal (`&#9;`) instead of uppercase-hex
   (`&#x9;`), and
2. a child re-declaring the default namespace having that declaration dropped.
