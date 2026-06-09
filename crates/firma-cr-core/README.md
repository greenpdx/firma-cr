# firma-cr-pades

Clean-room CLI for ETSI digital signatures using the
`firma-cr-pkcs11` driver and a Costa Rica BCCR Firma Digital smart
card. Three signature families — PAdES (PDF), CAdES (detached CMS),
XAdES (XML).

A Rust replacement for [Firmador], scope-limited to what a single
session can implement and audit. GUI not included; if you want the
button-driven workflow, keep using Firmador with our driver as the
backing PKCS#11 module — `install.sh` symlinks at the path Firmador
checks.

[Firmador]: https://codeberg.org/firmador

## What's implemented

| Family | -B-B (baseline) | -B-T (timestamp) | -B-LT (long-term) | -B-LTA (archive) |
|--------|------|------|------|------|
| CAdES (.p7s)  | ✓ | scaffold | scaffold | scaffold |
| PAdES (.pdf)  | ✓ | scaffold | scaffold | scaffold |
| XAdES (.xml)  | ✓ enveloped | scaffold | scaffold | scaffold |

"Scaffold" means the protocol clients (`tsa::request_token`,
`revocation::fetch_ocsp`, `revocation::fetch_crl`) and the data
shapes are in place but the injection of resulting tokens into an
existing CMS / PDF / XML signature is not wired into the CLI
`--profile T|LT|LTA` flag. The last-mile wiring needs a working
TSA URL and OCSP responder to validate against; that's tester-driven
work, not single-session work.

## Build

```
cargo build --release
```

Output: `target/release/firma-cr-pades` — single-binary CLI.

## CLI

```
firma-cr-pades info
firma-cr-pades cms --in <FILE> --out <FILE.p7s> --pin-env PIN
firma-cr-pades pdf --in <FILE.pdf> --out <FILE.signed.pdf> --pin-env PIN
firma-cr-pades xml --in <FILE.xml> --out <FILE.signed.xml> --mode enveloped --pin-env PIN
```

Common options on every subcommand:

```
--module <PATH>     PKCS#11 module .so (default: /usr/lib/firma-cr/libfirma_cr_pkcs11.so)
--slot <N>          slot index
--cert-file <PATH>  on-disk cert override (DER or PEM)
--digest <ALG>      sha256 (default) | sha384 | sha512
```

PIN sources (mutually exclusive): `--pin`, `--pin-env`, `--pin-file`,
`--pin-prompt`. Inline `--pin` is visible via `/proc`; prefer one of
the other three.

## Verification

* CMS:
  `openssl cms -verify -in out.p7s -inform DER -content original -CAfile ca-chain.pem`
* PDF:
  `pdfsig out.signed.pdf` (poppler-utils) or any PDF viewer that
  shows signature status.
* XML:
  `xmlsec1 --verify out.signed.xml` (libxmlsec1-bin).

Adobe Reader will accept the signature cryptographically but show
"signer's identity unknown" because MICITT's root isn't in Adobe's
AATL trust store — same caveat that applies to every BCCR-issued
signature, including Firmador's.

## Layout

```
src/
├── lib.rs                — module map + re-exports
├── error.rs              — Error / Result
├── digest.rs             — HashAlgo (sha256/384/512)
├── pkcs11_client.rs      — CardClient (open/login/sign/cert read)
├── cert.rs               — SignerCert (DER + parsed)
├── cades.rs              — Phase 2  CAdES-B-B detached CMS
├── pades.rs              — Phase 3  PAdES-B-B PDF embed
├── c14n.rs               — Exclusive XML C14N 1.0 (hand-rolled, pure Rust)
├── xades.rs              — Phase 4  XAdES-B-B enveloped XML
├── tsa.rs                — Phase 5  RFC 3161 TSP client
├── revocation.rs         — Phase 6/7 OCSP + CRL fetchers
└── bin/firma-cr-pades.rs — clap-based CLI
```

24 unit tests cover: digest dispatch, PKCS#1 DigestInfo shape, DER
length encoder, BER SEQUENCE wrapping, C14N (XML decl stripping,
self-close expansion, attribute sorting, namespace emission, comment
dropping, special-char escaping), base64 round-trip, PDF date format,
XAdES root-close insertion, TimeStampReq construction.

## Author

Shaun Savage <savages@crmep.com>
GPL-3.0-or-later
