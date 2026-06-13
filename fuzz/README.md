# firma-cr fuzz targets

Coverage-guided ([libFuzzer](https://llvm.org/docs/LibFuzzer.html) via
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)) harnesses for the parsers
that consume **fully untrusted input**. Each must always terminate with a clean
error — never panic, overflow, hang, or allocate unboundedly.

| Target  | Exercises | Hardened by |
|---------|-----------|-------------|
| `c14n`  | Exclusive XML C14N (`c14n::excl_c14n`) — also asserts idempotency | L5 |
| `cms`   | Detached CMS / CAdES verifier (`verify::cms::verify_detached`)    | L1/L4, M2c |
| `pades` | PAdES PDF `/ByteRange` + `/Contents` parser (`verify::pades::verify_pdf`) | C1/H1c |

## Run

```sh
cargo install cargo-fuzz          # one-time; needs a nightly toolchain
rustup toolchain install nightly

cargo fuzz list                   # c14n  cms  pades
cargo fuzz run c14n fuzz/seeds/c14n           # fuzz until a crash (Ctrl-C to stop)
cargo fuzz run pades -- -max_total_time=300   # time-boxed
```

Passing `fuzz/seeds/<target>` as an extra corpus dir seeds the run from the
committed starter inputs (the live corpus in `fuzz/corpus/` is local-only and
git-ignored).

A crash is written to `fuzz/artifacts/<target>/`; reproduce with
`cargo fuzz run <target> fuzz/artifacts/<target>/crash-…`.

CI (`.github/workflows/ci.yml`) only **builds** the targets (`cargo fuzz build`)
so they don't bitrot; real campaigns run out-of-band here.

## Corpus

Committed starter inputs live in `fuzz/seeds/<target>/`; the live, fuzzer-grown
corpus in `fuzz/corpus/<target>/` is git-ignored. Drop real samples into
`fuzz/seeds/` to bootstrap coverage — e.g. a genuine signed `.p7s` into
`seeds/cms/`, a signed PDF into `seeds/pades/`. The `cms`/`pades` targets use the
workspace test-CA root (`crates/firma-cr-core/tests/test_ca/`) as a fixed trust
anchor so the verifier reaches its parse/validate logic.
