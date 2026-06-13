# Firma CR

Open-source digital-signature toolkit for the Costa Rica BCCR **Firma Digital**
smart card — a Firmador / SCManager replacement. Produces ETSI **PAdES** (PDF),
**CAdES** (CMS) and **XAdES** (XML) signatures, verifies them, and ships a desktop
GUI plus a GAUDI-compatible local web-signing agent. Works with **any** PKCS#11
module (our `firma-cr-pkcs11` driver, the official Idopte driver, OpenSC, …).

License: GPL-3.0-or-later · Author: Shaun Savage `<savages@crmep.com>`

## What's here

| Path | What |
|---|---|
| `crates/firma-cr-core` | ETSI signer/verifier (PAdES/CAdES/XAdES), RFC 3161 TSA, OCSP/CRL, the local `/dyn` agent, and the **`firma-cr` CLI** |
| `crates/firma-cr-card` | PKCS#11 client (load a driver, read cert, login, sign); auto-uses a driver's `fcr_*` macro FFI when present, else standard PKCS#11 |
| `gui/` | Desktop app (Tauri 2 + TypeScript), embeds the agent |
| `docs/` | [`smartcard-commands.md`](docs/smartcard-commands.md) (full command reference), [`windows-build.md`](docs/windows-build.md), [`audit/`](docs/audit/) |
| `scripts/tester/` | One-shot RPi/Debian setup, build, and stack-check scripts |
| [`SECURITY.md`](SECURITY.md) | Threat model + vulnerability reporting |

The PKCS#11 **driver** (`libfirma_cr_pkcs11.so`) that talks to the card lives in a
separate repo (`firma-cr-engine`); this repo drives whatever PKCS#11 module you
point it at.

## Building

Debug build by default (release only when you ask for it).

### Prerequisites (Debian/Ubuntu/Raspberry Pi OS)

```sh
sudo apt-get install -y build-essential pkg-config libssl-dev \
  pcscd libpcsclite-dev pcsc-tools opensc poppler-utils
# GUI only (Tauri/WebKit + Node):
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
  librsvg2-dev libayatana-appindicator3-dev nodejs npm
sudo systemctl enable --now pcscd
# Rust toolchain (stable) if not present: https://rustup.rs
```

You also need a PKCS#11 driver installed where the tools look for it
(`/usr/lib/firma-cr/libfirma_cr_pkcs11.so` by default; override with `--module`
or `FIRMA_CR_MODULE`). Build/install it from `firma-cr-engine`, or use any
conformant module (e.g. OpenSC).

### CLI + library

```sh
cargo build                       # → target/debug/firma-cr  (CLI + libraries)
```

### Local web-signing agent (`firma-cr-agent`)

The GAUDI-compatible `/dyn` server on `127.0.0.1:41231` is behind the `agent`
feature:

```sh
cargo build --features agent --bin firma-cr-agent
cargo run   --features agent --bin firma-cr-agent     # run it
```

### Desktop GUI

```sh
cd gui
npm install
npm run tauri dev                 # run in dev
npm run tauri build               # bundle a desktop app
```
(The GUI embeds the agent and signs through it.)

### Tests

```sh
cargo test --workspace                                   # unit tests
# Sign/verify round-trips with a software signer (no card) — generate the test
# CA once, then run the gated integration tests:
bash crates/firma-cr-core/tests/test_ca/gen-test-ca.sh
cargo test -p firma-cr-core --features test-signer -- --ignored
```

### One-shot setup (Raspberry Pi / Debian)

`scripts/tester/{10-install-deps,20-build-stack,30-check-stack,40-run-gui}.sh`
install deps, build the driver+agent+CLI, sanity-check the card stack, and launch
the GUI. See [`scripts/tester/README.md`](scripts/tester/README.md).

## The `firma-cr` CLI

`firma-cr <command>`. Global flags (any command): `--module <path>`
(PKCS#11 `.so`, default `/usr/lib/firma-cr/libfirma_cr_pkcs11.so`, env
`FIRMA_CR_MODULE`), `--slot <n>`, `--cert-file <der|pem>`, `--include-chain
<pem-bundle>`.

### Diagnostics (no PIN)

```sh
firma-cr info                     # module + token + signing-cert info
firma-cr list                     # slots with a token present
firma-cr cert --pem -o signer.pem # dump the signing certificate
firma-cr probe -o probe.json      # deep PC/SC PKCS#15 probe (no PKCS#11)
```

### Signing

PIN source (pick one): `--pin-prompt` (recommended), `--pin-env VAR`,
`--pin-file FILE`, or `--pin 1234` (testing only — visible in the process list).
Signing options: `--digest sha256|sha384|sha512`, `--profile B|T|LT|LTA`,
`--tsa-url <url>` (required for T/LT/LTA), `--ocsp-url`/`--crl-url`,
`--ocsp-nonce-optional` (needed for BCCR's OCSP).

```sh
# PAdES (PDF) — plain baseline signature
firma-cr pdf -i contract.pdf -o contract-signed.pdf --pin-prompt

# PAdES with a trusted timestamp (-T), embedding the chain for verifiers
firma-cr --include-chain bccr-chain.pem \
  pdf -i contract.pdf -o contract-signed.pdf --pin-prompt \
  --profile T --tsa-url https://tsa.firmadigital.go.cr/tsa

# CAdES (detached CMS over any file) and XAdES (XML)
firma-cr cms -i file.txt -o file.p7s --pin-prompt
firma-cr xml -i doc.xml  -o doc.signed.xml --pin-prompt --mode enveloped
```
PDF extras: `--reason`, `--location`, `--contact-info`, `--visible-rect
"llx,lly,urx,ury"`, `--visible-page N` (visible stamp).

### Verifying (no card needed)

`<ca_file>` is the **trust anchor** — a single root cert. For BCCR signatures use
the national root **CA RAÍZ NACIONAL COSTA RICA** (download from
firmadigital.go.cr; not bundled here). Intermediates ride inside the signature.

```sh
firma-cr verify pdf contract-signed.pdf ca-raiz-nacional.pem
firma-cr verify cms file.p7s file.txt   ca-raiz-nacional.pem
firma-cr verify xml doc.signed.xml      ca-raiz-nacional.pem
# flags: --json · --require-revocation (hard-fail if no OCSP/CRL; for -LT/-LTA)
#        --cert-internal · --validation-time <ISO8601Z>
```

## More

- Full command reference (PC/SC, OpenSC, the agent's `/dyn` endpoints,
  troubleshooting): [`docs/smartcard-commands.md`](docs/smartcard-commands.md)
- Remote GUI debugging over one SSH-forwarded port: run the agent + `npm run dev`
  on the host (the Vite dev server proxies `/dyn` to the agent), then
  `ssh -L 1420:localhost:1420 host` and open `http://localhost:1420`.
- Security model and reporting: [`SECURITY.md`](SECURITY.md)
