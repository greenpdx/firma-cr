# Firma CR — smart-card command reference

A command-by-command reference for working with the BCCR *Firma Digital* card and
the Firma CR tools. Layers go from the lowest (reader/PC-SC) up to Firma CR's own
CLI and agent. For first-time RPi/Debian setup see
[`scripts/tester/COMMANDS.md`](../scripts/tester/COMMANDS.md); this file is the
"what command does what" reference.

Conventions: `$` = run as your user; `#` = needs root/sudo. The PKCS#11 driver
default path is `/usr/lib/firma-cr/libfirma_cr_pkcs11.so` (call it `$MOD`).

```sh
MOD=/usr/lib/firma-cr/libfirma_cr_pkcs11.so
```

---

## 0. Packages that provide these tools (Debian/Ubuntu)

```sh
# PC/SC daemon + reader tooling
sudo apt-get install -y pcscd pcsc-tools libccid libpcsclite-dev
# generic PKCS#11 / smart-card tools (pkcs11-tool, opensc-tool, pkcs15-tool)
sudo apt-get install -y opensc
# independent signature cross-check
sudo apt-get install -y poppler-utils      # pdfsig
```

---

## 1. PC/SC layer — reader & daemon

| Command | What it does |
|---|---|
| `# systemctl enable --now pcscd` | Start/enable the PC/SC daemon (must run before anything sees the card). |
| `$ systemctl is-active pcscd` | Check the daemon is up. |
| `$ pcsc_scan` | Live monitor: shows readers, card insert/removal, and the **ATR**. `Ctrl-C` to stop. The #1 "is the card detected?" check. |
| `$ opensc-tool --list-readers` | List PC/SC readers OpenSC sees. |
| `$ opensc-tool --atr` | Print the inserted card's ATR. |
| `$ opensc-tool --name` | Best-effort card name from the ATR database. |
| `# pcscd -f -d` | Run pcscd in foreground with debug (driver/reader troubleshooting). Stop the service first. |

---

## 2. PKCS#15 / card-content layer (OpenSC, generic)

These talk to the card via OpenSC's own stack — useful to cross-check independently
of our driver.

| Command | What it does |
|---|---|
| `$ pkcs15-tool --dump` | Dump the card's PKCS#15 structure (PINs, keys, certs). |
| `$ pkcs15-tool --list-certificates` | List on-card certificates. |
| `$ pkcs15-tool --read-certificate <id> --out cert.der` | Export a cert by ID. |
| `$ pkcs15-tool --list-pins` | List PIN objects (refs, tries-left semantics). |

---

## 3. PKCS#11 layer against our driver (`pkcs11-tool`)

Point OpenSC's `pkcs11-tool` at **our** module to confirm it loads and exposes the
token the same way Firma CR will use it.

| Command | What it does |
|---|---|
| `$ pkcs11-tool --module $MOD -I` | Module/library info. |
| `$ pkcs11-tool --module $MOD -L` | List slots and tokens. |
| `$ pkcs11-tool --module $MOD -T` | List token mechanisms (confirm `RSA-PKCS`). |
| `$ pkcs11-tool --module $MOD -O` | List objects (certs/keys) — **no PIN**, public objects only. |
| `$ pkcs11-tool --module $MOD -O --login --pin <PIN>` | List objects including private (login). ⚠ a wrong PIN counts against the card's retry counter. |
| `$ pkcs11-tool --module $MOD --read-object --type cert --id <id> -o card.der` | Export the signing cert. |
| `$ pkcs11-tool --module $MOD --test --login --pin <PIN>` | OpenSC's built-in token self-test. |

---

## 4. Firma CR CLI (`firma-cr`) — the main tool

Build it: `cargo build` → `./target/debug/firma-cr` (or `--release`). Below, `firma-cr`
means that binary.

### Global flags (apply to every subcommand)

| Flag | Meaning |
|---|---|
| `--module <path>` | PKCS#11 `.so` to load. Default `/usr/lib/firma-cr/libfirma_cr_pkcs11.so`. Env: `FIRMA_CR_MODULE`. |
| `--slot <n>` | Token slot index. Default: first slot with a token. Env: `FIRMA_CR_SLOT`. |
| `--cert-file <path>` | Use this cert (DER/PEM) instead of the on-card cert. |
| `--include-chain <path>` | PEM bundle (intermediates [+root]) to embed alongside the leaf in the signature. |

### Diagnostics (no PIN)

| Command | What it does |
|---|---|
| `firma-cr info` | Module + library + token + signing-cert info. The first "is the card readable?" probe. |
| `firma-cr list` | List PKCS#11 slots that have a token present. |
| `firma-cr cert` | Dump the signing cert as DER to stdout. |
| `firma-cr cert --pem` | …as PEM. |
| `firma-cr cert --pem -o signer.pem` | …to a file. |
| `firma-cr probe -o probe.json` | Deep **PC/SC-direct** PKCS#15 probe (no PKCS#11): walks the card layout, writes JSON (`-o -` for stdout). |
| `firma-cr probe -o probe.json --with-pin <PIN>` | One authenticated re-probe. ⚠ **single** VERIFY attempt — aborts on wrong PIN, does not retry. Optional `--pin-ref <byte>` / `--pin-pad <byte|0xNN>`. |

### Signing

PIN source (pick one) is shared by all signing subcommands:

| Flag | Meaning |
|---|---|
| `--pin-prompt` | Prompt interactively (**recommended**). |
| `--pin-env <VAR>` | Read PIN from an environment variable. |
| `--pin-file <path>` | Read PIN from a file (first line, trimmed). |
| `--pin <PIN>` | Inline — **testing only** (visible in `/proc/<pid>/cmdline`). |

Signing options (`SignOpts`, shared):

| Flag | Meaning |
|---|---|
| `--digest <sha256\|sha384\|sha512>` | Hash algorithm. Default `sha256`. |
| `--profile <B\|T\|LT\|LTA>` | Baseline / +timestamp / +revocation / +archive-timestamp. Default `B`. |
| `--tsa-url <url>` | Time-Stamp Authority (required for T/LT/LTA; **https** only). |
| `--ocsp-url <url>` / `--crl-url <url>` | Override the responder/CRL URL (default: cert's AIA/CRLDP). |
| `--ocsp-nonce-optional` | Accept OCSP responses without the nonce (needed for BCCR's responder). |

| Command | What it does |
|---|---|
| `firma-cr cms -i file -o file.p7s --pin-prompt` | CAdES-B-B detached CMS over any file. |
| `firma-cr pdf -i in.pdf -o out.pdf --pin-prompt` | PAdES-B-B signature embedded in a PDF. |
| `firma-cr xml -i in.xml -o out.xml --pin-prompt --mode <enveloped\|enveloping\|detached>` | XAdES-B-B XML signature. |

PDF extras: `--reason <s>` `--location <s>` `--contact-info <s>` `--allow-resign`
`--visible-rect "llx,lly,urx,ury"` `--visible-page <n>` (points; default invisible).

Examples:

```sh
# Plain PAdES with interactive PIN
firma-cr pdf -i contract.pdf -o contract-signed.pdf --pin-prompt

# Timestamped, embed the chain for verifiers without BCCR roots installed
firma-cr --include-chain bccr-chain.pem \
  pdf -i contract.pdf -o contract-signed.pdf --pin-prompt \
  --profile T --tsa-url https://tsa.example.cr

# Long-term (LT) against BCCR's nonce-less OCSP
firma-cr pdf -i a.pdf -o a-lt.pdf --pin-prompt --profile LT \
  --tsa-url https://tsa.example.cr --ocsp-nonce-optional
```

### Verifying (no card needed)

`<ca_file>` is the **trust anchor**: a *single* root certificate that `verify`
anchors the chain to (loaded with `SignerCert::from_file` — one cert, PEM or DER).
For BCCR signatures this is the **CA RAÍZ NACIONAL COSTA RICA** root — see
[Trust anchor](#trust-anchor-where-ca_file-comes-from) below. Intermediates (the
policy/issuing CA) are **not** taken from `ca_file`; they come embedded in the
signature (card-produced, or added at signing with `--include-chain`) or via AIA.

| Command | What it does |
|---|---|
| `firma-cr verify cms <file.p7s> <content> <ca_file>` | Verify a detached CMS/CAdES signature. |
| `firma-cr verify pdf <signed.pdf> <ca_file>` | Verify a PAdES PDF. |
| `firma-cr verify xml <signed.xml> <ca_file>` | Verify a XAdES XML. |

Verify flags: `--json` (machine-readable verdict) · `--cert-internal` (accept a TSA
whose chain doesn't anchor to `ca_file`, as a warning) · `--validation-time
<ISO8601Z>` (evaluate as of a past time) · `--require-revocation` (hard-fail if no
embedded OCSP/CRL — use for LT/LTA).

```sh
firma-cr verify pdf contract-signed.pdf ca-raiz-nacional.pem
firma-cr verify pdf a-lt.pdf ca-raiz-nacional.pem --require-revocation --json
pdfsig contract-signed.pdf            # independent cross-check (poppler-utils)
```

#### Trust anchor: where `ca_file` comes from

This repo does **not** ship BCCR roots (only the throwaway test CA under
`crates/firma-cr-core/tests/test_ca/out/`). Obtain the real anchor yourself:

1. **Download the national root** "CA RAÍZ NACIONAL COSTA RICA" (and optionally the
   policy CAs, e.g. "CA POLÍTICA PERSONA FÍSICA") from the *Sistema Nacional de
   Certificación Digital* / BCCR Firma Digital site (**firmadigital.go.cr**). These
   are the same roots the official Firma Digital client installs.
2. **Verify its fingerprint out-of-band** before trusting it:
   ```sh
   openssl x509 -in ca-raiz-nacional.pem -noout -subject -fingerprint -sha256
   ```
3. Pass that single root as `<ca_file>`. To see what chain a signature actually
   carries (to confirm the intermediate is embedded):
   ```sh
   pdfsig -dump signed.pdf                                       # PAdES
   openssl pkcs7 -in out.p7s -inform DER -print_certs -noout     # CMS / .p7s
   ```

---

## 5. The `/dyn` agent (browser bridge / GAUDI replacement)

The agent exposes the GAUDI-compatible HTTP surface BCCR websites call.

| Command | What it does |
|---|---|
| `firma-cr-agent` | Run the agent (build with `--features agent`). Binds `127.0.0.1:41231`. |
| `FIRMA_CR_DYN_ADDR=127.0.0.1:51231 firma-cr-agent` | Run a test instance on another port. |

Endpoints (GET unless noted; `env=<id>` from `create_env`). Mostly browser-driven,
but handy for diagnostics:

| Route | Purpose |
|---|---|
| `/dyn/create_env` | Start a session; returns env id + RSA public key (for PIN encryption). |
| `/dyn/connect` | Open the card session. |
| `/dyn/get_token_info` | Token + cert info (no PIN) — quick agent-side card check. |
| `/dyn/login?env=…&e=<rsa-encrypted-pin>` | Authenticate (PIN encrypted client-side; rate-limited). |
| `/dyn/get_certstore_certificates?env=…` | Signing certs for the session. |
| `/dyn/cryptoshell_add_file?env=…&name=…` (POST body) | Stage a document (size/name-capped). |
| `/dyn/cryptoshell_build?env=…&type=SIGN&…` | Sign the staged document(s). |
| `/dyn/download?env=…&file=…` | Fetch a signed output. |

```sh
# Smoke-test the agent is up and the card is visible (no PIN):
curl -s http://127.0.0.1:41231/dyn/get_token_info | jq .
```

The desktop GUI (`gui/`) embeds this agent; run it with
`cd gui && npm install && npm run tauri dev`.

---

## 6. Tester / build scripts (`scripts/tester/`)

| Script | What it does |
|---|---|
| `10-install-deps.sh` | Install PC/SC, GTK/WebKit, Node, Rust toolchain. |
| `20-build-stack.sh` | Build the driver + agent + CLI and install the `.so`. |
| `30-check-stack.sh` | Stack health check (pcscd, slot/token, cert read; warns on clock skew). |
| `40-run-gui.sh` | `npm install` + launch the Tauri GUI. |

---

## 7. Environment variables & paths

| Name | Used by | Meaning |
|---|---|---|
| `FIRMA_CR_MODULE` | `firma-cr` CLI | PKCS#11 module path (same as `--module`). |
| `FIRMA_CR_SLOT` | `firma-cr` CLI | Token slot index (same as `--slot`). |
| `CRFIRMA_MODULE` | agent / GUI | Module path the embedded agent loads. |
| `FIRMA_CR_DYN_ADDR` | agent | Bind address (default `127.0.0.1:41231`). |
| `/usr/lib/firma-cr/libfirma_cr_pkcs11.so` | all | Default driver install path. |

---

## 8. Troubleshooting quick hits

| Symptom | Try |
|---|---|
| Card not seen | `pcsc_scan` (re-seat card); `systemctl restart pcscd`; check `libccid` installed. |
| `firma-cr list` shows no token | Confirm `$MOD` exists; try `pkcs11-tool --module $MOD -L`. |
| Wrong-PIN lockout risk | Use `--pin-prompt`; avoid repeated `--login` guesses (the card has a small retry counter). |
| Wedged session after an error | Just retry — the agent drops and re-opens the card session on the next request. |
| Verify fails on a valid old signature | Add `--validation-time <signingTimeZ>` (cert expired *now*). |
| OCSP step fails against BCCR | Add `--ocsp-nonce-optional`. |
