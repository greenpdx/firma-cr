# Firma CR — on-card security test flow

What the CI suite **cannot** prove without the real hardware/network: that the
merged security work (audit PRs #16/#17) behaves correctly end-to-end on a real
BCCR card, against the real BCCR TSA/OCSP, and that our signatures verify in
*third-party* tools. This is that flow. Work top-to-bottom; each step says
**PASS if …**. Capture anything that doesn't match and send it back.

> Unit/integration tests already cover the logic in isolation (the redirect-SSRF
> classifier, the DNS-rebinding Host check, the TSTInfo nonce parser, the ESS
> binding match/mismatch, and the c14n-vs-libxml2 corpus). This flow validates
> the parts those tests can't reach: the card, live network, and interop.

## Prerequisites

- Steps `10`–`40` of [`README.md`](README.md) already done: deps installed,
  stack built, **`30-check-stack.sh` passes**, GUI runs.
- The **real BCCR Firma Digital card** + reader, and **internet**.
- The **BCCR national CA trust anchor** as a PEM, saved as `~/bccr-chain.pem`
  (see "Getting `~/bccr-chain.pem`" below).
- A sample `~/sample.pdf` and `~/sample.xml` to sign.
- A second machine or any web browser for the interop check (Part A5) — e.g. the
  BCCR online validator <https://firmadigital.go.cr> ("Validar") or another
  Firmador.

```sh
cd ~/firma-cr/scripts/tester && source ./env.sh   # gives $CLI_BIN, $AGENT_BIN
TSA="https://tsa.firmadigital.go.cr/tsa"           # BCCR TSA
CA="$HOME/bccr-chain.pem"
```

You will enter the **card PIN** several times. Use `--pin-prompt` (never `--pin`
on a shared box — it shows up in the process list).

### Getting `~/bccr-chain.pem`

This repo does **not** ship BCCR roots (only the throwaway test CA). The verifier
anchors to a trust root and pulls the *intermediate* from the signature itself
(card-produced signatures embed it) or via AIA — so the anchor file only needs
the **national root**; add the policy CA if a verify fails to anchor.

1. **Download** "CA RAÍZ NACIONAL COSTA RICA" (and optionally "CA POLÍTICA
   PERSONA FÍSICA") from the *Sistema Nacional de Certificación Digital* / BCCR
   Firma Digital site — **firmadigital.go.cr**. These are the same roots the
   official Firma Digital client installs. Save the root as `~/bccr-chain.pem`.
2. **Verify the fingerprint out-of-band** before trusting it (compare against
   BCCR's published value — do not skip this):
   ```sh
   openssl x509 -in ~/bccr-chain.pem -noout -subject -issuer -fingerprint -sha256
   ```
3. If a download is `.crt`/DER, convert to PEM:
   ```sh
   openssl x509 -inform DER -in ca-raiz-nacional.crt -out ~/bccr-chain.pem
   ```
   To anchor with root **and** policy CA in one file, concatenate them (PEM order
   doesn't matter — the verifier reorders by issuer/subject):
   ```sh
   cat ca-raiz-nacional.pem ca-politica-persona-fisica.pem > ~/bccr-chain.pem
   ```
4. **Confirm the chain a signature actually carries** (that the intermediate is
   embedded), so a verify failure points at the anchor, not a missing link:
   ```sh
   pdfsig -dump ~/a2-signed.pdf                                  # PAdES
   openssl pkcs7 -in ~/a1.p7s -inform DER -print_certs -noout    # CMS / .p7s
   ```

See also [`../../docs/smartcard-commands.md`](../../docs/smartcard-commands.md) §4.

---

## Part A — Real-card signing + verification

### A1 — CAdES B-B (exercises L1 content-type, L2 ESS binding, L4 keyUsage)
```sh
$CLI_BIN cms -i ~/sample.pdf -o ~/a1.p7s --pin-prompt
$CLI_BIN verify cms --in ~/a1.p7s --content ~/sample.pdf --ca-file "$CA" --json
```
**PASS if** verify reports `ok: true`, a signer subject = your card CN, and there
is **no** `"no ESS signing-certificate attribute"` warning (our signer emits
`signingCertificateV2`, so the binding must be present *and* match).

### A2 — PAdES B-B + third-party cross-check (exercises C1 ByteRange)
```sh
$CLI_BIN pdf -i ~/sample.pdf -o ~/a2-signed.pdf --pin-prompt
$CLI_BIN verify pdf --in ~/a2-signed.pdf --ca-file "$CA"
pdfsig ~/a2-signed.pdf            # independent (poppler) check
```
**PASS if** our verify is `ok: true` **and** `pdfsig` prints `Signature is
Valid` and `Total document signed` (coverage to EOF).

### A3 — PAdES-T over the live BCCR TSA (exercises M3c nonce check)
```sh
$CLI_BIN pdf -i ~/sample.pdf -o ~/a3-t.pdf --profile T --tsa-url "$TSA" --pin-prompt
$CLI_BIN verify pdf --in ~/a3-t.pdf --ca-file "$CA" --json
```
**PASS if** signing **succeeds** (the new code requires the TSA to echo the
nonce we sent — a real BCCR token must pass) and verify shows
`has_timestamp: true` with a timestamp verdict `ok: true`.
**FAIL/REPORT if** signing aborts with `TSA response nonce mismatch` or
`omitted the nonce` — that would mean the BCCR TSA doesn't echo nonces and we
must reconsider the hard-fail.

### A4 — PAdES-LT and -LTA (live OCSP/CRL + archive timestamp)
```sh
$CLI_BIN pdf -i ~/sample.pdf -o ~/a4-lt.pdf  --profile LT  --tsa-url "$TSA" --pin-prompt
$CLI_BIN verify pdf --in ~/a4-lt.pdf  --ca-file "$CA" --require-revocation --json

$CLI_BIN pdf -i ~/sample.pdf -o ~/a4-lta.pdf --profile LTA --tsa-url "$TSA" --pin-prompt
$CLI_BIN verify pdf --in ~/a4-lta.pdf --ca-file "$CA" --require-revocation --json
```
**PASS if** both verify `ok: true`; LT carries a `revocation` verdict (`ok:
true`) and LTA additionally an `archive_timestamp` verdict (`ok: true`).
If BCCR's OCSP rejects our nonce, re-sign adding `--ocsp-nonce-optional`.

### A5 — XAdES interop (THE key check for the PR #17 c14n fixes)
The c14n fix changed our canonical bytes (hex char-refs `&#x9;`; default-ns
override). The point is that our XAdES now verifies in **other** tools.
```sh
$CLI_BIN xml -i ~/sample.xml -o ~/a5-signed.xml --pin-prompt
$CLI_BIN verify xml --in ~/a5-signed.xml --ca-file "$CA"     # our own verifier
```
Then verify `~/a5-signed.xml` **in a third-party validator**: the BCCR online
"Validar" page, or `xmlsec1 --verify`, or DSS.
**PASS if** our verifier says `ok: true` **and** the third-party validator
accepts the signature. **REPORT** the external tool's exact message either way.

---

## Part B — Negative / abuse tests

### B1 — appended-content forgery rejected (C1)
```sh
cp ~/a2-signed.pdf ~/b1-tampered.pdf
printf 'EXTRA UNSIGNED BYTES' >> ~/b1-tampered.pdf
$CLI_BIN verify pdf --in ~/b1-tampered.pdf --ca-file "$CA" --json ; echo "exit=$?"
```
**PASS if** verify reports `ok: false` (non-zero exit) — appended bytes after the
signed `/ByteRange` must break it. (`pdfsig` may still say the *signature* is
valid but "document has been modified" — both are correct.)

### B2 — agent is not reachable via DNS rebinding (M5a)
With the GUI (or the agent) running on `127.0.0.1:41231`:
```sh
# Legit loopback Host — allowed:
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:41231/dyn/create_env
# Spoofed/rebound Host — must be refused BEFORE any handler:
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: attacker.example' \
     http://127.0.0.1:41231/dyn/create_env
```
**PASS if** the first prints `200` and the second prints `403`.

### B3 — TSA nonce mismatch (optional, needs a stub TSA)
Only if you can stand up a TSA that returns a token with a *different* nonce
(or replays an old token). Point `--tsa-url` at it and sign with `--profile T`.
**PASS if** signing aborts with `TSA response nonce mismatch`. Otherwise skip —
the happy path (A3) plus the unit tests cover this.

---

## Part C — Driver path + regressions

### C1 — repeated signs in one session (SW=6985 regression / macro FFI)
Sign **three times without re-inserting the card**, ideally inside one GUI
session (Firmar → Sign → repeat) or three back-to-back CLI runs:
```sh
for n in 1 2 3; do $CLI_BIN pdf -i ~/sample.pdf -o ~/c1-$n.pdf --pin-prompt; done
```
**PASS if** all three succeed (no `SW=6985` / `CKR_DEVICE_ERROR`). This exercises
the atomic `fcr_sign` macro path (cert-read before VERIFY, nothing between VERIFY
and PSO:CDS).

### C2 — PKCS#11 fallback still works
Point the CLI at a *generic* PKCS#11 module that lacks our `fcr_*` symbols (e.g.
OpenSC) to force the cryptoki fallback:
```sh
$CLI_BIN --module /usr/lib/opensc-pkcs11.so info        # adjust path
$CLI_BIN --module /usr/lib/opensc-pkcs11.so pdf -i ~/sample.pdf -o ~/c2.pdf --pin-prompt
```
**PASS if** `info` lists the token and signing succeeds via the fallback path.
(Skip if OpenSC doesn't support this card; note that.)

### C3 — multi-session does not wedge the reader (reset-on-connect refcount)
Open **two** signing consumers at once — e.g. the GUI **and** a BCCR website
using the official agent, or two `firma-cr` runs in parallel shells. Sign from
each.
**PASS if** neither wedges and no signature fails. The reset-on-connect logic is
refcounted on purpose; a regression here shows up as the *second* session
killing the first (`6A82`/timeout). If a reader does stall,
`sudo systemctl restart pcscd` clears it — note it happened.

---

## Part D — GUI end-to-end (TSA field)

In the GUI:
1. **Tarjeta** — card / token / certificate appear (no PIN).
2. **Firmar** — add a PDF, place the box, enable the **sello de tiempo (TSA)**
   field (defaults to `https://tsa.firmadigital.go.cr/tsa`), **Sign**, enter PIN.
3. **Documento** — signed PDF opens inline.
4. Externally: `pdfsig ~/<that file>.pdf` → `Signature is Valid`, and it carries
   a timestamp.

**PASS if** the timestamped signature is produced and verifies.

---

## Part E — Open hardware investigations (data-gathering, not pass/fail)

These audit items are *deferred pending a card* — they need on-card data to
design the fix. Please capture and return the artifacts; do **not** expect a
pass/fail.

### E1 — CSCA / EF.CardSecurity (audit H2d)
Dump the card's PKCS#15 layout and any EF holding the CA/static public key:
```sh
$CLI_BIN probe -o ~/e1-probe.json            # no PIN; deep PC/SC walk
```
Return `e1-probe.json`. We need to know whether the CA public key arrives in a
**signed** EF (EF.CardSecurity / CMS) or an unsigned EF (D004) — it decides
whether CSCA pinning is feasible.

### E2 — APDU trace for a context-preserving MAC probe (audit H1d)
Capture a full sign exchange so we can design a MAC probe that runs *before* the
PIN without losing the `cdynid` context (SELECT MF must NOT be used):
```sh
FIRMA_CR_RECORD=~/e2-apdu.log $CLI_BIN pdf -i ~/sample.pdf -o /tmp/e2.pdf --pin-prompt
```
Return `e2-apdu.log`. **Note:** the recorder redacts the VERIFY (PIN) APDU — the
PIN is *not* written — but glance at the file and confirm before sending.

### E3 — card state after logout (audit M3d)
After a successful sign, observe whether a second operation still believes it is
authenticated (i.e. whether the SM channel / PIN status survives). Note the
behavior (does a fresh `info` or sign need the PIN again?). This informs the
`C_Logout` teardown fix.

---

## Reporting

For each step send: the command, the full output (use `--json` where offered),
and for Part E the captured files. Flag any **A3 nonce-mismatch**, **A5
third-party rejection**, or **B1/B2 not behaving as PASS** as priority — those
would indicate a real regression in the merged work.
