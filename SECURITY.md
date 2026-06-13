# Security Policy

Firma CR signs legally-binding documents with a Costa Rican BCCR *Firma Digital*
smart card. This document states the trust model, what the software does and does
not defend against, and how to report a vulnerability.

## Reporting a vulnerability

Email **savages@crmep.com** with details and, if possible, a reproduction. Please
do not open public issues for security problems until a fix is available.

## Architecture & trust model

Firma CR has three parts:

- **firma-cr-core** — the ETSI signer/verifier (PAdES/CAdES/XAdES), the RFC 3161
  TSA client, OCSP/CRL revocation, and the local `/dyn` web-signing agent.
- **firma-cr-card** — the PKCS#11 client that talks to the card via a driver.
- **gui/** — the Tauri 2 desktop app, which embeds the `/dyn` agent.

### The `/dyn` localhost agent (important)

To replace GAUDI/SCManager, the agent listens on `http://127.0.0.1:41231` with
**open CORS** so BCCR signing websites in the user's browser can drive it. This is
**by design** and is the accepted boundary:

- It binds to **loopback only** — it is not reachable from the network.
- Every signing operation requires the user to **interactively enter the card PIN**;
  the PIN is **RSA-encrypted in the browser** (per-session key) before it is sent,
  is decrypted only transiently in the agent, is never logged, and is wiped from
  memory after use (`zeroize`).
- **What this does not defend against:** a *malicious web page open in the same
  browser* can call the agent and ask the user to sign. The protection is that the
  user must consciously enter their PIN for each operation and (in the GUI) sees
  the document being signed. Do not enter your PIN for a signing prompt you did
  not initiate.

Defense-in-depth added on this surface (without breaking website compatibility):
failed-login **rate limiting** per session, **size caps** on uploads, and
**length caps** on file names. CORS is intentionally **not** locked to an origin
allowlist, as that would break legitimate BCCR sites.

### PKCS#11 module trust

The card is reached through a PKCS#11 module (`libfirma_cr_pkcs11.so` by default).
The module is loaded from a system path (`/usr/lib/firma-cr/…`) or an explicit
`CRFIRMA_MODULE` override; a `$HOME` fallback exists for development only. **The
OS is trusted to protect the module file** — anyone who can replace that `.so` (or
set `CRFIRMA_MODULE`/`LD_*` in your environment) can intercept signing. Install
the module to a root-owned path in production.

### Network fetches (OCSP / CRL / AIA / TSA)

Revocation and timestamp endpoints are fetched over HTTP(S). URLs taken from
certificate extensions (OCSP/CRL/AIA) are restricted to `http`/`https` schemes
(no `file://`/`ftp://`/… — blocks local-file and non-HTTP SSRF); cleartext `http`
is allowed there because those payloads are themselves signed. The TSA endpoint
(operator-configured) is restricted to `https`. All responses are **size-capped**
to bound memory use.

## Verification policy

`firma-cr verify` checks signatures, certificate chains (including
`basicConstraints`/`keyUsage` CA enforcement, RFC 5280), embedded timestamps, and
embedded revocation data. By default a `-B-B`/`-T` signature with no embedded
revocation data passes; pass `--require-revocation` to make missing revocation a
hard failure when verifying long-term `-LT`/`-LTA` signatures.

## Audit

A security review of `firma-cr` (core/card/gui) was performed in June 2026 — see
[`docs/audit/SECURITY-AUDIT-2026-06.md`](docs/audit/SECURITY-AUDIT-2026-06.md).
That report is cryptographically signed; verify it with
`docs/audit/verify-audit.sh`. The `firma-cr-engine` PKCS#11 driver was **not**
code-reviewed in that pass and is a recommended follow-up.

## Known follow-ups (not addressed in the June 2026 pass)

- Dependency version pinning / committing `Cargo.lock` policy and a signed
  auto-update mechanism for the GUI.
- Name-constraints and certificate-policy validation in chain building.
- Code review of the `firma-cr-engine` PKCS#11 driver (FFI, APDU/Secure-Messaging,
  PIN path).
