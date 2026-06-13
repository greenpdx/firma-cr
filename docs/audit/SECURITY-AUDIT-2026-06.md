# Firma CR — Security Audit, June 2026

| | |
|---|---|
| **Scope** | `firma-cr` repository: `firma-cr-core` (crypto/agent/CLI), `firma-cr-card` (PKCS#11 client), `gui/` (Tauri 2 desktop app) |
| **Out of scope** | `firma-cr-engine` (the native PKCS#11 driver) — **not** code-reviewed this pass; recommended follow-up |
| **Base commit** | `99a9361` (`main`) |
| **Remediation branch** | `security-hardening` |
| **Date** | 2026-06-13 |
| **Auditor** | Shaun Savage `<savages@crmep.com>` |
| **Method** | Manual review across three areas (crypto core, card/FFI, GUI/agent), confirmed against source; targeted regression tests added |

This report is cryptographically signed; see [Certification](#certification).

## Summary

The codebase was found to be well-structured with strong fundamentals: no `unsafe`
in the card/FFI layer (PKCS#11 access is mediated by `cryptoki`), cryptographically
sound signature/timestamp/revocation verification, no committed secrets, a
hardened systemd unit for the agent, and PIN handling that is encrypted in transit
and never logged. The findings below are hardening improvements, not exploited
breaks. All confirmed issues in scope were fixed; a few items were reclassified on
inspection (see notes) or deferred with rationale.

## Findings

Severity reflects impact assuming the documented trust model (localhost agent,
trusted PKCS#11 module).

| # | Area | Finding | Sev | Status |
|---|------|---------|-----|--------|
| 1 | GUI | CSP disabled (`csp: null`) — no backstop against injected-script XSS | Med | **Fixed** — strict CSP (`tauri.conf.json`) |
| 2 | GUI | `sign_pdf` passes webview-supplied paths straight to `fs::read`/`fs::write` | Med | **Fixed** — `validate_pdf_io()` (`gui/src-tauri/src/lib.rs`) |
| 3 | Card | Card PIN copied to an un-zeroized heap `String` in `login()` | High | **Fixed** — `Zeroizing` copy (`pkcs11_client.rs`); `AuthPin`=`secrecy::SecretString` already wipes its own copy |
| 4 | Core | OCSP/CRL/AIA/TSA responses read unbounded → memory-exhaustion DoS | Med | **Fixed** — per-endpoint size caps (`net::read_capped`) |
| 5 | Core | Fetch URLs (from attacker-influenced cert extensions) not scheme-checked → `file://`/non-HTTP SSRF | Med | **Fixed** — `net::require_web_scheme` (OCSP/CRL/AIA: http/https only), `net::require_https` (TSA) |
| 6 | Core | RFC 3161 TSA nonce from a time-seeded PRNG (~30 bits, predictable) | Med | **Fixed** — OS CSPRNG via `getrandom` (`tsa.rs`) |
| 7 | Core | Chain validation did not enforce `basicConstraints`/`keyUsage` → an end-entity cert under the trust root could pass as a CA | High | **Fixed** — RFC 5280 CA enforcement in `verify/chain.rs` (cA flag, pathLen, keyCertSign) |
| 8 | Core | Missing revocation data silently tolerated for all profiles | Med | **Fixed** — opt-in `require_revocation` policy (`VerifyOptions`, `--require-revocation`) for `-LT`/`-LTA` |
| 9 | Agent | `/dyn/login` had no rate limiting → PIN-guess hammering / card-lockout DoS | Med | **Fixed** — per-session failed-login throttle (`agent/http.rs`) |
| 10 | Agent | `cryptoshell_add_file` accepted unbounded uploads / unsanitized names | Med | **Fixed** — 32 MiB upload cap, basename + length sanitization, per-env file count cap |
| 11 | Core | `c14n.rs:252` `unwrap()` flagged as a panic-on-malformed-XML risk | — | **Not a defect** — line is a `#[cfg(test)]` helper; production `excl_c14n` already returns `Result` and all callers use `?` |
| 12 | Agent | `/dyn` is CORS-open with no auth | Med | **By design / documented** — required for BCCR website compatibility; mitigated by loopback binding + interactive PIN + #9/#10. See `SECURITY.md` |
| 13 | Card | PKCS#11 module path can come from `$HOME`/env | Med | **Documented** — OS-file-trust assumption; install to a root path in production (`SECURITY.md`) |
| 14 | Core | SHA-1 used for OCSP `CertID` | Low | **Won't fix** — mandated by RFC 6960; not used for document signatures |

## Remediation details

See the `security-hardening` branch. Code changes are grouped by area; each carries
a focused commit message and inline comments explaining the security rationale.
New/extended tests:

- `net::tests` — scheme allow/deny and oversize-response rejection (#4, #5).
- `verify::chain::tests::ca_constraints_enforced` — end-entity rejected as CA,
  pathLen enforced (#7).
- `integration_verify::verify_cades_require_revocation_hard_fails_without_data` —
  `require_revocation` hard-fails a `-B-B` signature (#8).
- Existing 31 verify round-trip / tamper-rejection integration tests continue to
  pass unchanged.

## Residual risk & assumptions

- **Localhost agent (#12):** a malicious page in the same browser can prompt for a
  signature; the user must interactively enter the PIN per operation.
- **PKCS#11 module trust (#13):** the OS must protect the driver file.
- **Verification scope:** name-constraints and certificate-policy checks are not
  implemented; revocation hard-fail is opt-in.
- **Engine driver:** `firma-cr-engine` was not reviewed.

## Test status at audit time

- `cargo test --workspace` — pass (unit, incl. new `net`/`chain` tests).
- `cargo test -p firma-cr-core --features test-signer -- --ignored` — pass
  (integration, incl. the new `require_revocation` test).
- `cargo build --workspace --features agent` — clean (no warnings).
- `cargo clippy` — touched code clean; pre-existing codebase-wide style lints left
  as-is.

## Certification

The finalized version of this report is signed with the audit certificate:

- Certificate (public): `docs/audit/audit-cert.pem`
- Detached signature: `docs/audit/SECURITY-AUDIT-2026-06.md.p7s`
- Verify: `docs/audit/verify-audit.sh`

— Shaun Savage `<savages@crmep.com>`, 2026-06-13
