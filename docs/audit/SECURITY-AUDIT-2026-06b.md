# Firma CR — Security Audit, June 2026 (round 2)

| | |
|---|---|
| **Scope** | `firma-cr` (core/card/gui/agent) **and** the `firma-cr-engine` PKCS#11 driver (`firma-cr-pkcs11`) — incl. the new vendor `fcr_*` macro FFI |
| **Date** | 2026-06-13 |
| **Auditor** | Shaun Savage `<savages@crmep.com>` |
| **Method** | 4 parallel review agents (Opus 4.8): crypto core, card/FFI, agent/GUI, engine driver. Top findings re-verified against source by hand. |
| **Follow-up to** | [`SECURITY-AUDIT-2026-06.md`](SECURITY-AUDIT-2026-06.md) (firma-cr only; the driver was out of scope there) |

This report is cryptographically signed; see [Certification](#certification).

## Summary

This round added the `firma-cr-engine` driver to scope and re-reviewed the open
repo after the macro-FFI / timestamp / dynamic-`/Contents` / cert-fix changes. It
found **one Critical** signature-verification bypass (now fixed) plus a set of
High/Medium hardening items. Fundamentals remain strong: the driver's Secure
Messaging is MAC-then-decrypt with constant-time MAC verification (no
unauthenticated card response accepted), KDF/CMAC match TR-03110 + NIST vectors,
all APDU/TLV parsers are bounds-checked and fuzz-tested, the C-ABI catches panics,
and the PIN is never logged.

Status legend: **Fixed** (this pass) · **Mitigated/Documented** · **Deferred**
(tracked follow-up) · **Needs-card** (correct fix requires on-card validation).

## Findings

| # | Area | Sev | Finding | Status |
|---|------|-----|---------|--------|
| C1 | core | **Critical** | PAdES verifier didn't validate `/ByteRange` coverage → content appended after a signed PDF (or a carved ByteRange) verified as OK | **Fixed** — enforce r1=0, gap==`/Contents`, outermost coverage to EOF; checked arithmetic (`verify/pades.rs`); regression test added |
| H1c | core | High | `/ByteRange` integer-overflow panic on hostile PDF (DoS) | **Fixed** — checked arithmetic (same commit as C1) |
| H2c | core | High | XAdES signature wrapping: first-match element/ID resolution (substring scan, not a namespaced DOM) | **Deferred** — needs a namespace-aware DOM + unique-ID resolution; tracked. Affects XAdES verify only |
| H1a | agent | High | Login rate-limiter keyed per-env → attacker mints envs to bypass and burn the card PIN counter | **Fixed** — global (process/card-scoped) throttle (`agent/http.rs`) |
| H1d | driver | High | CA channel not MAC-probed before the PIN VERIFY | **Mitigated** — the new connect()-reads-cert-before-login order makes the (MAC-checked) cert read run before the PIN, probing the channel vs a passive MITM. Full fix (probe) needs a **context-preserving** SM command — *not* SELECT MF (loses cdynid context → 6A82). **Needs-card** |
| H2d | driver | High | Card's static CA public key read from an **unsigned** EF (D004), no CMS signature check → a rogue card can supply its own key and derive the SM key (decrypt PIN) | **Needs-card** — requires verifying EF.CardSecurity's CMS signature against a pinned CSCA. Documented; inherent to CA-v1 without PACE/TA (attacker must get the user to insert a malicious card and enter their PIN) |
| H3d | driver | High | RFC-5114 MODP DH (chipdoc path): no validation of the card's public value (small-subgroup/range) | **Fixed** — reject `{0,1,p-1}`/out-of-range card pub and Z (`crypto/dh.rs`) |
| M1c | core | Med | SSRF: fetchers checked only the URL scheme, not the target IP | **Fixed** — block loopback/private/link-local/CGNAT/metadata/ULA (v4+v6), opt-out `FIRMA_CR_ALLOW_PRIVATE_FETCH` (`net.rs`) |
| M2c | core | Med | No OCSP/CRL freshness check (`nextUpdate` ignored) → stale-"good" replay | **Deferred** — needs `validation_time` threaded into `validate_signer`; tracked |
| M3c | core | Med | TSA client doesn't verify the response nonce | **Deferred** — well-mitigated (the imprint check already rejects tokens over different data); tracked |
| M1k | card | Med | cryptoki-path PIN copy not actually zeroized (`.into()` reallocated) | **Fixed** — single `Box<str>` handed to `AuthPin` (`pkcs11_client.rs`) |
| M2k | card | Med | Arbitrary unsigned `dlopen` of the module path | **Documented** — install the `.so` to a root-owned path; trust model in [`SECURITY.md`](../../SECURITY.md). (Pre-existing for the cryptoki path too) |
| M3k | card | Med | `fcr_sign` retry could double-sign if `modulus_bits` under-reported | **Mitigated** — `fcr_modulus_bits` (ABI v2) reports the real size; the length-query doesn't sign |
| M2a | agent | Med | No env-ownership check on add_file/build/download/get_certs; `download` fell back to first file | **Fixed** — reject unknown envs; exact-name download (`agent/http.rs`) |
| M3a | agent | Med | `build` ignored `sign_cert`/`files` and signed all staged files | **Fixed** — sign exactly the named files; validate the handle (`agent/http.rs`) |
| M4a | agent | Med | Per-request `tsa` param → SSRF / signature-hash side channel | **Mitigated/Documented** — kept (the GUI TSA field needs it); covered by the M1c internal-IP block + https-only + size cap; residual side channel documented |
| M1d | driver | Med | `FIRMA_CR_RECORD` wrote the **cleartext PIN** to disk on the legacy non-SM path | **Fixed** — redact VERIFY (INS=0x20) data in the recorder (`trace.rs`) |
| M2d | driver | Med | DH ephemeral private key / `Z` not zeroized | **Fixed** — `Zeroizing` + wipe stack copy (`crypto/dh.rs`) |
| M3d | driver | Med | `C_Logout` doesn't drop card-side auth / SM channel | **Deferred** — tracked; reset card on logout when no other session is authenticated |
| L1–L5 | core/driver | Low/Info | content-type signed attr not checked; ESS cert-binding not verified; chain validity-window only checked with `validation_time`; leaf keyUsage/EKU not enforced; hand-rolled c14n; replay/record env-gated in prod | **Deferred** — see agent reports; low risk |

## What was verified sound (coverage)
CMS signedAttrs + messageDigest binding; TSA token verification; embedded OCSP/CRL
signature+EKU+chain; RFC 5280 CA-constraint enforcement; the signing-side
`/Contents` measurement; CSPRNG TSA nonce; `net.rs` size caps; driver SM
MAC-then-decrypt with constant-time MAC (no unauthenticated response accepted);
KDF/CMAC vs TR-03110 + NIST vectors; bounds-checked/fuzz-tested APDU/TLV parsers;
FFI signatures match the driver, two-call buffers correct, panics caught at the
C-ABI; PIN never logged; GUI CSP/capabilities tight; frontend `innerHTML` escaped;
the localhost + interactive-PIN IPC boundary.

## Remediation
Fixes landed on the `audit-fixes` branch of each repo:
- `firma-cr`: C1/H1c, H1a, M1c, M1k, M2a, M3a (PR for review).
- `firma-cr-engine`: H3d, M1d, M2d (PR for review).
Each fix has a focused commit; new tests: PAdES appended-content rejection, SSRF
classifier/blocklist.

## Residual risk & recommended follow-ups
1. **H2d/H1d (driver, Needs-card):** verify EF.CardSecurity's CMS signature
   against a pinned CSCA and add a context-preserving MAC probe before the PIN —
   the only way to fully stop a rogue-card PIN harvest. Validate on hardware.
2. **H2c:** replace the hand-rolled XAdES element/ID resolution with a
   namespace-aware DOM (signature-wrapping resistance).
3. **M2c/M3c:** OCSP/CRL `nextUpdate` freshness and TSA nonce verification.
4. **M3d / M2k:** card-side logout teardown; lock down module-path loading.

## Certification
The finalized report is signed with the audit certificate:
`docs/audit/audit-cert.pem` · signature `SECURITY-AUDIT-2026-06b.md.p7s` · verify
with `docs/audit/verify-audit.sh SECURITY-AUDIT-2026-06b.md`.

— Shaun Savage `<savages@crmep.com>`, 2026-06-13
