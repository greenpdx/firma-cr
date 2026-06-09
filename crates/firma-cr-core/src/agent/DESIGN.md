# firma-cr-agent — design & test plan

A Pi-native (aarch64) replacement for the official BCCR **GAUDI** web-signing
agent. It re-implements the local **`/dyn/<action>`** HTTP API that BCCR
websites call (reverse-engineered in `firma-cr-analysis/reports/29`), backed by
the clean-room **crfirma** PKCS#11 driver for the card and a PAdES/CMS signer for
the documents — so a Raspberry Pi can do web-based Firma Digital signing with no
x86-64 middleware.

**Spec source:** `firma-cr-analysis/reports/29-gaudi-web-agent-protocol.md`.
**Methodology:** spec-first + test-first (TDD). Each protocol behavior gets a
test before/with its implementation; the tests are the executable contract.

## Decisions (flag if you'd change these)
- **Language:** Rust (matches the driver; aarch64-native).
- **Location:** `firma-cr-pades/src/agent/` — a feature-gated (`--features
  agent`) module + binary of the `firma-cr-pades` crate. (Formerly a standalone
  `digitalfirma/firma-cr-agent/` crate; folded in so the upper layer is one
  crate and `digitalfirma` is drivers-only.)
- **Card access + document signing:** delegate to **`firma-cr-pades`** (the
  sibling clean-room Rust lib at `~/firma-cr-pades`: PAdES/CAdES/XAdES + a
  `CardClient`/`CardKey` over the `cryptoki` PKCS#11 binding to crfirma; builds,
  24 tests pass). The agent is a thin `/dyn` HTTP layer over it — all-Rust,
  aarch64-native, no Python.
- **HTTP:** **`axum` 0.8** (async, tokio) on `127.0.0.1:41231`. Pure modules
  (`dyn_request`, `session`, `pin`) stay sync and are called from the async
  handlers; shared state (the `EnvStore`) goes behind `Arc<Mutex<…>>`.
- **PAdES backend:** `firma-cr-pades::pades::sign_pdf` (above). pyHanko remains
  only as the independent M5 cross-check, not a runtime dependency.

## Architecture (modules)
```
http        — the localhost server + routing  (/dyn/<action>?env=<id>)
dyn_request — parse an incoming /dyn request → { action, env, params }   [pure]
session     — EnvStore: create_env → (envId, RSA pubKeyPem); per-env state [pure+crypto]
pin         — RSA-decrypt the client-encrypted PIN with the env key        [crypto]
token       — token verbs (connect/login/get_certs) → firma-cr-pades CardClient/CardKey
sign        — cryptoshell pipeline (add_file → build type=SIGN) → firma-cr-pades pades::sign_pdf
api         — JSON request/response contracts per endpoint
```

## Protocol contract (from report 29)
- Transport: `GET/POST http://127.0.0.1:41231/dyn/<action>?env=<envId>[&k=v…]`,
  params percent-encoded, JSON bodies/responses, CORS, plain HTTP.
- Handshake: `create_env` → `{ envId, pubKeyPem(RSA) }`. Every later call carries
  `?env=<envId>`.
- PIN: client sends it **RSA-encrypted** with `pubKeyPem` as `&e=<b64>`; the
  agent decrypts with the env private key. (RSA mode — OAEP-SHA256 vs PKCS#1v1.5
  — is an open item; the `pin` module is written mode-agnostic with the chosen
  default behind a constant, and a round-trip test pins it.)
- Token verbs: `connect`, `begin_session`, `activate_certificates`, `login`,
  `get_certstore_certificates` (→ cert/key handles), `end_session`/`disconnect`.
- Signing: `cryptoshell_add_file` → `cryptoshell_build?type=SIGN&sign_cert=<h>&sign_key=<h>&files=<json>`
  → PAdES/CMS (+RFC3161) → `cryptoshell_SignedFileInfo`/download.

## Test plan (in build order)
1. **`dyn_request`** (pure) — parse action/env/params, percent-decoding,
   missing-env, malformed input. *(this commit)*
2. **`session`/`pin`** — `create_env` yields a valid RSA pubkey PEM + a distinct
   envId; an encrypted PIN round-trips (encrypt with the published pubkey →
   decrypt → original); unknown env rejected.
3. **`api`** — JSON request/response shapes per endpoint serialize/parse to the
   report-29 contract.
4. **`token`** (integration) — against crfirma + the card simulator: connect →
   login → list certs returns handles.
5. **`sign`** (integration) — `build type=SIGN` over a sample PDF yields a file
   `pdfsig` validates (reuses the M5 path).
6. **`http`/e2e** — drive the real `/dyn/` sequence over HTTP against the sim.

Tests 1–3 need no card; 4–6 run against `card-sim` (no hardware).

## Status
- [x] DESIGN
- [x] dyn_request (+ tests)
- [x] session/pin
- [x] api
- [x] token (crfirma) — connect/login/get_certs/sign vs the sim (integration
      test passes after the firma-cr-pades single-RW-session fix)

- [x] sign (PAdES) — cryptoshell_build SIGN -> firma-cr-pades::pades; signature
      verifies vs the sim (firma-cr-pades verifier + structural)
- [x] http/e2e (axum) — full /dyn flow over HTTP vs the sim; signature verifies
