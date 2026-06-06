# firma-cr-tauri — Phase 1 GUI

A Tauri v2 desktop front-end for `firma-cr-pades`. **Phase 1 scope:** sign a
PDF with a **PAdES-B-B** signature using the BCCR card, through the native
PKCS#11 module — a button-driven replacement for the Firmador PDF flow that
reuses our Rust signing library directly (no PKCS#11 shim, no WASM).

```
tauri/
├── index.html            Vite entry
├── src/
│   ├── main.ts           UI logic (TypeScript) → tauri invoke()
│   └── styles.css
├── package.json          vite + typescript + @tauri-apps/*
├── tsconfig.json
├── vite.config.ts
└── src-tauri/
    ├── Cargo.toml        depends on ../.. (firma-cr-pades) + tauri 2
    ├── tauri.conf.json
    ├── capabilities/default.json   core + dialog permissions
    └── src/{main.rs,lib.rs}        commands: card_info, sign_pdf
```

## Architecture
- **Frontend** (TS/Vite) does file pick + PIN entry, then `invoke()`s two
  backend commands.
- **Backend** (Rust) calls `firma_cr_pades` directly:
  `CardClient::open → login → read_signing_key/read_certificate →
  CardSigner → pades::sign_pdf`. Commands are **synchronous** so the
  `cryptoki` session never crosses a thread.
- The card is reached via the system PKCS#11 module (default
  `/usr/lib/firma-cr/libfirma_cr_pkcs11.so`, overridable in the UI).

## Build prerequisites
- Rust ≥ 1.85, Node ≥ 18 (+ npm).
- Tauri system deps (Debian/RPi): `libwebkit2gtk-4.1-dev libsoup-3.0-dev
  build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev`.
- `pcscd` + reader + card at runtime, and our PKCS#11 `.so` at the module path.
- Icons: `cargo tauri icon <png>` (referenced by `bundle.icon`).

## Run / build
```bash
cd tauri
npm install
npm run tauri dev      # dev: Vite on :1420 + Tauri window
npm run tauri build    # release bundle
```

## Status / not yet done
- **PAdES-B-B only.** B-T/LT/LTA (timestamp, revocation) stay behind the
  library scaffolds until a TSA endpoint is wired (Phase 2).
- **Not built/validated in CI here** — needs the webkit/node system deps.
  The backend's `firma_cr_pades` API calls were compile-checked against the
  library separately.
- CAdES/XAdES and a visible-signature appearance are future UI work.
- PIN crosses `invoke` as a plain string (in-memory, desktop-local); not
  zeroized — acceptable for a local app, revisit if hardening.
