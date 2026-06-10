# Building Firma CR for Windows

Status: the **driver DLL** and the **agent/CLI EXEs** cross-compile cleanly from
Linux today (verified — see "Verified" below). The **Tauri GUI** must be built on
Windows (or Windows CI). This doc is the build recipe; it does **not** cover
installation/deployment beyond what's needed to test.

---

## 1. Why it's mostly a build job, not a port

The whole stack is portable Rust + PC/SC + a web frontend:

| Component | Crate / repo | Windows story |
|---|---|---|
| **Driver** `firma_cr_pkcs11.dll` | `firma-cr-engine/crates/firma-cr-pkcs11` (closed) | Pure-Rust crypto (AES/CBC/CMAC/3DES/P-521/SHA) + `pcsc` 2.9. The only OS binding is `pcsc`, which links **WinSCard** on Windows vs pcsclite on Linux. No `cfg(unix)`, no `/dev`, no Linux-only code. |
| **Agent** `firma-cr-agent.exe` | `firma-cr/crates/firma-cr-core --features agent` (open) | tokio + axum (cross-platform). Loads the driver at runtime via `cryptoki` (libloading dlopen → `LoadLibrary`). |
| **CLI** `firma-cr.exe` | same crate, `--bin firma-cr` (open) | Same: dlopens the driver DLL. |
| **GUI** `.msi`/`.exe` | `firma-cr/gui` (Tauri, open) | Cross-platform, but the Windows bundle needs **WebView2** + NSIS/WiX — build on Windows. |
| **card-sim** | `firma-cr-analysis/tools/card-sim` | Linux-only (vpcd/vsmartcard). **Not** used on Windows — test with a real reader + card. |

The card protocol (Chip Authentication → AES Secure Messaging → PSO:CDS) is
card-side and OS-independent. Only the **PC/SC transport** differs, and `pcsc`
abstracts it.

---

## 2. One-time toolchain (on the Linux build host)

No Windows machine and no sudo needed — the MSVC target via `cargo-xwin`:

```sh
rustup target add x86_64-pc-windows-msvc
cargo install cargo-xwin
```

On the first `cargo xwin build`, cargo-xwin downloads the Microsoft CRT + Windows
SDK headers/libs (cached under `~/.cache/cargo-xwin`). `pcsc` links
`winscard.lib`, which ships in that SDK — no extra setup.

> Alternative: the GNU target `x86_64-pc-windows-gnu` works too but needs
> `mingw-w64` installed (apt). MSVC (xwin) is preferred — it matches the ABI
> Windows users expect and needs no system packages.

---

## 3. Cross-compile from Linux

### Driver DLL (closed engine repo)

```sh
cd firma-cr-engine
cargo xwin build --release --target x86_64-pc-windows-msvc -p firma-cr-pkcs11
# → target/x86_64-pc-windows-msvc/release/firma_cr_pkcs11.dll
```

The crate is `crate-type = ["cdylib", "rlib"]`, so the cdylib emits
`firma_cr_pkcs11.dll`.

### Agent + CLI EXEs (open repo)

```sh
cd firma-cr
cargo xwin build --release --target x86_64-pc-windows-msvc \
  -p firma-cr-core --features agent \
  --bin firma-cr-agent --bin firma-cr
# → target/x86_64-pc-windows-msvc/release/firma-cr-agent.exe
# → target/x86_64-pc-windows-msvc/release/firma-cr.exe
```

### Verified (cross-built on Linux, rustc 1.96)

- `firma_cr_pkcs11.dll` — **~1.98 MB**, links `winscard.lib`, no portability
  errors.
- `firma-cr-agent.exe`, `firma-cr.exe` — build completed (exit 0).

Cross-building only proves it **compiles and links**. The Chip-Auth + SM + PSO
flow can only be validated on Windows with a real reader + card (§6).

---

## 4. The GUI (Tauri) — build on Windows

Cross-compiling Tauri from Linux is impractical (WebView2 + NSIS/WiX/code-sign).
Build it on a Windows box (or Windows CI runner):

```powershell
# prerequisites: Rust (msvc), Node, WebView2 runtime, NSIS/WiX (Tauri installs prompts)
cd firma-cr\gui
npm ci
npm run tauri build
# → src-tauri\target\release\bundle\{nsis|msi}\Firma CR_*.exe / *.msi
```

The web frontend (`gui/src`) is unchanged across platforms. In the desktop
shell the GUI uses Tauri `invoke`; in browser/web mode it talks to the agent's
`/dyn` on `127.0.0.1` (default port 41231).

---

## 5. Deploying on Windows (for testing — not an installer)

1. Copy `firma_cr_pkcs11.dll` to a fixed path, e.g. `C:\Program Files\Firma CR\`.
2. Run the agent pointed at it (the GUI/web flow and BCCR sites call `/dyn`):
   ```powershell
   set CRFIRMA_MODULE=C:\Program Files\Firma CR\firma_cr_pkcs11.dll
   firma-cr-agent.exe            # serves http://127.0.0.1:41231
   # test-port override: set FIRMA_CR_DYN_ADDR=127.0.0.1:51231
   ```
3. CLI signing without the agent:
   ```powershell
   firma-cr.exe --module "C:\Program Files\Firma CR\firma_cr_pkcs11.dll" pdf -i in.pdf -o out.pdf --pin <PIN>
   ```
4. For Firmador / Java (SunPKCS11), point its PKCS#11 config `library=` at the
   same DLL.

A real installer (autostart the agent, register paths, Authenticode signing) is
a separate task — **out of scope here**.

---

## 6. Testing with a real card (Windows)

- PC/SC comes from the built-in **Smart Card** service (`SCardSvr`) + the
  reader's own Windows driver. No pcsclite.
- Insert a BCCR Firma Digital card, run the agent or CLI, and exercise the full
  sign. `firma-cr.exe info` first (reads token/cert, no PIN) is the quickest
  smoke test that the DLL loads and the reader is seen.

---

## 7. Caveats to verify on Windows (the real unknowns)

1. **WinSCard transactions / share mode.** Chip-Auth + SM is a long APDU
   sequence; the card must be held (`SCardBeginTransaction` / appropriate share
   mode) or another process can grab the reader mid-flow. WinSCard semantics
   differ subtly from pcsclite — verify connect/transaction behaviour on a real
   reader.
2. **Coexistence with the official Idopte / SCManager.** A user's Windows box
   likely already has BCCR middleware that may own the reader, register a rival
   PKCS#11, and **also listen on `:41231`**. Expect contention; plan stop/replace
   or a different port.
3. **Authenticode signing.** Unsigned DLL/EXE/MSI trip SmartScreen and may be
   blocked by policy. (Separate from the smart-card signing — this is about
   trusting our binaries.)
4. **No card-sim on Windows.** The Linux vpcd test rig doesn't exist there;
   functional testing is hardware-dependent (real card, or a Windows virtual
   smart card, which is more setup).
