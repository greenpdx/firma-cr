# Firma CR — tester setup on a Raspberry Pi (Debian 13 "trixie", aarch64)

Goal: a fresh Pi → build the stack → **prove the real card is readable** →
**test the GUI** by signing a PDF. Each step is a bash script; run them in order.

The card flow is: **reader → `pcscd` → driver `.so` → PKCS#11 client → card**.
We verify that headlessly (step 3) *before* touching the GUI, so a failure points
at the stack, not the UI.

## What the tester needs
- A Raspberry Pi (64-bit, Debian 13 trixie) with internet.
- The **real BCCR Firma Digital card** + a PC/SC reader.
- A **GitHub account with access to all three repos** — `firma-cr` (public),
  `firma-cr-engine` (private, the closed driver), and `firma-cr-analysis`
  (private). Grant access before they start. The tester builds everything from
  source. *(`firma-cr-analysis` is cloned for completeness; the real-card test
  flow only needs `firma-cr` + `firma-cr-engine`.)*

## Steps

```sh
# 0. SSH + git + clone.  Delivered OUT-OF-BAND (paste / USB) and intentionally
#    NOT in this repo — it's what fetches the repo in the first place. The
#    equivalent commands are in COMMANDS.md §0 (ssh-keygen, add key to GitHub,
#    git clone the repos).
#    -> generate an SSH key, add it to GitHub, then:
#    -> clone ~/firma-cr and ~/firma-cr-engine (siblings).

cd ~/firma-cr/scripts/tester    # the rest of the scripts live here after cloning

# 1. Toolchain + dev packages (apt, rustup, node, pcscd, WebKitGTK).
bash 10-install-deps.sh
source ~/.cargo/env             # if cargo isn't found in the next step

# 2. Build the driver (closed) + agent/CLI (open); install the driver system-wide.
bash 20-build-stack.sh

# 3. STACK CHECK — insert the real card, then:
bash 30-check-stack.sh
#    Passes only if the driver reads a token and the certificate off the card.
#    NO PIN is entered here. If this fails, stop and fix it before the GUI.

# 4. Test the GUI.
bash 40-run-gui.sh              # opens the app (dev mode)
#    or: bash 40-run-gui.sh build   -> produces an installable .deb
```

## GUI test plan (step 4)
The GUI is self-contained: it embeds the signing agent on `127.0.0.1:41231` and
loads the driver itself — nothing else needs to run.

- **Tarjeta** tab → card / token / certificate details show up (no PIN).
- **Firmar** tab → add one or more PDFs, drag the signature box on the preview,
  click **Sign**, enter the **card PIN** once.
- **Documento** tab → the signed PDF opens inline.
- Confirm the signature externally:
  ```sh
  pdfsig ~/path/to/signed.pdf      # expect: "Signature is Valid"
  ```

## Troubleshooting
- **`cargo: command not found`** → `source ~/.cargo/env` (or open a new shell).
- **Step 3 sees no token** → card fully seated? reader plugged in?
  `sudo systemctl restart pcscd` then retry. `pcsc_scan` should show an ATR.
- **GUI says the port is busy / `:41231` in use** → the official BCCR
  `SCManager`/`Agente-GAUDI` is running and owns that port. Stop it
  (`sudo ss -ltnp | grep 41231` to find the PID) so the embedded agent can bind.
- **Driver not found at runtime** → it must be at
  `/usr/lib/firma-cr/libfirma_cr_pkcs11.so` (step 2 installs it), or export
  `CRFIRMA_MODULE=/path/to/libfirma_cr_pkcs11.so` before launching.
- **First `tauri dev` is very slow on a Pi** → normal (cold Rust + WebKit build);
  later runs are incremental.

## Wedged reader (rare)
Killing a signing process mid-transaction can stall the reader. The driver
self-heals on the next connect; if signs still time out,
`sudo systemctl restart pcscd` clears it.
