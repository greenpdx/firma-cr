#!/usr/bin/env bash
# STEP 4 — launch the GUI to test against the real card.
#
# The GUI is the whole app: it embeds the /dyn signing agent on 127.0.0.1:41231
# and loads the driver from /usr/lib/firma-cr/libfirma_cr_pkcs11.so by itself —
# nothing else needs to be running.
#
#   bash 40-run-gui.sh            # dev mode: compiles + opens the window (slow first run on a Pi)
#   bash 40-run-gui.sh build      # instead, build an installable .deb bundle
#
set -euo pipefail
cd "$(dirname "$0")"; . ./env.sh
# shellcheck disable=SC1090
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

[ -f "$DRIVER_INSTALL" ] || die "Driver not installed — run 20-build-stack.sh first"
GUI_DIR="$OPEN_REPO/gui"
[ -d "$GUI_DIR" ] || die "Missing $GUI_DIR"

say "Installing frontend dependencies (npm)"
( cd "$GUI_DIR" && npm install )
ok "node_modules ready"

# The official SCManager/GAUDI middleware (if present) owns :41231 and will clash
# with the GUI's embedded agent. Warn if something already holds the port.
if ss -ltn 2>/dev/null | grep -q ':41231 '; then
  warn ":41231 is already in use (official SCManager/GAUDI?). Stop it, or the"
  warn "embedded agent can't bind. Find it with:  sudo ss -ltnp | grep 41231"
fi

MODE="${1:-dev}"
if [[ "$MODE" == build ]]; then
  say "Building an installable bundle (.deb) — this takes a while on a Pi"
  ( cd "$GUI_DIR" && npm run tauri build -- --bundles deb )
  say "Bundle(s):"
  find "$OPEN_REPO/gui/src-tauri/target/release/bundle" -name '*.deb' 2>/dev/null || \
    find "$OPEN_REPO" -path '*bundle*' -name '*.deb' 2>/dev/null
  echo "Install with:  sudo apt install ./<that>.deb   then launch 'Firma CR' from the menu."
  exit 0
fi

say "Launching the GUI (tauri dev). First compile is slow — be patient."
echo "    A window titled 'Firma CR — firmador' will open. Test plan:"
echo "      • Tarjeta tab  → card/token/cert details appear (no PIN)."
echo "      • Firmar tab   → add a PDF, set the signature box, Sign, enter the card PIN."
echo "      • Documento tab→ the signed PDF opens; verify it externally with:"
echo "          pdfsig ~/path/to/signed.pdf      # expect 'Signature is Valid'"
echo
( cd "$GUI_DIR" && npm run tauri dev )
