#!/usr/bin/env bash
# STEP 1 — development packages + toolchains (Debian 13 "trixie", aarch64 RPi).
#
#   bash 10-install-deps.sh
#
set -euo pipefail
cd "$(dirname "$0")"; . ./env.sh

say "APT packages (sudo)"
sudo apt-get update -qq
sudo apt-get install -y \
  build-essential pkg-config curl wget file ca-certificates git \
  libssl-dev \
  `# --- smart-card stack (the real card talks through pcscd) ---` \
  pcscd libpcsclite-dev pcsc-tools libccid \
  `# --- Tauri / WebKitGTK GUI deps ---` \
  libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev \
  libayatana-appindicator3-dev \
  `# --- signature verification for the smoke test ---` \
  poppler-utils \
  `# --- Node.js for the GUI frontend ---` \
  nodejs npm
ok "apt packages installed"

say "Enable the smart-card daemon (pcscd)"
sudo systemctl enable --now pcscd
ok "pcscd: $(systemctl is-active pcscd)"

say "Rust toolchain (rustup)"
if command -v rustc >/dev/null 2>&1 && rustc --version | grep -q .; then
  ok "rustc already present: $(rustc --version)"
else
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
  ok "rustup installed"
fi
# shellcheck disable=SC1090
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v rustc >/dev/null 2>&1 && ok "$(rustc --version)" || warn "Open a new shell (or 'source ~/.cargo/env') so cargo is on PATH."

say "Versions"
echo "  node $(node --version 2>/dev/null || echo '?')   npm $(npm --version 2>/dev/null || echo '?')"
echo "  pcsc-tools: $(command -v pcsc_scan || echo missing)"

say "Done. Next: bash 20-build-stack.sh"
warn "If 'cargo' is not found in the next script, run:  source ~/.cargo/env"
