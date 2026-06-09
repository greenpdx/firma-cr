#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build runtime .deb packages for the OPEN Firma CR components:
#   - firma-cr         (the CLI: sign / verify / info / list / cert / probe)
#   - firma-cr-agent   (the local /dyn web-signing service, SCManager role)
#
# Both come from the firma-cr-core crate (the agent is its `agent`-feature
# binary). The desktop GUI is packaged from the firma-cr-gui repo (`tauri
# build`); the closed driver + signd from the firma-cr-engine repo.
#
# Runtime artifacts + runtime Depends only. Run on the target architecture.
set -euo pipefail

PKG_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$PKG_DIR/.." && pwd)          # open workspace root
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  arm64) TRIPLET=aarch64-linux-gnu ;;
  amd64) TRIPLET=x86_64-linux-gnu ;;
  armhf) TRIPLET=arm-linux-gnueabihf ;;
  *)     TRIPLET="$(uname -m)-linux-gnu" ;;
esac
MAINT="Shaun Savage <savages@crmep.com>"
DIST="$PKG_DIR/dist"
rm -rf "$DIST"; mkdir -p "$DIST"
ver() { grep -m1 '^version' "$1/Cargo.toml" | cut -d'"' -f2; }

CORE="$ROOT/crates/firma-cr-core"; V=$(ver "$CORE")
# One build yields both bins: the CLI (default) and the agent (--features agent).
echo ">> building firma-cr CLI + agent (release, --features agent)"
( cd "$ROOT" && cargo build --release --features agent -p firma-cr-core >/dev/null )

# --- firma-cr (CLI) --------------------------------------------------------
P1="$DIST/firma-cr_${V}_${ARCH}"
mkdir -p "$P1/DEBIAN" "$P1/usr/bin"
install -m755 "$ROOT/target/release/firma-cr" "$P1/usr/bin/"
cat > "$P1/DEBIAN/control" <<EOF
Package: firma-cr
Version: $V
Architecture: $ARCH
Maintainer: $MAINT
Section: utils
Priority: optional
Depends: libc6, libgcc-s1, libpcsclite1, pcscd
Recommends: firma-cr-pkcs11
Description: Firma CR — CLI signer/verifier for the BCCR Firma Digital card
 Sign (PAdES/CAdES/XAdES) and verify documents through any PKCS#11 module —
 the official Idopte driver, OpenSC, or the firma-cr-pkcs11 driver.
EOF
dpkg-deb --build --root-owner-group "$P1" "$DIST/firma-cr_${V}_${ARCH}.deb" >/dev/null

# --- firma-cr-agent (local /dyn service) -----------------------------------
P2="$DIST/firma-cr-agent_${V}_${ARCH}"
mkdir -p "$P2/DEBIAN" "$P2/usr/bin" "$P2/lib/systemd/system"
install -m755 "$ROOT/target/release/firma-cr-agent" "$P2/usr/bin/"
cat > "$P2/lib/systemd/system/firma-cr-agent.service" <<EOF
[Unit]
Description=firma-cr-agent — local /dyn web-signing agent (SCManager replacement)
Wants=pcscd.service
After=pcscd.service network.target

[Service]
Environment=CRFIRMA_MODULE=/usr/lib/firma-cr/libfirma_cr_pkcs11.so
ExecStart=/usr/bin/firma-cr-agent
Restart=on-failure
RestartSec=2
# Hardening — localhost-only, stateless service:
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
RuntimeDirectory=firma-cr-agent

[Install]
WantedBy=multi-user.target
EOF
cat > "$P2/DEBIAN/control" <<EOF
Package: firma-cr-agent
Version: $V
Architecture: $ARCH
Maintainer: $MAINT
Section: utils
Priority: optional
Depends: libc6, libgcc-s1, libpcsclite1, pcscd
Recommends: firma-cr-pkcs11
Description: Firma CR — local /dyn web-signing agent (SCManager replacement)
 Serves the local /dyn HTTP API that BCCR websites call, backed by any PKCS#11
 module. Runs as a systemd service on 127.0.0.1:41231.
EOF
cat > "$P2/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  systemctl daemon-reload || true
  systemctl enable --now firma-cr-agent.service || true
fi
PI
cat > "$P2/DEBIAN/prerm" <<'PR'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then systemctl disable --now firma-cr-agent.service || true; fi
PR
cat > "$P2/DEBIAN/postrm" <<'PO'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then systemctl daemon-reload || true; fi
PO
chmod 755 "$P2/DEBIAN/postinst" "$P2/DEBIAN/prerm" "$P2/DEBIAN/postrm"
dpkg-deb --build --root-owner-group "$P2" "$DIST/firma-cr-agent_${V}_${ARCH}.deb" >/dev/null

echo ">> built:"; ls -1 "$DIST"/*.deb 2>/dev/null
