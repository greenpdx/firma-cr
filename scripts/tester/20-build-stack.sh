#!/usr/bin/env bash
# STEP 2 — build the closed driver + the open agent/CLI, and install the driver
# where firma-cr looks for it by default (/usr/lib/firma-cr/).
#
#   bash 20-build-stack.sh
#
# Note: release builds on an RPi are slow the first time (lots of crates +
# WebKit-free here, but still ~minutes). Subsequent builds are incremental.
set -euo pipefail
cd "$(dirname "$0")"; . ./env.sh
# shellcheck disable=SC1090
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v cargo >/dev/null 2>&1 || die "cargo not on PATH — run: source ~/.cargo/env"

[ -d "$ENGINE_REPO" ] || die "Missing $ENGINE_REPO (run 00-ssh-git.sh)"
[ -d "$OPEN_REPO" ]   || die "Missing $OPEN_REPO (run 00-ssh-git.sh)"

say "Building the PKCS#11 driver (closed) — firma-cr-engine"
( cd "$ENGINE_REPO" && cargo build --release -p firma-cr-pkcs11 )
[ -f "$DRIVER_SO" ] || die "Driver .so not produced at $DRIVER_SO"
ok "Built $DRIVER_SO"

say "Installing the driver to $DRIVER_INSTALL (sudo)"
sudo install -Dm755 "$DRIVER_SO" "$DRIVER_INSTALL"
ok "Installed — firma-cr & the GUI will find it with no env var"

say "Building the agent + CLI (open) — firma-cr-core"
( cd "$OPEN_REPO" && cargo build --release -p firma-cr-core \
    --features agent --bin firma-cr-agent --bin firma-cr )
[ -x "$CLI_BIN" ]   || die "CLI not built at $CLI_BIN"
[ -x "$AGENT_BIN" ] || die "Agent not built at $AGENT_BIN"
ok "Built $CLI_BIN"
ok "Built $AGENT_BIN"

say "Done. Next: bash 30-check-stack.sh  (insert the real card first)"
