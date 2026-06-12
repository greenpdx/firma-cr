#!/usr/bin/env bash
# Shared paths + helpers for the tester setup scripts. Sourced by the others.
# Assumes the three repos are cloned as siblings under $HOME.

set -euo pipefail

# --- repo layout (siblings under $HOME) ------------------------------------
export FIRMA_HOME="${FIRMA_HOME:-$HOME}"
export OPEN_REPO="$FIRMA_HOME/firma-cr"           # public  (GUI + agent + CLI)
export ENGINE_REPO="$FIRMA_HOME/firma-cr-engine"  # private (the PKCS#11 driver)

# --- build artefacts -------------------------------------------------------
export DRIVER_SO="$ENGINE_REPO/target/release/libfirma_cr_pkcs11.so"
export DRIVER_INSTALL="/usr/lib/firma-cr/libfirma_cr_pkcs11.so"   # default path firma-cr looks for
export CLI_BIN="$OPEN_REPO/target/release/firma-cr"
export AGENT_BIN="$OPEN_REPO/target/release/firma-cr-agent"

# --- pretty output ---------------------------------------------------------
say()  { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }
