#!/usr/bin/env bash
# STEP 3 — confirm the WHOLE stack reads the real card, headless, NO PIN.
#
#   reader → pcscd → driver(.so) → PKCS#11 client → card certificate
#
# If this passes, the GUI will work. If it fails, the GUI would only hide the
# error — fix it here first.
#
#   bash 30-check-stack.sh         # insert the real card before running
#
set -euo pipefail
cd "$(dirname "$0")"; . ./env.sh

[ -x "$CLI_BIN" ]        || die "Build first: bash 20-build-stack.sh"
[ -f "$DRIVER_INSTALL" ] || die "Driver not installed at $DRIVER_INSTALL — run 20-build-stack.sh"

say "1/4  pcscd running?"
[ "$(systemctl is-active pcscd)" = active ] || { sudo systemctl start pcscd; }
ok "pcscd: $(systemctl is-active pcscd)"

say "2/4  Reader + card visible to PC/SC?"
warn "Watching the reader for ~6s — insert the card now if you haven't."
# pcsc_scan exits on its own with -r? Use timeout; ATR line means a card is present.
if timeout 6 pcsc_scan 2>/dev/null | grep -qiE 'ATR|Card inserted|PC/SC device'; then
  ok "A reader/card is visible to pcscd"
else
  warn "pcsc_scan didn't clearly show a card. Continuing — the driver probe below is the real test."
fi

say "3/4  Driver enumerates a token (firma-cr list — no PIN)"
"$CLI_BIN" list || die "No token. Check: card fully inserted? reader plugged in? 'sudo systemctl restart pcscd'."
ok "PKCS#11 driver sees a slot with a token"

say "4/4  Read the signing certificate off the card (firma-cr info — no PIN)"
"$CLI_BIN" info || die "Could not read the cert. Driver loaded but card not readable."
ok "Certificate read from the card — the full stack works end-to-end"

say "Clock sanity (matters for SIGNING, not for reading the card)"
synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
if [ "$synced" = yes ]; then
  ok "system clock NTP-synced ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))"
else
  warn "clock NOT NTP-synced (NTPSynchronized=$synced). A Pi has no RTC; a wrong"
  warn "clock makes signatures carry a bad signingTime and can make verification"
  warn "falsely fail. Fix before signing in the GUI: sudo timedatectl set-ntp true"
fi

cat <<'EOF'

  ──────────────────────────────────────────────────────────────────────
  STACK OK.  The card is readable through the driver. You did NOT enter a
  PIN — that only happens at signing time, in the GUI.

  Next:  bash 40-run-gui.sh
  ──────────────────────────────────────────────────────────────────────
EOF
