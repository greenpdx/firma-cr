#!/usr/bin/env bash
# Verify the audit report's detached CMS signature against the committed audit
# certificate. Exits non-zero if the report has been tampered with or the
# signature does not match. Needs only the public cert + the .p7s (no key).
#
# Usage:  docs/audit/verify-audit.sh [report.md]

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPORT="${1:-$HERE/SECURITY-AUDIT-2026-06.md}"
CERT="$HERE/audit-cert.pem"
SIG="$REPORT.p7s"

for f in "$REPORT" "$CERT" "$SIG"; do
    [[ -f "$f" ]] || { echo "error: missing $f" >&2; exit 2; }
done

# The audit cert is self-signed and asserts EKU=codeSigning, so trust it as its
# own CA (-CAfile) and accept any purpose.
openssl cms -verify -binary \
    -content "$REPORT" -in "$SIG" -inform DER \
    -certfile "$CERT" -CAfile "$CERT" -purpose any \
    -out /dev/null

echo "OK: $(basename "$REPORT") is authentic (signed by the audit certificate)."
