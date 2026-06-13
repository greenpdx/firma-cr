#!/usr/bin/env bash
# Generate the self-signed X.509 "audit" certificate and sign the audit report
# with it (detached CMS / PKCS#7). Reproducible and idempotent:
#   * if audit-cert.pem + audit-cert.key already exist, the cert is reused;
#   * the report is (re)signed to docs/audit/<report>.p7s.
#
# The PRIVATE KEY (audit-cert.key) is NOT committed (see .gitignore). Only the
# public certificate (audit-cert.pem) and the signature ship, so anyone can
# verify the report with docs/audit/verify-audit.sh.
#
# Usage:  docs/audit/gen-audit-cert.sh [report.md]

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPORT="${1:-$HERE/SECURITY-AUDIT-2026-06.md}"
KEY="$HERE/audit-cert.key"
CERT="$HERE/audit-cert.pem"
SIG="$REPORT.p7s"

SUBJ="/C=CR/O=CRMEP/CN=Firma CR Security Audit"
DAYS=3650

if [[ ! -f "$REPORT" ]]; then
    echo "error: report not found: $REPORT" >&2
    exit 1
fi

if [[ -f "$CERT" && -f "$KEY" ]]; then
    echo "==> reusing existing audit cert ($CERT)"
else
    if [[ -f "$CERT" && ! -f "$KEY" ]]; then
        echo "error: $CERT exists but $KEY is missing — cannot re-sign." >&2
        echo "       (the private key is intentionally not committed)" >&2
        exit 1
    fi
    echo "==> generating audit signing key + self-signed cert"
    openssl req -x509 -newkey rsa:3072 -keyout "$KEY" -out "$CERT" \
        -days "$DAYS" -nodes -subj "$SUBJ" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=codeSigning" 2>/dev/null
    chmod 600 "$KEY"
fi

echo "==> signing report (detached CMS, DER): $(basename "$REPORT")"
openssl cms -sign -binary -in "$REPORT" \
    -signer "$CERT" -inkey "$KEY" \
    -outform DER -out "$SIG"

echo "==> done:"
echo "    cert: $CERT"
echo "    sig:  $SIG"
echo "    verify with: $HERE/verify-audit.sh"
