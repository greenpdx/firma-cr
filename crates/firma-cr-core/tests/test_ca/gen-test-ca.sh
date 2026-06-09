#!/usr/bin/env bash
# Generate a 3-tier RSA test CA:
#   test-root.{key,crt}          — self-signed root, 10-year
#   test-intermediate.{key,crt}  — signed by root, 5-year
#   test-leaf.{key,crt}          — signed by intermediate, 2-year
#   test-chain.pem               — intermediate + root concatenated
#
# Outputs land in tests/test_ca/out/. Re-running is idempotent: only
# regenerates if outputs are missing. Pass `--force` to nuke and
# regenerate.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${HERE}/out"
mkdir -p "$OUT"

if [[ "${1:-}" == "--force" ]]; then
    rm -f "$OUT"/*
fi

if [[ -f "$OUT/test-leaf.crt" && -f "$OUT/test-chain.pem" ]]; then
    echo "test CA already present in $OUT — pass --force to regenerate"
    exit 0
fi

echo "==> generating test CA in $OUT"

# Root CA — self-signed, 3650 days
openssl genrsa -out "$OUT/test-root.key" 2048 2>/dev/null
openssl req -x509 -new -key "$OUT/test-root.key" \
    -days 3650 -sha256 \
    -subj "/C=CR/O=firma-cr-pades test/CN=CR Test Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT/test-root.crt"

# Intermediate CA — signed by root, 1825 days
openssl genrsa -out "$OUT/test-intermediate.key" 2048 2>/dev/null
openssl req -new -key "$OUT/test-intermediate.key" \
    -subj "/C=CR/O=firma-cr-pades test/CN=CR Test Intermediate CA" \
    -out "$OUT/test-intermediate.csr"
openssl x509 -req -in "$OUT/test-intermediate.csr" \
    -CA "$OUT/test-root.crt" -CAkey "$OUT/test-root.key" \
    -CAcreateserial -days 1825 -sha256 \
    -extfile <(echo -e "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") \
    -out "$OUT/test-intermediate.crt"
rm -f "$OUT/test-intermediate.csr"

# Leaf signer — signed by intermediate, 730 days
openssl genrsa -out "$OUT/test-leaf.key" 2048 2>/dev/null
openssl req -new -key "$OUT/test-leaf.key" \
    -subj "/C=CR/O=firma-cr-pades test/CN=Test Signer" \
    -out "$OUT/test-leaf.csr"
openssl x509 -req -in "$OUT/test-leaf.csr" \
    -CA "$OUT/test-intermediate.crt" -CAkey "$OUT/test-intermediate.key" \
    -CAcreateserial -days 730 -sha256 \
    -extfile <(echo -e "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=clientAuth,emailProtection") \
    -out "$OUT/test-leaf.crt"
rm -f "$OUT/test-leaf.csr"

# Chain bundle (intermediate then root)
cat "$OUT/test-intermediate.crt" "$OUT/test-root.crt" > "$OUT/test-chain.pem"

echo "==> done; verify with:"
echo "    openssl verify -CAfile $OUT/test-root.crt -untrusted $OUT/test-intermediate.crt $OUT/test-leaf.crt"
