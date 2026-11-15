#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Linux-only real-client evidence; run from the repository root.
set -euo pipefail
umask 077
certbot_bin=$(realpath "${1:?pass pinned Certbot executable}")
core_bin=$(realpath "${2:?pass Community OpenSSL core executable}")
mkdir -p .tmp
work=$(mktemp -d "$PWD/.tmp/acme-live-certbot.XXXXXXXX")
stage=versions
cleanup() {
    result=$?
    # Certbot debug logs contain JWS bodies; never print or upload this directory.
    rm -rf -- "$work"
    if [ "$result" -ne 0 ]; then
        echo "Real Certbot HTTP-01 failed at stage: $stage" >&2
    fi
}
trap cleanup EXIT
"$certbot_bin" --version > "$work/version" 2>&1
test "$(cat "$work/version")" = 'certbot 5.6.0'
echo 'Real client: Certbot 5.6.0; HTTP-01 webroot; isolated SQLite'
stage=enrollment
# Suppress all client, responder and service output, including challenge paths.
pwsh -NoProfile -File scripts/acme-smoke/run-certbot-smoke.ps1 \
    -CertbotPath "$certbot_bin" -StartService -Run \
    -CoreBin "$core_bin" -ServiceBin "$work/anopki-service" \
    -WorkDir "$work" -DbDsn "$work/anopki.db" \
    -ServiceLogDir "$work/service-logs" -DirectoryTimeoutSec 90 \
    > "$work/private-harness.log" 2>&1
stage=certificate-verification
live="$work/config/live/edge-01.example.test"
# Anchor verification in the actual isolated service issuer, not client input.
python3 - "$work" <<'PY'
import pathlib
import sqlite3
import sys
root = pathlib.Path(sys.argv[1])
with sqlite3.connect(root / 'anopki.db') as db:
    rows = db.execute('SELECT certificate_pem FROM issuers').fetchall()
if len(rows) != 1:
    raise SystemExit('expected one isolated issuer')
(root / 'issuer.pem').write_text(rows[0][0])
PY
for file in cert.pem chain.pem fullchain.pem privkey.pem; do
    test -s "$live/$file"
done
openssl verify -CAfile "$work/issuer.pem" -verify_hostname edge-01.example.test \
    -purpose sslserver "$live/cert.pem" > "$work/verify.log" 2>&1
openssl verify -CAfile "$work/issuer.pem" "$live/chain.pem" >> "$work/verify.log" 2>&1
openssl x509 -in "$live/cert.pem" -checkend 3600 -noout > "$work/time.log" 2>&1
openssl x509 -in "$live/cert.pem" -pubkey -noout > "$work/cert.pub"
openssl pkey -in "$live/privkey.pem" -pubout > "$work/key.pub" 2> "$work/key.log"
cmp -s "$work/cert.pub" "$work/key.pub"
cat "$live/cert.pem" "$live/chain.pem" > "$work/fullchain.pem"
cmp -s "$work/fullchain.pem" "$live/fullchain.pem"
# Exercise fail-closed hostname and time checks on the real retrieved certificate.
if openssl verify -CAfile "$work/issuer.pem" -verify_hostname wrong.example.test \
    "$live/cert.pem" > "$work/wrong-host.log" 2>&1; then
    exit 1
fi
if openssl x509 -in "$live/cert.pem" -checkend 172800 -noout > "$work/expiry.log" 2>&1; then
    exit 1
fi
openssl x509 -in "$live/cert.pem" -noout -subject -issuer -dates -ext subjectAltName
echo 'Real Certbot HTTP-01 issuance, retrieval, issuer trust, hostname, validity and key match passed'
