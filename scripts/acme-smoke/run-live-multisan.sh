#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
umask 077
client=${1:?pass lego or certbot}
client_bin=$(realpath "${2:?pass pinned client executable}")
core_bin=$(realpath "${3:?pass Community OpenSSL core executable}")
case "$client" in lego|certbot) ;; *) exit 2 ;; esac
mkdir -p .tmp
work=$(mktemp -d "$PWD/.tmp/acme-multisan.XXXXXXXX")
stage=versions
cleanup() {
    result=$?
    rm -rf -- "$work"
    if [ "$result" -ne 0 ]; then echo "Multi-name $client failed at stage: $stage" >&2; fi
}
trap cleanup EXIT
"$client_bin" --version > "$work/version" 2>&1
if [ "$client" = certbot ]; then
    test "$(cat "$work/version")" = 'certbot 5.6.0'
    path_arg=-CertbotPath
else
    grep -Eq '^lego version v?4\.35\.2(\+dev-release)? ' "$work/version"
    path_arg=-LegoPath
fi
echo "Real $client multi-name HTTP-01; isolated SQLite and local responder"
stage=enrollment
pwsh -NoProfile -File scripts/acme-smoke/run-certbot-smoke.ps1 \
    -Client "$client" "$path_arg" "$client_bin" -StartService -Run \
    -Domain edge-01.example.test -AdditionalDomain edge-02.example.test \
    -CoreBin "$core_bin" -ServiceBin "$work/anopki-service" \
    -HTTPSProxyBin "$work/acme-https-proxy" \
    -WorkDir "$work" -DbDsn "$work/anopki.db" \
    -ServiceLogDir "$work/service-logs" -DirectoryTimeoutSec 90 \
    > "$work/private-harness.log" 2>&1
stage=verification
python3 scripts/acme-smoke/verify_multisan.py "$work" "$client" edge-01.example.test edge-02.example.test
