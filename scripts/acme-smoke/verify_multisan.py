# SPDX-License-Identifier: MPL-2.0
"""Fail-closed evidence checks for a fresh, local two-name ACME run."""
import json
import pathlib
import sqlite3
import subprocess
import sys


def require(condition):
    if not condition:
        raise ValueError('multi-name evidence mismatch')


def verify_order(db, names):
    require(len(names) >= 2 and len(set(names)) == len(names))
    orders = db.execute('SELECT id, status, requested_dns_names, certificate_id FROM acme_orders').fetchall()
    require(len(orders) == 1)
    order, status, dns, certificate = orders[0]
    require(status == 'valid' and certificate and sorted(json.loads(dns)) == sorted(names))
    authzs = db.execute('SELECT id, identifier_type, identifier_value, status FROM acme_authorizations WHERE order_id=?', (order,)).fetchall()
    require(len(authzs) == len(names))
    require(sorted(a[2] for a in authzs) == sorted(names))
    tokens = []
    for authz, kind, name, status in authzs:
        require(kind == 'dns' and status == 'valid')
        challenges = db.execute('SELECT type, token, status, validated_at FROM acme_challenges WHERE authorization_id=?', (authz,)).fetchall()
        require(len(challenges) == 1)
        kind, token, status, validated = challenges[0]
        require(kind == 'http-01' and token and status == 'valid' and validated)
        tokens.append(token)
    require(len(set(tokens)) == len(names))


def verify_sans(output, names):
    lines = output.strip().splitlines()
    require(lines and 'Subject Alternative Name' in lines[0])
    sans = [s.strip() for s in ''.join(lines[1:]).split(',')]
    require(sorted(sans) == sorted('DNS:' + n for n in names))


def openssl(*args, success=True):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, check=False)
    require((result.returncode == 0) == success)
    return result.stdout


def verify_certificate(root, client, names):
    with sqlite3.connect(root / 'anopki.db') as db:
        verify_order(db, names)
        issuers = db.execute('SELECT certificate_pem FROM issuers').fetchall()
    require(len(issuers) == 1)
    issuer = root / 'issuer.pem'
    issuer.write_text(issuers[0][0])
    if client == 'certbot':
        live = root / 'config/live' / names[0]
        leaf, chain, full, key = (live / f for f in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'])
        require(full.read_bytes() == leaf.read_bytes() + chain.read_bytes())
    else:
        live = root / 'lego/certificates'
        full, chain, key = (live / (names[0] + suffix) for suffix in ['.crt', '.issuer.crt', '.key'])
        # lego bundles leaf and issuer. Check every downloaded block and retain leaf separately.
        blocks = full.read_bytes().split(b'-----END CERTIFICATE-----')
        require(len(blocks) == 3 and not blocks[-1].strip())
        require(blocks[1].strip() + b'\n-----END CERTIFICATE-----\n' == chain.read_bytes())
        leaf = root / 'leaf.pem'
        leaf.write_bytes(blocks[0] + b'-----END CERTIFICATE-----\n')
    # This bootstrap scenario has one self-signed issuer; reject ignored extra PEM blocks.
    for certificate in (leaf, chain):
        require(certificate.read_bytes().count(b'-----BEGIN CERTIFICATE-----') == 1)
        require(certificate.read_bytes().count(b'-----END CERTIFICATE-----') == 1)
    require(openssl('x509', '-in', chain, '-outform', 'DER') ==
            openssl('x509', '-in', issuer, '-outform', 'DER'))
    verify_sans(openssl('x509', '-in', leaf, '-noout', '-ext', 'subjectAltName').decode(), names)
    for name in names:
        openssl('verify', '-CAfile', issuer, '-untrusted', chain, '-verify_hostname', name, '-purpose', 'sslserver', leaf)
    openssl('verify', '-CAfile', issuer, chain)
    openssl('x509', '-in', leaf, '-checkend', '3600', '-noout')
    openssl('x509', '-in', leaf, '-checkend', '172800', '-noout', success=False)
    openssl('verify', '-CAfile', issuer, '-verify_hostname', 'wrong.example.test', leaf, success=False)
    require(openssl('x509', '-in', leaf, '-pubkey', '-noout') == openssl('pkey', '-in', key, '-pubout'))
    print(openssl('x509', '-in', leaf, '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName').decode(), end='')
    print('Two distinct HTTP-01 authorizations valid; exact DNS SANs, chain, time, hostnames and key match passed')


if __name__ == '__main__':
    try:
        verify_certificate(pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3:])
    except Exception:
        # Never expose subprocess output, database rows, tokens or key material.
        raise SystemExit('Multi-name certificate/evidence verification failed') from None
