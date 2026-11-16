# SPDX-License-Identifier: MPL-2.0
"""Fail-closed checks for one retained Certbot lineage and two ACME orders."""
import datetime
import json

from verify_multisan import openssl, require, verify_sans

NAME = 'edge-01.example.test'


def verify_orders(db, count):
    accounts = db.execute('SELECT id, status FROM acme_accounts').fetchall()
    require(len(accounts) == 1 and accounts[0][1] == 'valid')
    orders = db.execute('SELECT id, account_id, status, requested_dns_names, certificate_id FROM acme_orders').fetchall()
    require(len(orders) == count)
    require(db.execute('SELECT COUNT(*) FROM acme_authorizations').fetchone()[0] == count)
    require(db.execute('SELECT COUNT(*) FROM acme_challenges').fetchone()[0] == count)
    certs = dict(db.execute('SELECT id, certificate_pem FROM certificates').fetchall())
    require(len(certs) == count)
    tokens, certificate_ids, result = set(), set(), {}
    for order, account, status, dns, certificate in orders:
        require(account == accounts[0][0] and status == 'valid' and json.loads(dns) == [NAME])
        require(certificate in certs and certificate not in certificate_ids and certs[certificate])
        certificate_ids.add(certificate)
        authzs = db.execute('SELECT id, identifier_type, identifier_value, status FROM acme_authorizations WHERE order_id=?', (order,)).fetchall()
        require(len(authzs) == 1 and authzs[0][1:] == ('dns', NAME, 'valid'))
        challenges = db.execute('SELECT type, token, status, validated_at FROM acme_challenges WHERE authorization_id=?', (authzs[0][0],)).fetchall()
        require(len(challenges) == 1)
        kind, token, status, validated = challenges[0]
        require(kind == 'http-01' and token and token not in tokens and status == 'valid' and validated)
        tokens.add(token)
        result[order] = (certificate, certs[certificate])
    return result


def verify_certificates(root, database_pems):
    require(len(database_pems) == 2)
    issuer = root/'issuer.pem'
    serials, keys, metadata = [], [], []
    for n, pem in enumerate(database_pems, 1):
        leaf, chain, full, key = (root/f'{kind}{n}.pem' for kind in ('cert', 'chain', 'fullchain', 'privkey'))
        for path in (leaf, chain):
            require(path.read_bytes().count(b'-----BEGIN CERTIFICATE-----') == 1)
            require(path.read_bytes().count(b'-----END CERTIFICATE-----') == 1)
        require(full.read_bytes() == leaf.read_bytes() + chain.read_bytes())
        require(openssl('x509', '-in', chain, '-outform', 'DER') ==
                openssl('x509', '-in', issuer, '-outform', 'DER'))
        db_leaf = root/f'database-cert{n}.pem'
        db_leaf.write_text(pem)
        require(openssl('x509', '-in', leaf, '-outform', 'DER') ==
                openssl('x509', '-in', db_leaf, '-outform', 'DER'))
        verify_sans(openssl('x509', '-in', leaf, '-noout', '-ext', 'subjectAltName').decode(), [NAME])
        openssl('verify', '-CAfile', issuer, '-untrusted', chain, '-verify_hostname', NAME, '-purpose', 'sslserver', leaf)
        openssl('verify', '-CAfile', issuer, chain)
        openssl('verify', '-CAfile', issuer, '-verify_hostname', 'wrong.example.test', leaf, success=False)
        openssl('x509', '-in', leaf, '-checkend', '3600', '-noout')
        openssl('x509', '-in', leaf, '-checkend', '172800', '-noout', success=False)
        dates = openssl('x509', '-in', leaf, '-noout', '-dates').decode().splitlines()
        times = [datetime.datetime.strptime(line.split('=', 1)[1], '%b %d %H:%M:%S %Y GMT') for line in dates]
        require(len(times) == 2 and datetime.timedelta(hours=23) < times[1]-times[0] < datetime.timedelta(hours=25))
        serial = int(openssl('x509', '-in', leaf, '-noout', '-serial').decode().strip().split('=')[1], 16)
        require(serial > 0)
        serials.append(serial)
        pubkey = openssl('x509', '-in', leaf, '-pubkey', '-noout')
        require(pubkey == openssl('pkey', '-in', key, '-pubout'))
        keys.append(pubkey)
        metadata.append(openssl('x509', '-in', leaf, '-noout', '-serial', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName').decode())
    require(serials[0] != serials[1] and keys[0] != keys[1])
    for n, value in enumerate(metadata, 1):
        print(f'Certificate version {n}:\n{value}', end='')
    print('Both certificates match their orders; trust, exact SAN, validity, distinct serials, rotated leaf keys and downloaded chains verified')
