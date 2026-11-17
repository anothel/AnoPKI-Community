# SPDX-License-Identifier: MPL-2.0
"""Private-state checks and actual OpenSSL verification for revocation runners."""
import datetime
import json
import sqlite3
import subprocess
import urllib.request

from verify_multisan import require, openssl
from verify_renewal import verify_orders


def prepare(root, leaf):
    with sqlite3.connect(root/'anopki.db') as db:
        verify_orders(db, 1)
        rows = db.execute('SELECT id, issuer_id, certificate_pem, status FROM certificates').fetchall()
        require(len(rows) == 1 and rows[0][3] == 'valid')
        certificate, issuer, pem, _ = rows[0]
        issuer_pem = db.execute('SELECT certificate_pem FROM issuers WHERE id=?', (issuer,)).fetchone()[0]
    (root/'issuer.pem').write_text(issuer_pem)
    (root/'database-leaf.pem').write_text(pem)
    require(openssl('x509', '-in', leaf, '-outform', 'DER') ==
            openssl('x509', '-in', root/'database-leaf.pem', '-outform', 'DER'))
    openssl('verify', '-CAfile', root/'issuer.pem', '-verify_hostname', 'edge-01.example.test', leaf)
    return certificate, issuer


def verify_database(root, certificate, expected):
    with sqlite3.connect(root/'anopki.db') as db:
        verify_orders(db, 1)
        require(db.execute('SELECT status FROM certificates WHERE id=?', (certificate,)).fetchone() == ('revoked',))
        require(db.execute('SELECT certificate_id, reason FROM revocations').fetchall() == [(certificate, expected)])
        audits = db.execute("SELECT metadata_json FROM audit_events WHERE action='certificate.revoked'").fetchall()
        outbox = db.execute("SELECT payload_json FROM outbox_messages WHERE type='certificate.revoked'").fetchall()
        for rows in (audits, outbox):
            require(len(rows) == 1)
            data = json.loads(rows[0][0])
            require(data.get('certificate_id') == certificate and data.get('revocation_reason') == expected)


def verify_status(root, base, leaf, issuer, reason=None, revoked=False):
    # Publish and fetch actual service-generated status objects. Existing dev
    # actor authentication is confined to this fresh isolated local service.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    body = json.dumps({'issuer_id': issuer, 'distribution_point': base+'/fixture.crl',
        'next_update': (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}).encode()
    request = urllib.request.Request(base+'/crls', body,
        {'Content-Type': 'application/json', 'X-Actor': 'operator'})
    with opener.open(request, timeout=10) as response:
        publication = json.load(response)
    (root/'status.crl').write_text(publication['crl_pem'])
    openssl('crl', '-in', root/'status.crl', '-verify', '-CAfile', root/'issuer.pem', '-noout')
    text = openssl('crl', '-in', root/'status.crl', '-text', '-noout').decode()
    result = subprocess.run(['openssl', 'verify', '-CAfile', str(root/'issuer.pem'),
        '-CRLfile', str(root/'status.crl'), '-crl_check', str(leaf)], capture_output=True, timeout=10)
    require((not revoked and result.returncode == 0) or
            (revoked and result.returncode != 0 and b'certificate revoked' in result.stderr))
    require(not revoked or reason in ('not_provided', 'unspecified', 'superseded'))
    expected_reason = {'not_provided': None, 'unspecified': 'Unspecified', 'superseded': 'Superseded'}.get(reason)
    require(('X509v3 CRL Reason Code' in text) == (revoked and expected_reason is not None))
    if revoked and expected_reason:
        require(expected_reason in text)
    openssl('ocsp', '-issuer', root/'issuer.pem', '-cert', leaf, '-no_nonce', '-reqout', root/'status.req')
    request = urllib.request.Request(base+'/ocsp', (root/'status.req').read_bytes(),
        {'Content-Type': 'application/ocsp-request'})
    with opener.open(request, timeout=10) as response:
        (root/'status.resp').write_bytes(response.read())
    result = subprocess.run(['openssl', 'ocsp', '-respin', str(root/'status.resp'),
        '-issuer', str(root/'issuer.pem'), '-cert', str(leaf), '-CAfile', str(root/'issuer.pem'),
        '-no_nonce', '-text'], capture_output=True, timeout=10)
    require(result.returncode == 0 and b'Response verify OK' in result.stderr)
    text = result.stdout.decode()
    require((': revoked' if revoked else ': good') in text)
    require(('Revocation Reason:' in text) == (revoked and expected_reason is not None))
    if revoked and expected_reason:
        require('Revocation Reason: '+expected_reason.lower() in text)
