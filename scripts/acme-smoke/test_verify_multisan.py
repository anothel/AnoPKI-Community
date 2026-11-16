# SPDX-License-Identifier: MPL-2.0
import json
import sqlite3
import unittest
import pathlib
import tempfile
import subprocess
import contextlib
import io
from verify_multisan import verify_order, verify_sans, verify_certificate

NAMES = ['edge-01.example.test', 'edge-02.example.test']

class EvidenceTests(unittest.TestCase):
    def db(self):
        db = sqlite3.connect(':memory:')
        db.executescript('''
        CREATE TABLE acme_orders(id, status, requested_dns_names, certificate_id);
        CREATE TABLE acme_authorizations(id, order_id, identifier_type, identifier_value, status);
        CREATE TABLE acme_challenges(authorization_id, type, token, status, validated_at);
        ''')
        db.execute('INSERT INTO acme_orders VALUES (?, ?, ?, ?)', ('order', 'valid', json.dumps(NAMES), 'cert'))
        for i, name in enumerate(NAMES):
            db.execute('INSERT INTO acme_authorizations VALUES (?, ?, ?, ?, ?)', (str(i), 'order', 'dns', name, 'valid'))
            db.execute('INSERT INTO acme_challenges VALUES (?, ?, ?, ?, ?)', (str(i), 'http-01', f'token-{i}', 'valid', '2026-11-16T01:00:00Z'))
        return db

    def test_complete_order(self):
        verify_order(self.db(), NAMES)

    def test_incomplete_evidence_rejected(self):
        for mutation in [
            "DELETE FROM acme_authorizations WHERE id='1'",
            "UPDATE acme_authorizations SET status='pending' WHERE id='1'",
            "UPDATE acme_challenges SET status='processing' WHERE authorization_id='1'",
            "UPDATE acme_challenges SET validated_at=NULL WHERE authorization_id='1'",
            "UPDATE acme_challenges SET token='same'",
            "UPDATE acme_authorizations SET identifier_value='edge-01.example.test'",
            "UPDATE acme_orders SET status='ready'",
            "UPDATE acme_orders SET requested_dns_names='[]'",
        ]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                db = self.db()
                db.execute(mutation)
                verify_order(db, NAMES)

    def test_exact_sans(self):
        verify_sans('X509v3 Subject Alternative Name:\n DNS:edge-02.example.test, DNS:edge-01.example.test\n', NAMES)
        for sans in ['DNS:edge-01.example.test', 'DNS:edge-01.example.test, DNS:edge-02.example.test, DNS:extra.test',
                     'DNS:edge-01.example.test, IP Address:127.0.0.1',
                     'DNS:edge-01.example.test, DNS:edge-01.example.test']:
            with self.subTest(sans=sans), self.assertRaises(ValueError):
                verify_sans('X509v3 Subject Alternative Name:\n' + sans, NAMES)

class CertificateTests(EvidenceTests):
    def test_real_openssl_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            live = root / 'config/live' / NAMES[0]
            live.mkdir(parents=True)
            def run(*args):
                subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)
            run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/'ca.key',
                '-out', root/'ca.pem', '-subj', '/CN=Throwaway test issuer', '-days', '2')
            run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', live/'privkey.pem',
                '-out', root/'leaf.csr', '-subj', '/CN='+NAMES[0])
            (root/'ext').write_text('subjectAltName=DNS:'+NAMES[0]+',DNS:'+NAMES[1]+'\n')
            run('x509', '-req', '-in', root/'leaf.csr', '-CA', root/'ca.pem', '-CAkey', root/'ca.key',
                '-CAcreateserial', '-out', live/'cert.pem', '-days', '1', '-extfile', root/'ext')
            (live/'chain.pem').write_bytes((root/'ca.pem').read_bytes())
            def fullchain():
                (live/'fullchain.pem').write_bytes((live/'cert.pem').read_bytes()+(live/'chain.pem').read_bytes())
            fullchain()
            db = self.db()
            db.commit()
            disk = sqlite3.connect(root/'anopki.db')
            db.backup(disk)
            disk.execute('CREATE TABLE issuers(certificate_pem)')
            disk.execute('INSERT INTO issuers VALUES (?)', ((root/'ca.pem').read_text(),))
            disk.commit()
            disk.close()
            with contextlib.redirect_stdout(io.StringIO()):
                verify_certificate(root, 'certbot', NAMES)
            original_key = (live/'privkey.pem').read_bytes()
            (live/'privkey.pem').write_bytes((root/'ca.key').read_bytes())
            with self.assertRaises(ValueError):
                verify_certificate(root, 'certbot', NAMES)
            (live/'privkey.pem').write_bytes(original_key)
            # An extra unrelated PEM block must not silently escape chain checks.
            (live/'chain.pem').write_bytes((root/'ca.pem').read_bytes()+(live/'cert.pem').read_bytes())
            fullchain()
            with self.assertRaises(ValueError):
                verify_certificate(root, 'certbot', NAMES)

if __name__ == '__main__':
    unittest.main()
