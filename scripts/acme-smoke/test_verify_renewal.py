# SPDX-License-Identifier: MPL-2.0
"""Reject evidence that could mistake a skip or unrelated issuance for renewal."""
import contextlib
import io
import json
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest

from verify_renewal import verify_orders, verify_certificates

NAME = 'edge-01.example.test'


class OrderTests(unittest.TestCase):
    def database(self):
        db = sqlite3.connect(':memory:')
        db.executescript('''
            CREATE TABLE acme_accounts(id, status);
            CREATE TABLE acme_orders(id, account_id, status, requested_dns_names, certificate_id);
            CREATE TABLE acme_authorizations(id, order_id, identifier_type, identifier_value, status);
            CREATE TABLE acme_challenges(authorization_id, type, token, status, validated_at);
            CREATE TABLE certificates(id, certificate_pem);
            INSERT INTO acme_accounts VALUES ('account', 'valid');
        ''')
        for n in (1, 2):
            db.execute('INSERT INTO acme_orders VALUES (?, ?, ?, ?, ?)',
                       (f'order{n}', 'account', 'valid', json.dumps([NAME]), f'cert{n}'))
            db.execute('INSERT INTO acme_authorizations VALUES (?, ?, ?, ?, ?)',
                       (f'auth{n}', f'order{n}', 'dns', NAME, 'valid'))
            db.execute('INSERT INTO acme_challenges VALUES (?, ?, ?, ?, ?)',
                       (f'auth{n}', 'http-01', f'token{n}', 'valid', '2026-11-16T01:00:00Z'))
            db.execute('INSERT INTO certificates VALUES (?, ?)', (f'cert{n}', f'pem{n}'))
        return db

    def test_same_account_two_independent_valid_orders(self):
        self.assertEqual(verify_orders(self.database(), 2),
                         {'order1': ('cert1', 'pem1'), 'order2': ('cert2', 'pem2')})

    def test_skip_cannot_be_called_renewal(self):
        db = self.database()
        db.execute("DELETE FROM acme_orders WHERE id='order2'")
        with self.assertRaises(ValueError):
            verify_orders(db, 2)

    def test_incomplete_or_unrelated_evidence_rejected(self):
        for mutation in [
            "UPDATE acme_orders SET account_id='other' WHERE id='order2'",
            "UPDATE acme_orders SET certificate_id='cert1'",
            "UPDATE acme_orders SET requested_dns_names='[]' WHERE id='order2'",
            "UPDATE acme_orders SET status='ready' WHERE id='order2'",
            "DELETE FROM acme_authorizations WHERE id='auth2'",
            "UPDATE acme_authorizations SET status='pending' WHERE id='auth2'",
            "UPDATE acme_authorizations SET identifier_value='wrong.test' WHERE id='auth2'",
            "UPDATE acme_challenges SET token='token1' WHERE authorization_id='auth2'",
            "UPDATE acme_challenges SET validated_at=NULL WHERE authorization_id='auth2'",
            "UPDATE acme_challenges SET status='processing' WHERE authorization_id='auth2'",
            "DELETE FROM certificates WHERE id='cert2'",
            "UPDATE acme_accounts SET status='deactivated'",
            "INSERT INTO acme_accounts VALUES ('other', 'valid')",
        ]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                db = self.database()
                db.execute(mutation)
                verify_orders(db, 2)


class CertificateTests(unittest.TestCase):
    def test_real_openssl_renewal_and_corrupted_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            def run(*args):
                subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)
            run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', root/'ca.key',
                '-out', root/'issuer.pem', '-subj', '/CN=Throwaway renewal CA', '-days', '2')
            (root/'ext').write_text('subjectAltName=DNS:'+NAME+'\nextendedKeyUsage=serverAuth\n')
            for n in (1, 2):
                run('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-keyout', root/f'privkey{n}.pem', '-out', root/'leaf.csr', '-subj', '/')
                run('x509', '-req', '-in', root/'leaf.csr', '-CA', root/'issuer.pem',
                    '-CAkey', root/'ca.key', '-set_serial', str(n), '-days', '1',
                    '-extfile', root/'ext', '-out', root/f'cert{n}.pem')
                (root/f'chain{n}.pem').write_bytes((root/'issuer.pem').read_bytes())
                (root/f'fullchain{n}.pem').write_bytes(
                    (root/f'cert{n}.pem').read_bytes()+(root/f'chain{n}.pem').read_bytes())
            pems = [(root/f'cert{n}.pem').read_text() for n in (1, 2)]
            with contextlib.redirect_stdout(io.StringIO()):
                verify_certificates(root, pems)
            mutations = [
                ('cert2.pem', (root/'cert1.pem').read_bytes()),
                ('privkey2.pem', (root/'privkey1.pem').read_bytes()),
                ('chain2.pem', (root/'chain2.pem').read_bytes()+(root/'cert1.pem').read_bytes()),
                ('fullchain2.pem', (root/'cert2.pem').read_bytes()),
            ]
            for name, bad in mutations:
                with self.subTest(file=name), self.assertRaises(ValueError):
                    path = root/name
                    original = path.read_bytes()
                    path.write_bytes(bad)
                    try:
                        verify_certificates(root, pems)
                    finally:
                        path.write_bytes(original)
            with self.assertRaises(ValueError):
                verify_certificates(root, pems[::-1])
            # Keep DB binding/fullchain/key matches correct while isolating the
            # distinct-serial, rotated-key, exact-SAN and lifetime guards.
            originals = {name: (root/name).read_bytes() for name in ('cert2.pem', 'privkey2.pem', 'fullchain2.pem')}
            for serial, key_version, names, days in [
                ('1', 2, NAME, '1'),
                ('2', 1, NAME, '1'),
                ('2', 2, NAME+',DNS:extra.example.test', '1'),
                ('2', 2, NAME, '3'),
            ]:
                with self.subTest(serial=serial, key=key_version, names=names, days=days):
                    for name, content in originals.items():
                        (root/name).write_bytes(content)
                    run('req', '-new', '-key', root/f'privkey{key_version}.pem', '-out', root/'leaf.csr', '-subj', '/')
                    (root/'ext').write_text('subjectAltName=DNS:'+names+'\nextendedKeyUsage=serverAuth\n')
                    run('x509', '-req', '-in', root/'leaf.csr', '-CA', root/'issuer.pem',
                        '-CAkey', root/'ca.key', '-set_serial', serial, '-days', days,
                        '-extfile', root/'ext', '-out', root/'cert2.pem')
                    (root/'privkey2.pem').write_bytes((root/f'privkey{key_version}.pem').read_bytes())
                    (root/'fullchain2.pem').write_bytes((root/'cert2.pem').read_bytes()+(root/'chain2.pem').read_bytes())
                    with self.assertRaises(ValueError):
                        verify_certificates(root, [pems[0], (root/'cert2.pem').read_text()])


if __name__ == '__main__':
    unittest.main()
