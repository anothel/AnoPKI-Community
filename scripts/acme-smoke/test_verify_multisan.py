# SPDX-License-Identifier: MPL-2.0
import json
import sqlite3
import unittest
from verify_multisan import verify_order, verify_sans

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

if __name__ == '__main__':
    unittest.main()
