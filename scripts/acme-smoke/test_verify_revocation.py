# SPDX-License-Identifier: MPL-2.0
import json
import pathlib
import sqlite3
import tempfile
import unittest

from verify_revocation import verify_database


class RevocationEvidenceTests(unittest.TestCase):
    def database(self, root):
        db = sqlite3.connect(root/'anopki.db')
        db.executescript('''
            CREATE TABLE acme_accounts(id, status);
            CREATE TABLE acme_orders(id, account_id, status, requested_dns_names, certificate_id);
            CREATE TABLE acme_authorizations(id, order_id, identifier_type, identifier_value, status);
            CREATE TABLE acme_challenges(authorization_id, type, token, status, validated_at);
            CREATE TABLE certificates(id, certificate_pem, status);
            CREATE TABLE revocations(certificate_id, reason);
            CREATE TABLE audit_events(action, metadata_json);
            CREATE TABLE outbox_messages(type, payload_json);
            INSERT INTO acme_accounts VALUES ('account','valid');
            INSERT INTO acme_orders VALUES ('order','account','valid','["edge-01.example.test"]','cert');
            INSERT INTO acme_authorizations VALUES ('auth','order','dns','edge-01.example.test','valid');
            INSERT INTO acme_challenges VALUES ('auth','http-01','fixture','valid','2026-11-17T00:00:00Z');
            INSERT INTO certificates VALUES ('cert','public-fixture','revoked');
            INSERT INTO revocations VALUES ('cert','not_provided');
        ''')
        payload = json.dumps({'certificate_id':'cert', 'revocation_reason':'not_provided'})
        db.execute("INSERT INTO audit_events VALUES ('certificate.revoked',?)", (payload,))
        db.execute("INSERT INTO outbox_messages VALUES ('certificate.revoked',?)", (payload,))
        db.commit()
        return db

    def test_requires_exact_marker_and_transactional_evidence(self):
        for mutation in [None, "UPDATE certificates SET status='valid'",
                         "UPDATE revocations SET reason='unspecified'",
                         "DELETE FROM audit_events", "DELETE FROM outbox_messages",
                         "UPDATE audit_events SET metadata_json='{}'",
                         "UPDATE outbox_messages SET payload_json='{}'",
                         "INSERT INTO revocations VALUES ('cert','not_provided')"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                with self.database(root) as db:
                    if mutation:
                        db.execute(mutation)
                if mutation:
                    with self.assertRaises(ValueError):
                        verify_database(root, 'cert', 'not_provided')
                else:
                    verify_database(root, 'cert', 'not_provided')
                    with self.assertRaises(ValueError):
                        verify_database(root, 'cert', 'unspecified')


if __name__ == '__main__':
    unittest.main()
