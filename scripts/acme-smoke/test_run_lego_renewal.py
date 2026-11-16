# SPDX-License-Identifier: MPL-2.0
import pathlib
import subprocess
import sys
import tempfile
import unittest

class LegoTests(unittest.TestCase):
    def test_wrong_version_is_private_and_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root/'lego'
            fake.write_text('#!/bin/sh\necho PRIVATE-MARKER\necho lego version 0.0.0\n')
            fake.chmod(0o700)
            runner = pathlib.Path(__file__).with_name('run_lego_renewal.py').resolve()
            result = subprocess.run([sys.executable, str(runner), str(fake), '/bin/false'], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('stage: versions', result.stderr)
            self.assertNotIn('PRIVATE-MARKER', result.stdout+result.stderr)
            self.assertEqual(list((root/'.tmp').iterdir()), [])

    def test_storage_requires_complete_exact_files(self):
        from run_lego_renewal import certificate_state, NAME
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            certs = root/'lego/certificates'
            certs.mkdir(parents=True)
            for ext in ('crt', 'issuer.crt', 'key', 'json'):
                (certs/f'{NAME}.{ext}').write_text(ext)
            saved = certificate_state(root)
            self.assertEqual(len(saved), 4)
            for ext in ('crt', 'issuer.crt', 'key', 'json'):
                path = certs/f'{NAME}.{ext}'
                path.unlink()
                with self.assertRaises(ValueError):
                    certificate_state(root)
                path.write_text(ext)
            (certs/'unrelated.crt').touch()
            with self.assertRaises(ValueError):
                certificate_state(root)

    def test_account_snapshot_detects_changes_and_missing_keys(self):
        from run_lego_renewal import account_state
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            account = root/'lego/accounts/local/ops@example.test'
            (account/'keys').mkdir(parents=True)
            key = account/'keys/ops@example.test.key'
            key.write_bytes(b'private fixture')
            (account/'account.json').write_text('{"registration":"retained"}')
            saved = account_state(root)
            key.write_bytes(b'replaced fixture')
            self.assertNotEqual(account_state(root), saved)
            key.unlink()
            with self.assertRaises(ValueError):
                account_state(root)

    def test_bundle_normalization_rejects_missing_or_extra_leaf(self):
        from run_lego_renewal import save_pair, NAME
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            leaf = b'-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n'
            chain = b'-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n'
            state = {f'{NAME}.crt': leaf+chain, f'{NAME}.issuer.crt': chain, f'{NAME}.key': b'key'}
            save_pair(root, state, state)
            self.assertEqual((root/'cert1.pem').read_bytes(), leaf)
            self.assertEqual((root/'chain2.pem').read_bytes(), chain)
            for bad in (leaf, chain, leaf+leaf+chain):
                with self.assertRaises(ValueError):
                    save_pair(root, state, {**state, f'{NAME}.crt': bad})

    def test_metadata_must_match_new_certificate(self):
        import json
        from run_lego_renewal import verify_metadata, NAME
        url = 'https://127.0.0.1:1234'
        good = {'domain': NAME, 'certUrl': url+'/acme/cert/new',
                'certStableUrl': url+'/acme/cert/new'}
        def state(value):
            return {f'{NAME}.json': json.dumps(value).encode()}
        verify_metadata(state(good), url, 'new')
        for key, value in [('domain', 'other.test'), ('certUrl', url+'/acme/cert/old'),
                           ('certStableUrl', url+'/acme/cert/old')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_metadata(state({**good, key: value}), url, 'new')

if __name__ == '__main__':
    unittest.main()
