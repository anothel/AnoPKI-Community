# SPDX-License-Identifier: MPL-2.0
import base64
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from run_live_revocation import verify_wire


class WireEvidenceTest(unittest.TestCase):
    def test_requires_target_der_mode_reason_and_exact_problem(self):
        def b64(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
        directory = 'http://127.0.0.1:1234/acme/directory'
        header = {'url': directory.replace('/directory', '/revoke-cert'), 'kid': 'account'}
        payload = {'certificate': base64.urlsafe_b64encode(b'leaf-der').decode().rstrip('='), 'reason': 4}
        problem = {'type': 'urn:ietf:params:acme:error:malformed', 'status': 400, 'detail': 'invalid request'}
        def wire(h=header, p=payload, response=problem):
            return json.dumps({'protected': b64(h), 'payload': b64(p), 'signature': 'private-fixture'})+'\n'+json.dumps(response)
        with tempfile.TemporaryDirectory() as tmp, patch('run_live_revocation.subprocess.check_output', return_value=b'leaf-der'):
            path = pathlib.Path(tmp)/'private.log'
            path.write_text(wire())
            verify_wire(path, 'account-key', path, directory)
            for content in [wire(p={**payload, 'reason': 'superseded'}),
                            wire(p={**payload, 'certificate': 'b3RoZXI'}),
                            wire(h={**header, 'url': 'https://foreign/acme/revoke-cert'}),
                            wire(response={**problem, 'status': 403}),
                            wire(response={**problem, 'type': 'urn:ietf:params:acme:error:badNonce'})]:
                path.write_text(content)
                with self.assertRaises(Exception):
                    verify_wire(path, 'account-key', path, directory)
            path.write_text(wire())
            with self.assertRaises(Exception):
                verify_wire(path, 'certificate-key', path, directory)
            with self.assertRaises(Exception):
                path.write_text('no revocation traffic')
                verify_wire(path, 'account-key', path, directory)
            path.write_text(wire(h={'url':header['url'], 'jwk':{'kty':'EC'}}))
            verify_wire(path, 'certificate-key', path, directory)


if __name__ == '__main__':
    unittest.main()
