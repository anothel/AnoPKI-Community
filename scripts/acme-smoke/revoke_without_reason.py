# SPDX-License-Identifier: MPL-2.0
"""Protocol probe using the pinned acme 5.6.0 network, not a Certbot CLI claim."""
import base64
import importlib.metadata
import pathlib
import subprocess
import sys

import josepy as jose
from acme import client, messages
from verify_multisan import require


def main():
    root, base, leaf = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
    require(importlib.metadata.version('acme') == '5.6.0')
    print('PROBE_STAGE=accounts', flush=True)
    accounts = list((root/'config/accounts').rglob('private_key.json'))
    require(len(accounts) == 1)
    print('PROBE_STAGE=key', flush=True)
    key = jose.JWK.json_loads(accounts[0].read_text())
    print('PROBE_STAGE=registration', flush=True)
    registration = messages.RegistrationResource.json_loads((accounts[0].parent/'regr.json').read_text())
    print('PROBE_STAGE=network', flush=True)
    network = client.ClientNetwork(key, account=registration)
    der = subprocess.check_output(['openssl', 'x509', '-in', str(leaf), '-outform', 'DER'])
    class OmittedReason(jose.JSONObjectWithFields):
        certificate: str = jose.field('certificate')
    print('PROBE_STAGE=post', flush=True)
    response = network.post(base+'/acme/revoke-cert',
        OmittedReason(certificate=base64.urlsafe_b64encode(der).decode().rstrip('=')),
        new_nonce_url=base+'/acme/new-nonce')
    require(response.status_code == 200 and response.content == b'')


if __name__ == '__main__':
    main()
