#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Linux-only, pinned real Certbot revocation interoperability evidence. Run at repo root."""
import argparse
import base64
import functools
import glob
import http.server
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from verify_multisan import require
from verify_renewal import NAME, verify_orders
from run_live_renewal import private_process, QuietWebroot
from verify_revocation import prepare, verify_database, verify_status


def verify_wire(path, mode, leaf, directory, numeric_reason=4):
    # Parse private Certbot debug logs internally; never print JWS or key material.
    content = path.read_text()
    objects = []
    decoder = json.JSONDecoder()
    for match in re.finditer(r'\{', content):
        try:
            value, consumed = decoder.raw_decode(content[match.start():])
            if isinstance(value, dict):
                objects.append((value, match.start()+consumed))
        except ValueError:
            pass
    expected = subprocess.check_output(['openssl', 'x509', '-in', str(leaf), '-outform', 'DER'])
    found = False
    for value, end in objects:
        if not all(field in value for field in ('protected', 'payload', 'signature')):
            continue
        decode = lambda field: json.loads(base64.urlsafe_b64decode(value[field]+'==='))
        header = decode('protected')
        if header.get('url') != directory.replace('/directory', '/revoke-cert'):
            continue
        payload = decode('payload')
        if mode == 'account-key' and 'kid' not in header:
            continue
        if mode == 'certificate-key' and ('jwk' not in header or 'kid' in header):
            continue
        require(set(payload) == {'certificate', 'reason'} and type(payload['reason']) is int and payload['reason'] == numeric_reason)
        require(base64.urlsafe_b64decode(payload['certificate']+'===') == expected)
        response = re.search(r'Received response:\s*\nHTTP ([0-9]{3})(?:\s|$)', content[end:])
        if response and response.group(1) == '200':
            found = True
    require(found)


def exercise(root, certbot, core, stage, mode="account-key"):
    def run(args, label, cwd=None):
        stage[0] = label
        with (root/f'{label}.log').open('wb') as output:
            result = subprocess.run(args, cwd=cwd, stdout=output, stderr=output, timeout=180)
        if result.returncode:
            if label == 'omitted-reason-probe':
                steps = re.findall(r'PROBE_STAGE=([a-z]+)', (root/f'{label}.log').read_text())
                stage[0] = 'omitted-reason-'+(steps[-1] if steps else 'startup')
            raise RuntimeError('private command failed')

    stage[0] = 'client-configuration'
    # Certbot 5.6.0 reads both default cli.ini files even with --config-dir
    # or an explicit empty --config. Refuse ambient settings/hooks before any
    # client invocation; do not read, modify or print their private contents.
    defaults = ['/etc/letsencrypt/cli.ini',
                os.path.join(os.environ.get('XDG_CONFIG_HOME', '~/.config'), 'letsencrypt', 'cli.ini')]
    require(not any(glob.glob(os.path.expanduser(path)) for path in defaults))
    run([str(certbot), '--version'], 'versions')
    require((root/'versions.log').read_text().strip() == 'certbot 5.6.0')
    print('Real client: Certbot 5.6.0; revocation investigation; isolated SQLite', flush=True)
    run(['go', 'build', '-o', str(root/'anopki-service'), './cmd/anopki-service'], 'service-build', cwd='service')
    webroot = root/'http01-webroot'
    webroot.mkdir()
    # The OS allocates responder ports; no public DNS/port-80 requests.
    handler = functools.partial(QuietWebroot, directory=str(webroot))
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler) as responder:
        thread = threading.Thread(target=responder.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            url = f'http://127.0.0.1:{port}'
            directory = url+'/acme/directory'
            # Inherited deployment/credential configuration cannot affect this fixture.
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANOPKI_')}
            env.update({
                'ANOPKI_ADDR': f'127.0.0.1:{port}', 'ANOPKI_ENV': 'development',
                'ANOPKI_AUTH_MODE': 'dev', 'ANOPKI_DB_DRIVER': 'sqlite',
                'ANOPKI_DB_DSN': str(root/'anopki.db'), 'ANOPKI_CORE_BIN': str(core),
                'ANOPKI_ACME_HTTP01_BASE_URL': f'http://127.0.0.1:{responder.server_port}',
                'ANOPKI_ACME_BOOTSTRAP_DEFAULTS': 'true', 'ANOPKI_ACME_DEFAULT_VALIDITY': '24h',
                'ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF': str(root/'issuer.key'),
            })
            stage[0] = 'service-start'
            with private_process([str(root/'anopki-service')], root/'service.log', env) as service:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                deadline = time.monotonic()+30
                while True:
                    require(service.poll() is None)
                    try:
                        with opener.open(directory, timeout=1) as response:
                            data = json.load(response)
                        require(data['newNonce'] == url+'/acme/new-nonce' and
                                data['newAccount'] == url+'/acme/new-account' and
                                data['newOrder'] == url+'/acme/new-order')
                        break
                    except (OSError, ValueError):
                        require(time.monotonic() < deadline)
                        time.sleep(0.1)
                common = ['--config-dir', str(root/'config'), '--work-dir', str(root/'work'),
                          '--logs-dir', str(root/'logs'), '--non-interactive']
                run([str(certbot), 'certonly', *common, '--server', directory, '--webroot',
                     '--webroot-path', str(webroot), '--agree-tos', '--email', 'ops@example.test',
                     '--no-eff-email', '--cert-name', NAME, '-d', NAME], 'initial-issuance')
                stage[0] = 'revocation-evidence'
                leaf = root/'config/live'/NAME/'cert.pem'
                key = root/'config/live'/NAME/'privkey.pem'
                certificate, issuer = prepare(root, leaf)
                verify_status(root, url, leaf, issuer)
                if mode == 'omitted':
                    stage[0] = 'pinned-acme-omitted-reason-probe'
                    expected = 'not_provided'
                    run([str(certbot.parent/'python'), 'scripts/acme-smoke/revoke_without_reason.py',
                         str(root), url, str(leaf)], 'omitted-reason-probe')
                else:
                    numeric, expected = (4, 'superseded') if mode == 'account-key' else (0, 'unspecified')
                    options = [] if mode == 'account-key' else ['--key-path', str(key)]
                    stage[0] = mode+'-revoke'
                    revoke_common = common.copy()
                    log_dir = root/('logs-'+mode)
                    revoke_common[revoke_common.index('--logs-dir')+1] = str(log_dir)
                    run([str(certbot), 'revoke', *revoke_common, '--server', directory,
                         '--cert-path', str(leaf), '--reason', expected,
                         '--no-delete-after-revoke', *options], mode+'-revoke')
                    verify_wire(log_dir/'letsencrypt.log', mode, leaf, directory, numeric)
                verify_database(root, certificate, expected)
                stage[0] = mode+'-signed-status'
                verify_status(root, url, leaf, issuer, expected, revoked=True)
                print(('Pinned-acme protocol probe' if mode == 'omitted' else 'Certbot '+mode)+': HTTP 200; database/audit/outbox and signed CRL/OCSP verify revoked with '+expected, flush=True)
        finally:
            responder.shutdown()
            thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('certbot', type=pathlib.Path)
    parser.add_argument('core', type=pathlib.Path)
    args = parser.parse_args()
    os.umask(0o077)
    stage = ['versions']
    try:
        pathlib.Path('.tmp').mkdir(exist_ok=True)
        for mode in ('account-key', 'certificate-key', 'omitted'):
            with tempfile.TemporaryDirectory(prefix='acme-revocation.', dir=pathlib.Path('.tmp').resolve()) as tmp:
                exercise(pathlib.Path(tmp), args.certbot.resolve(), args.core.resolve(), stage, mode)
    except Exception:
        # Never print subprocess output, exception details, JWS, DB rows or keys.
        print(f'Real Certbot revocation investigation failed at stage: {stage[0]}', file=sys.stderr)
        return 1
    print('Real Certbot account-key and certificate-key revocation verified; private state removed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
