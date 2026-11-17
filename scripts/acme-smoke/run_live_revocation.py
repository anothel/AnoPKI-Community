#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Linux-only, pinned real Certbot revocation rejection evidence. Run at repo root."""
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


def verify_wire(path, mode, leaf, directory):
    # Parse private Certbot debug logs internally; never print JWS or key material.
    content = path.read_text()
    objects = []
    decoder = json.JSONDecoder()
    for match in re.finditer(r'\{', content):
        try:
            value, _ = decoder.raw_decode(content[match.start():])
            if isinstance(value, dict):
                objects.append(value)
        except ValueError:
            pass
    expected = subprocess.check_output(['openssl', 'x509', '-in', str(leaf), '-outform', 'DER'])
    found = False
    for value in objects:
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
        require(set(payload) == {'certificate', 'reason'} and payload['reason'] == 4)
        require(base64.urlsafe_b64decode(payload['certificate']+'===') == expected)
        found = True
    require(found)
    require(any(value.get('type') == 'urn:ietf:params:acme:error:malformed'
                and value.get('status') == 400 and value.get('detail') == 'invalid request'
                for value in objects))


def exercise(root, certbot, core, stage):
    def run(args, label, cwd=None):
        stage[0] = label
        with (root/f'{label}.log').open('wb') as output:
            subprocess.run(args, cwd=cwd, stdout=output, stderr=output, check=True, timeout=180)

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
                with sqlite3.connect(root/'anopki.db') as db:
                    first = verify_orders(db, 1)
                    before = db.execute('SELECT id, status, certificate_pem FROM certificates').fetchall()
                    issuer = db.execute('SELECT certificate_pem FROM issuers').fetchone()[0]
                (root/'issuer.pem').write_text(issuer)
                run(['openssl', 'verify', '-CAfile', str(root/'issuer.pem'),
                     '-verify_hostname', NAME, str(leaf)], 'openssl-trust')
                for mode, options in [('account-key', []), ('certificate-key', ['--key-path', str(key)])]:
                    stage[0] = mode+'-revoke'
                    # Certbot rotates logs per invocation; isolate each mode.
                    revoke_common = common.copy()
                    log_dir = root/('logs-'+mode)
                    revoke_common[revoke_common.index('--logs-dir')+1] = str(log_dir)
                    wire_log = log_dir/'letsencrypt.log'
                    with (root/(mode+'.log')).open('wb') as output:
                        result = subprocess.run([str(certbot), 'revoke', *revoke_common,
                            '--server', directory, '--cert-path', str(leaf),
                            '--reason', 'superseded', '--no-delete-after-revoke', *options],
                            stdout=output, stderr=output, timeout=60)
                    require(result.returncode != 0)
                    log = (root/(mode+'.log')).read_text()
                    require('invalid request' in log.lower())
                    verify_wire(wire_log, mode, leaf, directory)
                    with sqlite3.connect(root/'anopki.db') as db:
                        require(db.execute('SELECT id, status, certificate_pem FROM certificates').fetchall() == before)
                        require(db.execute('SELECT COUNT(*) FROM revocations').fetchone()[0] == 0)
                        require(verify_orders(db, 1) == first)
                    print('Certbot '+mode+': HTTP 400 malformed/invalid request; certificate and revocation state unchanged', flush=True)
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
        with tempfile.TemporaryDirectory(prefix='acme-revocation.', dir=pathlib.Path('.tmp').resolve()) as tmp:
            exercise(pathlib.Path(tmp), args.certbot.resolve(), args.core.resolve(), stage)
    except Exception:
        # Never print subprocess output, exception details, JWS, DB rows or keys.
        print(f'Real Certbot revocation investigation failed at stage: {stage[0]}', file=sys.stderr)
        return 1
    print('Real Certbot revocation incompatibility reproduced; private state removed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
