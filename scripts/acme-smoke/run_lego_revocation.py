#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Pinned lego RFC revocation and signed status evidence; run from the repository root."""
import argparse
import functools
import http.server
import json
import os
import pathlib
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from run_live_renewal import private_process, QuietWebroot
from verify_multisan import require
from verify_renewal import NAME
from verify_revocation import prepare, verify_database, verify_status


def exercise(root, lego, core, stage, mode):
    # Do not inherit lego-specific flags/credentials.
    client_env = {k: v for k, v in os.environ.items() if not k.startswith('LEGO_')}
    def run(args, label, cwd=None):
        stage[0] = label
        with (root/f'{label}.log').open('wb') as output:
            subprocess.run(args, cwd=cwd, env=client_env, stdout=output, stderr=output,
                           check=True, timeout=180)
    run([str(lego), '--version'], 'versions')
    require(re.fullmatch(r'lego version v?4\.35\.2(?:\+dev-release)? .*',
                         (root/'versions.log').read_text().strip()) is not None)
    print('Real lego v4.35.2: RFC revocation; isolated SQLite', flush=True)
    run(['go', 'build', '-o', str(root/'anopki-service'), './cmd/anopki-service'], 'service-build', cwd='service')
    run(['go', 'build', '-o', str(root/'https-proxy'), 'scripts/acme-smoke/acme-https-proxy.go'], 'proxy-build')
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
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                proxy_port = sock.getsockname()[1]
            public_url = f'https://127.0.0.1:{proxy_port}'
            directory = public_url+'/acme/directory'
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
            with private_process([str(root/'anopki-service')], root/'service.log', env) as service, \
                    private_process([str(root/'https-proxy'), '-listen', f'127.0.0.1:{proxy_port}',
                                     '-target', url], root/'proxy.log', client_env) as proxy:
                # Same throwaway loopback TLS adapter as the existing lego lanes.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
                deadline = time.monotonic()+30
                while True:
                    require(service.poll() is None and proxy.poll() is None)
                    try:
                        with opener.open(directory, timeout=1) as response:
                            data = json.load(response)
                        require(data['newNonce'] == public_url+'/acme/new-nonce' and
                                data['newAccount'] == public_url+'/acme/new-account' and
                                data['newOrder'] == public_url+'/acme/new-order')
                        break
                    except (OSError, ValueError):
                        require(time.monotonic() < deadline)
                        time.sleep(0.1)
                common = [str(lego), '--path', str(root/'lego'), '--server', directory,
                          '--email', 'ops@example.test', '--domains', NAME,
                          '--tls-skip-verify', '--http', '--http.webroot', str(webroot), '--accept-tos']
                run([*common, 'run'], 'initial-issuance')
                stage[0] = 'initial-evidence'
                leaf = root/'lego/certificates'/f'{NAME}.crt'
                certificate, issuer = prepare(root, leaf)
                verify_status(root, url, leaf, issuer)
                options = [] if mode == 'default' else ['--reason', '4']
                expected = 'unspecified' if mode == 'default' else 'superseded'
                run([*common, 'revoke', '--keep', *options], 'revoke-'+mode)
                stage[0] = 'revoke-evidence-'+mode
                verify_database(root, certificate, expected)
                verify_status(root, url, leaf, issuer, expected, revoked=True)
                print('Lego '+mode+': database/audit/outbox and signed CRL/OCSP verify revoked with '+expected, flush=True)
        finally:
            responder.shutdown()
            thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lego', type=pathlib.Path)
    parser.add_argument('core', type=pathlib.Path)
    args = parser.parse_args()
    os.umask(0o077)
    stage = ['versions']
    try:
        pathlib.Path('.tmp').mkdir(exist_ok=True)
        for mode in ('default', 'superseded'):
            with tempfile.TemporaryDirectory(prefix='lego-revocation.', dir=pathlib.Path('.tmp').resolve()) as tmp:
                exercise(pathlib.Path(tmp), args.lego.resolve(), args.core.resolve(), stage, mode)
    except Exception:
        print(f'Real lego revocation failed at stage: {stage[0]}', file=sys.stderr)
        return 1
    print('Real lego default-zero/explicit-superseded revocation and OpenSSL status verified; private state removed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
