#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Pinned lego renewal with retained local state; run from the repository root."""
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
from verify_renewal import NAME, verify_orders, verify_certificates


def account_state(root):
    files = [p for p in (root/'lego/accounts').rglob('*') if p.is_file()]
    require(len(files) == 2 and sorted(p.suffix for p in files) == ['.json', '.key'])
    return {p.relative_to(root): p.read_bytes() for p in files}


def certificate_state(root):
    directory = root/'lego/certificates'
    expected = {f'{NAME}.{ext}' for ext in ('crt', 'issuer.crt', 'key', 'json')}
    require({p.name for p in directory.iterdir()} == expected)
    return {p.name: p.read_bytes() for p in directory.iterdir()}


def verify_metadata(state, base_url, certificate_id):
    metadata = json.loads(state[f'{NAME}.json'])
    expected = base_url+'/acme/cert/'+certificate_id
    require(metadata['domain'] == NAME and metadata['certUrl'] == expected
            and metadata['certStableUrl'] == expected)


def save_pair(root, previous, current):
    # Normalize lego's downloaded bundle to the existing strict OpenSSL verifier.
    for n, state in enumerate((previous, current), 1):
        full = state[f'{NAME}.crt']
        chain = state[f'{NAME}.issuer.crt']
        require(chain and full.endswith(chain) and len(full) > len(chain))
        leaf = full[:-len(chain)]
        require(leaf.count(b'-----BEGIN CERTIFICATE-----') == 1)
        for kind, value in [('cert', leaf), ('chain', chain), ('fullchain', full),
                            ('privkey', state[f'{NAME}.key'])]:
            (root/f'{kind}{n}.pem').write_bytes(value)


def exercise(root, lego, core, stage):
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
    print('Real lego v4.35.2: dynamic skip, ordinary and unconditional renewal; isolated SQLite', flush=True)
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
                with sqlite3.connect(root/'anopki.db') as db:
                    first = verify_orders(db, 1)
                    issuers = db.execute('SELECT certificate_pem FROM issuers').fetchall()
                require(len(issuers) == 1)
                (root/'issuer.pem').write_text(issuers[0][0])
                issuer_key = (root/'issuer.key').read_bytes()
                account = account_state(root)
                previous = certificate_state(root)
                verify_metadata(previous, public_url, next(iter(first.values()))[0])
                renew = [*common, 'renew', '--no-random-sleep']
                run([*renew, '--dynamic'], 'dynamic-renew')
                stage[0] = 'dynamic-skip-evidence'
                with sqlite3.connect(root/'anopki.db') as db:
                    require(verify_orders(db, 1) == first)
                require(account_state(root) == account and certificate_state(root) == previous)
                require(b'no renewal.' in (root/'dynamic-renew.log').read_bytes())
                print('Dynamic renew: not due; account, storage and single order unchanged', flush=True)
                previous_pem = next(iter(first.values()))[1]
                for count, options, label in [(2, [], 'ordinary-renew'),
                                               (3, ['--days', '-1'], 'unconditional-renew')]:
                    run([*renew, *options], label)
                    stage[0] = label+'-evidence'
                    require(service.poll() is None and account_state(root) == account)
                    require((root/'issuer.key').read_bytes() == issuer_key)
                    with sqlite3.connect(root/'anopki.db') as db:
                        both = verify_orders(db, count)
                        require(db.execute('SELECT certificate_pem FROM issuers').fetchall() == issuers)
                    require(all(both[k] == v for k, v in first.items()))
                    new = set(both)-set(first)
                    require(len(new) == 1)
                    certificate_id, pem = both[new.pop()]
                    current = certificate_state(root)
                    verify_metadata(current, public_url, certificate_id)
                    save_pair(root, previous, current)
                    verify_certificates(root, [previous_pem, pem])
                    print(f'{label}: {count} valid orders under retained account; fresh HTTP-01 authorization; rotated leaf key verified', flush=True)
                    first, previous, previous_pem = both, current, pem
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
        with tempfile.TemporaryDirectory(prefix='lego-renewal.', dir=pathlib.Path('.tmp').resolve()) as tmp:
            exercise(pathlib.Path(tmp), args.lego.resolve(), args.core.resolve(), stage)
    except Exception:
        print(f'Real lego renewal failed at stage: {stage[0]}', file=sys.stderr)
        return 1
    print('Real lego renewal and OpenSSL verification passed; private state removed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
