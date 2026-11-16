#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Linux-only, pinned real Certbot forced-renewal evidence. Run at repo root."""
import argparse
import contextlib
import functools
import glob
import http.server
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from verify_multisan import require
from verify_renewal import NAME, verify_orders, verify_certificates


@contextlib.contextmanager
def private_process(args, log, env):
    with log.open('wb') as output:
        process = subprocess.Popen(args, stdout=output, stderr=output, env=env)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


class QuietWebroot(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Challenge paths contain tokens; never print them.


def account_state(root):
    # Keep the exact account registration and private-key files unchanged.
    files = list((root/'config/accounts').rglob('*.json'))
    require(len(files) == 3 and sorted(p.name for p in files) == ['meta.json', 'private_key.json', 'regr.json'])
    return {p.relative_to(root): p.read_bytes() for p in files}


def lineage_state(root, version):
    config = root/'config'
    require(list((config/'renewal').glob('*.conf')) == [config/'renewal'/f'{NAME}.conf'])
    require(sorted(p.name for p in (config/'live').iterdir()) == ['README', NAME])
    live, archive = config/'live'/NAME, config/'archive'/NAME
    expected = {f'{kind}{n}.pem' for kind in ('cert', 'chain', 'fullchain', 'privkey') for n in range(1, version+1)}
    require({p.name for p in archive.iterdir()} == expected)
    for kind in ('cert', 'chain', 'fullchain', 'privkey'):
        require((live/f'{kind}.pem').is_symlink())
        require((live/f'{kind}.pem').resolve() == archive/f'{kind}{version}.pem')
    return {p.name: p.read_bytes() for p in archive.iterdir()}


def renewal_settings(path):
    # Certbot caches an ARI retry time even when the directory has no ARI.
    # Permit only this bookkeeping; preserve every other setting, including
    # account/server/authenticator/webroot and any due-date override.
    return tuple(line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')
                 and line.strip() != '[acme_renewal_info]'
                 and not line.strip().startswith('ari_retry_after ='))


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
    print('Real client: Certbot 5.6.0; ordinary renew skip then forced renew; isolated SQLite', flush=True)
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
                stage[0] = 'initial-evidence'
                with sqlite3.connect(root/'anopki.db') as db:
                    first = verify_orders(db, 1)
                    issuers = db.execute('SELECT certificate_pem FROM issuers').fetchall()
                require(len(issuers) == 1)
                (root/'issuer.pem').write_text(issuers[0][0])
                account = account_state(root)
                initial_archive = lineage_state(root, 1)
                renewal_config = root/'config/renewal'/f'{NAME}.conf'
                saved_config = renewal_settings(renewal_config)
                # The renewal invocation supplies no server, domain, account or
                # authenticator: Certbot must recover them from its saved state.
                renew = [str(certbot), 'renew', *common, '--cert-name', NAME, '--no-random-sleep-on-renew']
                run(renew, 'ordinary-renew')
                stage[0] = 'ordinary-skip-evidence'
                with sqlite3.connect(root/'anopki.db') as db:
                    require(verify_orders(db, 1) == first)
                stage[0] = 'ordinary-skip-archive'
                require(lineage_state(root, 1) == initial_archive)
                stage[0] = 'ordinary-skip-account'
                require(account_state(root) == account)
                stage[0] = 'ordinary-skip-config'
                require(renewal_settings(renewal_config) == saved_config)
                stage[0] = 'ordinary-skip-result'
                require(b'Certificate not yet due for renewal' in (root/'ordinary-renew.log').read_bytes())
                print('Ordinary renew: not due; one order, version 1 and account unchanged', flush=True)
                run([*renew, '--force-renewal'], 'forced-renew')
                stage[0] = 'forced-renew-evidence'
                require(service.poll() is None and account_state(root) == account)
                require(renewal_settings(renewal_config) == saved_config)
                archive = lineage_state(root, 2)
                require(all(archive[k] == v for k, v in initial_archive.items()))
                with sqlite3.connect(root/'anopki.db') as db:
                    both = verify_orders(db, 2)
                require(all(both[k] == v for k, v in first.items()))
                new = set(both)-set(first)
                require(len(new) == 1)
                for name, content in archive.items():
                    (root/name).write_bytes(content)
                verify_certificates(root, [next(iter(first.values()))[1], both[new.pop()][1]])
                print('Forced renew: same account and lineage; two valid orders with fresh HTTP-01 authorizations; archive/live advanced to version 2', flush=True)
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
        with tempfile.TemporaryDirectory(prefix='acme-renewal.', dir=pathlib.Path('.tmp').resolve()) as tmp:
            exercise(pathlib.Path(tmp), args.certbot.resolve(), args.core.resolve(), stage)
    except Exception:
        # Never print subprocess output, exception details, JWS, DB rows or keys.
        print(f'Real Certbot renewal failed at stage: {stage[0]}', file=sys.stderr)
        return 1
    print('Real Certbot forced renewal and OpenSSL verification passed; private state removed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
