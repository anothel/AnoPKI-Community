# SPDX-License-Identifier: MPL-2.0
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

RUNNER = pathlib.Path(__file__).with_name('run_live_renewal.py')


def load_runner():
    spec = importlib.util.spec_from_file_location('runner', RUNNER)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


class RunnerTests(unittest.TestCase):
    def test_wrong_version_fails_privately_and_removes_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake = root/'certbot'
            fake.write_text('#!/bin/sh\necho PRIVATE-OUTPUT-MARKER >&2\necho "certbot 0.0.0"\n')
            fake.chmod(0o700)
            result = subprocess.run([sys.executable, str(RUNNER), str(fake), '/bin/false'],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('stage: versions', result.stderr)
            self.assertNotIn('PRIVATE-OUTPUT-MARKER', result.stdout+result.stderr)
            self.assertEqual(list((root/'.tmp').iterdir()), [])

    def test_failed_stage_stops_child(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with self.assertRaisesRegex(ValueError, 'stage failed'):
                with runner.private_process([sys.executable, '-c', 'import time; time.sleep(60)'],
                                            root/'private.log', os.environ.copy()) as process:
                    self.assertIsNone(process.poll())
                    raise ValueError('stage failed')
            self.assertIsNotNone(process.poll())

    def test_renewal_settings_preserved_allowing_only_ari_cache(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)/'renewal.conf'
            initial = 'version = 5.6.0\n[renewalparams]\naccount = saved\nserver = http://127.0.0.1/acme/directory\nauthenticator = webroot\n'
            path.write_text(initial)
            expected = runner.renewal_settings(path)
            path.write_text(initial+'\n[acme_renewal_info]\nari_retry_after = 2026-11-17T00:00:00\n')
            self.assertEqual(runner.renewal_settings(path), expected)
            for extra in ['renew_before_expiry = 2 days\n', 'account = other\n', 'server = other\n']:
                path.write_text(initial+extra)
                self.assertNotEqual(runner.renewal_settings(path), expected)

    def test_lineage_requires_all_live_links_to_advance_together(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = root/'config'
            live = config/'live'/runner.NAME
            archive = config/'archive'/runner.NAME
            live.mkdir(parents=True)
            archive.mkdir(parents=True)
            (config/'renewal').mkdir()
            (config/'renewal'/f'{runner.NAME}.conf').write_text('saved settings')
            (config/'live/README').touch()
            for version in (1, 2):
                for kind in ('cert', 'chain', 'fullchain', 'privkey'):
                    (archive/f'{kind}{version}.pem').write_text(f'{kind}-{version}')
                    link = live/f'{kind}.pem'
                    link.unlink(missing_ok=True)
                    link.symlink_to(archive/f'{kind}{version}.pem')
                self.assertEqual(len(runner.lineage_state(root, version)), 4*version)
            for kind in ('cert', 'chain', 'fullchain', 'privkey'):
                link = live/f'{kind}.pem'
                link.unlink()
                link.symlink_to(archive/f'{kind}1.pem')
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    runner.lineage_state(root, 2)
                link.unlink()
                link.symlink_to(archive/f'{kind}2.pem')


if __name__ == '__main__':
    unittest.main()
