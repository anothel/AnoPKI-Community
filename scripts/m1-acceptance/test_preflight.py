# SPDX-License-Identifier: MPL-2.0
from configparser import ConfigParser
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


RUNNER = Path(__file__).with_name("run.py")


class PreflightTest(unittest.TestCase):
    def run_without_binaries(self, *args):
        env = os.environ | {"ANOPKI_CORE_BIN": "", "ANOPKI_SERVICE_BIN": "",
                            "ANOPKI_DB_DSN": "must-not-appear-in-evidence"}
        result = subprocess.run(
            [sys.executable, str(RUNNER), *args], env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("must-not-appear-in-evidence", result.stdout)
        return json.loads(result.stdout)

    def test_live_requires_explicit_runner_authorization(self):
        report = self.run_without_binaries("--live")
        self.assertEqual(report["live"], "NOT_RUN")
        self.assertEqual(report["reason"], "--authorized-runner is required for live execution")
        self.assertEqual(report["cleanup"], "no live resources created")

    def test_fixture_preflight_cannot_count_as_live_acceptance(self):
        report = self.run_without_binaries()
        self.assertEqual(report["preflight"], "NOT_RUN")
        self.assertIn("ANOPKI_CORE_BIN", report["missing"])
        self.assertEqual(report["live"], "NOT_RUN")
        self.assertTrue(report["cases"])
        self.assertTrue(all(case["status"] == "NOT_RUN" for case in report["cases"]))
        self.assertEqual(report["cleanup"], "no live resources created")

    def test_fixture_has_matching_dns_ip_and_ca_signing_constraints(self):
        config = ConfigParser()
        with RUNNER.with_name("openssl.cnf").open(encoding="ascii") as fixture:
            config.read_file(fixture)
        self.assertEqual(config[config["req"]["distinguished_name"]]["CN"], "edge-01")
        self.assertEqual(config[config["req"]["req_extensions"]]["subjectAltName"],
                         "DNS:edge-01.example.test,IP:127.0.0.1")
        self.assertEqual(config["ca"]["basicConstraints"], "critical,CA:TRUE,pathlen:0")
        self.assertEqual(config["ca"]["keyUsage"], "critical,keyCertSign,cRLSign")


if __name__ == "__main__":
    unittest.main()
