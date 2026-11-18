#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for the Audit hash-chain integrity verification drill."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "verify-audit-integrity-drill.py"
SPEC = importlib.util.spec_from_file_location("audit_integrity_drill", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load Audit integrity drill")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def fake_go(
    path: Path,
    *,
    version: str = "go1.25.12",
    failing_test: str = "",
    omitted_test: str = "",
    postgres_status: str = "pass",
    sensitive_output: str = "",
    exit_code: int = 0,
    incomplete: bool = False,
) -> list[str]:
    baseline_events = []
    for package, test in MODULE.BASELINE_TESTS:
        if test == omitted_test:
            continue
        baseline_events.append(
            json.dumps(
                {
                    "Action": "fail" if test == failing_test else "pass",
                    "Package": package,
                    "Test": test,
                }
            )
        )
    postgres_action = postgres_status
    postgres_event = json.dumps(
        {
            "Action": postgres_action,
            "Package": MODULE.POSTGRES_TEST[0],
            "Test": MODULE.POSTGRES_TEST[1],
        }
    )
    for package in sorted({package for package, _ in MODULE.BASELINE_TESTS}):
        if not incomplete:
            baseline_events.append(json.dumps({"Action": "fail" if failing_test else "pass", "Package": package}))
    baseline_output = "\n".join(baseline_events)
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'version': print('go version {version} linux/amd64'); raise SystemExit(0)\n"
        "if sys.argv[1] == 'test':\n"
        "    command = ' '.join(sys.argv)\n"
        f"    if 'TestPostgresIntegrationRepositoryParity' in command: print({postgres_event!r}); print({json.dumps({"Action": postgres_status, "Package": MODULE.POSTGRES_TEST[0]})!r}); print(__import__('os').environ.get('ANOPKI_POSTGRES_TEST_DSN', '')); raise SystemExit({0 if postgres_status == 'pass' else 1})\n"
        f"    print({baseline_output!r}); print({sensitive_output!r}); raise SystemExit({1 if failing_test else exit_code})\n"
        "raise SystemExit(2)\n",
        encoding="utf-8",
    )
    return [sys.executable, str(path)]


def main() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go"), "a" * 40)
        assert evidence["result"] == "passed"
        assert evidence["checks"][-2]["status"] == "not_run"
        written = json.loads((root / "out" / "audit-integrity-verification.json").read_text(encoding="utf-8"))
        assert len(written["checks"]) == len(MODULE.EXPECTED_CHECKS)

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        old = MODULE.os.environ.get(MODULE.POSTGRES_DSN_ENV)
        MODULE.os.environ[MODULE.POSTGRES_DSN_ENV] = "postgres://redacted"
        try:
            evidence = MODULE.run_drill(
                ROOT,
                root / "out",
                fake_go(root / "go"),
                "b" * 40,
                require_postgres=True,
            )
        finally:
            if old is None:
                MODULE.os.environ.pop(MODULE.POSTGRES_DSN_ENV, None)
            else:
                MODULE.os.environ[MODULE.POSTGRES_DSN_ENV] = old
        assert evidence["result"] == "passed"
        assert evidence["checks"][-2]["status"] == "passed"
        serialized = (root / "out" / "audit-integrity-verification.json").read_text(encoding="utf-8")
        postgres_log = serialized
        assert "postgres://redacted" not in serialized
        assert "postgres://redacted" not in postgres_log
        assert not list((root / "out").glob("*.log"))

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            fake_go(root / "go", version="go1.23.2"),
            "c" * 40,
        )
        assert evidence["result"] == "failed"
        assert not evidence["tests"]

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            fake_go(root / "go", failing_test=MODULE.BASELINE_TESTS[0][1]),
            "d" * 40,
        )
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            fake_go(root / "go", omitted_test=MODULE.BASELINE_TESTS[1][1]),
            "e" * 40,
        )
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        old = MODULE.os.environ.get(MODULE.POSTGRES_DSN_ENV)
        MODULE.os.environ[MODULE.POSTGRES_DSN_ENV] = "postgres://redacted"
        try:
            evidence = MODULE.run_drill(
                ROOT,
                root / "out",
                fake_go(root / "go", postgres_status="fail"),
                "f" * 40,
                require_postgres=True,
            )
        finally:
            if old is None:
                MODULE.os.environ.pop(MODULE.POSTGRES_DSN_ENV, None)
            else:
                MODULE.os.environ[MODULE.POSTGRES_DSN_ENV] = old
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            fake_go(root / "go", sensitive_output="-----BEGIN " + "PRIVATE KEY-----"),
            "1" * 40,
        )
        assert evidence["result"] == "failed"
        assert evidence["redaction"]["private_key_markers_found"] is True
        assert evidence["checks"][-1]["status"] == "failed"

    for options, expected in [
        ({"failing_test": MODULE.BASELINE_TESTS[0][1]}, "failed"),
        ({"omitted_test": MODULE.BASELINE_TESTS[1][1]}, "missing"),
        ({"exit_code": 7}, "nonzero_exit"),
        ({"incomplete": True}, "incomplete"),
    ]:
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", **options), "a" * 40)
            written = json.loads((root / "out" / "audit-integrity-verification.json").read_text())
            assert written["result"] == "failed"
            assert written["stages"]["baseline"]["status"] == expected
            assert written["stages"]["baseline"]["exit_code"] == options.get("exit_code", 1 if "failing_test" in options else 0)
            assert not list((root / "out").glob("*.log"))

    for secret in ["password=hunter2", "Authorization: Bearer secret", "token=abc", "postgresql://user:pass@host/db", "-----BEGIN " + "PRIVATE KEY-----"]:
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", sensitive_output=secret), "a" * 40)
            assert evidence["result"] == "failed"
            assert evidence["redaction"]["sensitive_values_in_evidence"]
            assert all(secret not in p.read_text() for p in (root / "out").iterdir())
            MODULE.validate_evidence(root / "out")
            report = root / "out" / "audit-integrity-verification.json"
            report.write_text(report.read_text().replace('"blocker":', '"injected": "unknown-secret", "blocker":'))
            try:
                MODULE.validate_evidence(root / "out")
            except MODULE.DrillFailure:
                pass
            else:
                raise AssertionError("untrusted evidence accepted")

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", [str(root / "missing-go")], "a" * 40)
        assert evidence["result"] == "failed"
        assert evidence["stages"]["toolchain"]["status"] == "setup_error"

    try:
        MODULE.resolve_commit(ROOT, "bad")
    except MODULE.DrillFailure:
        pass
    else:
        raise AssertionError("invalid commit passed")

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        MODULE.run_drill(ROOT, root / "out", fake_go(root / "go"), "a" * 40)
        report = root / "out" / "audit-integrity-verification.json"
        value = json.loads(report.read_text())
        value["blocker"] = 98765432100123456789
        report.write_text(json.dumps(value))
        try:
            MODULE.validate_evidence(root / "out")
        except MODULE.DrillFailure:
            pass
        else:
            raise AssertionError("numeric payload accepted")

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        out = root / "out"
        MODULE.run_drill(ROOT, out, fake_go(root / "go", exit_code=7), "a" * 40)
        import subprocess
        result = subprocess.run([sys.executable, str(RUNNER), "--validate-evidence", "--out-dir", str(out)], capture_output=True)
        assert result.returncode == 0
        assert json.loads((out / "audit-integrity-verification.json").read_text())["stages"]["baseline"]["exit_code"] == 7
        (out / "audit-integrity-verification.json").unlink()
        result = subprocess.run([sys.executable, str(RUNNER), "--validate-evidence", "--out-dir", str(out)], capture_output=True)
        assert result.returncode != 0

    workflow = (ROOT / ".github/workflows/ci.yml").read_text().split("  audit-integrity-drill:", 1)[1].split("  authorization-boundary-drill:", 1)[0]
    assert "--validate-evidence" in workflow
    assert "steps.audit-evidence.outcome == 'success'" in workflow
    assert "if: ${{ !cancelled() }}" in workflow
    assert "path: |" in workflow
    assert "audit-integrity-verification.json" in workflow
    assert "audit-integrity-verification.md" in workflow

    print("Audit integrity drill self-checks passed (success, failure, missing, exit, incomplete, secrets, setup, validation)")


if __name__ == "__main__":
    main()
