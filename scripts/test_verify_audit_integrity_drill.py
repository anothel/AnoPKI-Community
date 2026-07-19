#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for the Audit hash-chain integrity verification drill."""

from __future__ import annotations

import importlib.util
import json
import stat
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
) -> Path:
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
    baseline_output = "\n".join(baseline_events)
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'version': print('go version {version} linux/amd64'); raise SystemExit(0)\n"
        "if sys.argv[1] == 'test':\n"
        "    command = ' '.join(sys.argv)\n"
        f"    if 'TestPostgresIntegrationRepositoryParity' in command: print({postgres_event!r}); print(__import__('os').environ.get('ANOPKI_POSTGRES_TEST_DSN', '')); raise SystemExit({0 if postgres_status == 'pass' else 1})\n"
        f"    print({baseline_output!r}); print({sensitive_output!r}); raise SystemExit({1 if failing_test else 0})\n"
        "raise SystemExit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def main() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", str(fake_go(root / "go")), "a" * 40)
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
                str(fake_go(root / "go")),
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
        postgres_log = (root / "out" / "audit-integrity-postgres-test.log").read_text(encoding="utf-8")
        assert "postgres://redacted" not in serialized
        assert "postgres://redacted" not in postgres_log
        assert "<postgres-dsn>" in postgres_log

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            str(fake_go(root / "go", version="go1.23.2")),
            "c" * 40,
        )
        assert evidence["result"] == "failed"
        assert not evidence["tests"]

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            str(fake_go(root / "go", failing_test=MODULE.BASELINE_TESTS[0][1])),
            "d" * 40,
        )
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(
            ROOT,
            root / "out",
            str(fake_go(root / "go", omitted_test=MODULE.BASELINE_TESTS[1][1])),
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
                str(fake_go(root / "go", postgres_status="fail")),
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
            str(fake_go(root / "go", sensitive_output="-----BEGIN " + "PRIVATE KEY-----")),
            "1" * 40,
        )
        assert evidence["result"] == "failed"
        assert evidence["redaction"]["private_key_markers_found"] is True
        assert evidence["checks"][-1]["status"] == "failed"

    try:
        MODULE.resolve_commit(ROOT, "bad")
    except MODULE.DrillFailure:
        pass
    else:
        raise AssertionError("invalid commit passed")

    print("Audit integrity drill tests passed: 8")


if __name__ == "__main__":
    main()
