#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for the PostgreSQL recovery drill."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "verify-postgres-recovery-drill.py"
SPEC = importlib.util.spec_from_file_location("postgres_recovery_drill", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load PostgreSQL recovery drill")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def main() -> None:
    config = MODULE.parse_postgres_dsn(
        "postgres://anopki:secret@localhost:5432/anopki_test?sslmode=disable"
    )
    public_uri = MODULE.build_postgres_uri(config, "anopki_recovery_test", include_password=False)
    private_uri = MODULE.build_postgres_uri(config, "anopki_recovery_test", include_password=True)
    assert "secret" not in public_uri
    assert "secret" in private_uri

    assert MODULE.parse_go_version("go version go1.25.12 linux/amd64") == (1, 25, 12)
    assert MODULE.parse_postgres_major("psql (PostgreSQL) 16.9") == 16
    assert MODULE.parse_postgres_major("pg_dump (PostgreSQL) 17.1") == 17

    try:
        MODULE.resolve_commit(ROOT, "bad")
    except MODULE.DrillFailure:
        pass
    else:
        raise AssertionError("invalid commit passed")

    with tempfile.TemporaryDirectory() as dirname:
        out = Path(dirname)
        evidence = MODULE.evidence_template("a" * 40)
        evidence["blocker"] = MODULE.SENSITIVE_FIXTURES[0]
        try:
            MODULE.write_evidence(out, evidence)
        except MODULE.DrillFailure:
            pass
        else:
            raise AssertionError("sensitive evidence was written")

    with tempfile.TemporaryDirectory() as dirname:
        out = Path(dirname)
        evidence = MODULE.run_drill(ROOT, out, "go", "", "b" * 40)
        assert evidence["result"] == "failed"
        assert "DSN is required" in evidence["blocker"]
        written = json.loads((out / "postgres-recovery-verification.json").read_text(encoding="utf-8"))
        assert written["evidence_type"] == "community_postgres_recovery_drill"
        assert len(written["checks"]) == len(MODULE.EXPECTED_CHECKS)

    print("PostgreSQL recovery drill tests passed: 5")


if __name__ == "__main__":
    main()
