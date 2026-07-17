#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-tests for the SQLite recovery drill."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-recovery-drill.py"
SPEC = importlib.util.spec_from_file_location("verify_recovery_drill", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def context(work_dir: Path):
    migration = (ROOT / MODULE.MIGRATION).read_bytes()
    return MODULE.DrillContext(
        root=ROOT,
        work_dir=work_dir,
        migration_checksum=MODULE.sha256_bytes(migration),
        commit="a" * 40,
    )


def test_successful_drill_writes_redacted_evidence() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "evidence"
        evidence = MODULE.run_drill(ROOT, out, "a" * 40)
        json_text = (out / "recovery-verification.json").read_text(encoding="utf-8")
        markdown = (out / "recovery-verification.md").read_text(encoding="utf-8")
    assert evidence["result"] == "passed"
    assert evidence["state_counts"] == MODULE.EXPECTED_COUNTS
    assert len(evidence["checks"]) == 11
    assert json.loads(json_text)["commit"] == "a" * 40
    combined = (json_text + markdown).lower()
    for sensitive in MODULE.SENSITIVE_FIXTURES:
        assert sensitive.lower() not in combined
    assert "begin private key" not in combined


def test_dirty_schema_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        ctx = context(work)
        db_path = work / "dirty.db"
        MODULE.initialize_database(ctx, db_path)
        with MODULE.connect(db_path) as db:
            expected = MODULE.state_digest(db)
            db.execute("UPDATE schema_migrations SET dirty = 1")
        try:
            MODULE.verify_restored_database(ctx, db_path, expected)
        except MODULE.DrillFailure as exc:
            assert "dirty" in str(exc) or "migration" in str(exc)
        else:
            raise AssertionError("dirty schema unexpectedly passed")


def test_missing_crl_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        ctx = context(work)
        db_path = work / "missing-crl.db"
        MODULE.initialize_database(ctx, db_path)
        with MODULE.connect(db_path) as db:
            expected = MODULE.state_digest(db)
            db.execute("DELETE FROM crl_publications")
        try:
            MODULE.verify_restored_database(ctx, db_path, expected)
        except MODULE.DrillFailure as exc:
            assert "state digest" in str(exc) or "CRL" in str(exc)
        else:
            raise AssertionError("missing CRL unexpectedly passed")


def test_private_key_marker_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        ctx = context(work)
        db_path = work / "private-key.db"
        MODULE.initialize_database(ctx, db_path)
        with MODULE.connect(db_path) as db:
            db.execute(
                "UPDATE audit_events SET metadata_json = ? WHERE id = ?",
                (MODULE.PRIVATE_KEY_MARKERS[0].decode("ascii"), "audit-restore-1"),
            )
            expected = MODULE.state_digest(db)
        try:
            MODULE.verify_restored_database(ctx, db_path, expected)
        except MODULE.DrillFailure as exc:
            assert "private-key" in str(exc)
        else:
            raise AssertionError("private-key marker unexpectedly passed")


def test_invalid_commit_is_rejected() -> None:
    try:
        MODULE.resolve_commit(ROOT, "not-a-commit")
    except MODULE.DrillFailure as exc:
        assert "40-character" in str(exc)
    else:
        raise AssertionError("invalid commit unexpectedly passed")


def main() -> None:
    tests = [
        test_successful_drill_writes_redacted_evidence,
        test_dirty_schema_fails_closed,
        test_missing_crl_fails_closed,
        test_private_key_marker_fails_closed,
        test_invalid_commit_is_rejected,
    ]
    for test in tests:
        test()
    print(f"recovery drill tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
