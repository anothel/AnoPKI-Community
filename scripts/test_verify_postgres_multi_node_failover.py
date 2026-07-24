#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-tests for the PostgreSQL multi-node failover evidence runner."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_postgres_multi_node_failover",
    ROOT / "scripts" / "verify-postgres-multi-node-failover.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@contextmanager
def dsn(value: str):
    previous = os.environ.get(MODULE.DSN_ENV)
    if value:
        os.environ[MODULE.DSN_ENV] = value
    else:
        os.environ.pop(MODULE.DSN_ENV, None)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(MODULE.DSN_ENV, None)
        else:
            os.environ[MODULE.DSN_ENV] = previous


def fake_go(root: Path, *, version: str = "go1.25.12", fail: str = "", omit: str = "", skip: str = "", sensitive: str = "") -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    script = root / "fake-go.py"
    payload = {
        "version": version,
        "tests": list(MODULE.TESTS),
        "package": MODULE.PACKAGE,
        "fail": fail,
        "omit": omit,
        "skip": skip,
        "sensitive": sensitive,
    }
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"P={json.dumps(payload)!r}\n"
        "P=json.loads(P)\n"
        "if len(sys.argv)>1 and sys.argv[1]=='version':\n"
        " print('go version '+P['version']+' linux/amd64'); raise SystemExit(0)\n"
        "if P['sensitive']: print(P['sensitive'])\n"
        "code=0\n"
        "for name in P['tests']:\n"
        " if name==P['omit']: continue\n"
        " action='pass'\n"
        " if name==P['fail']: action='fail'; code=1\n"
        " if name==P['skip']: action='skip'\n"
        " print(json.dumps({'Action':action,'Package':P['package'],'Test':name}))\n"
        "raise SystemExit(code)\n",
        encoding="utf-8",
    )
    return [os.sys.executable, str(script)]


def main() -> None:
    test_dsn = "postgres://operator:secret@localhost:5432/anopki?sslmode=disable"

    with tempfile.TemporaryDirectory() as dirname, dsn(test_dsn):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go"), "a" * 40)
        assert evidence["result"] == "passed"
        assert len(evidence["tests"]) == len(MODULE.TESTS)
        assert all(check["status"] == "passed" for check in evidence["checks"])
        combined = "\n".join(path.read_text(encoding="utf-8") for path in (root / "out").iterdir())
        assert test_dsn not in combined
        assert "postgres://" not in combined.lower()

    with tempfile.TemporaryDirectory() as dirname, dsn(""):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go"), "b" * 40)
        assert evidence["result"] == "failed"
        assert MODULE.DSN_ENV in evidence["blocker"]

    with tempfile.TemporaryDirectory() as dirname, dsn(test_dsn):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", version="go1.23.2"), "c" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname, dsn(test_dsn):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", fail=MODULE.TESTS[0]), "d" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname, dsn(test_dsn):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", omit=MODULE.TESTS[1]), "e" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname, dsn(test_dsn):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", skip=MODULE.TESTS[2]), "f" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname, dsn(test_dsn):
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", sensitive="-----BEGIN " + "PRIVATE KEY-----"), "1" * 40)
        assert evidence["result"] == "failed"
        assert evidence["redaction"]["private_key_markers_found"] is True

    try:
        MODULE.resolve_commit(ROOT, "bad")
    except MODULE.DrillFailure:
        pass
    else:
        raise AssertionError("invalid commit passed")

    print("PostgreSQL multi-node failover drill tests passed: 8")


if __name__ == "__main__":
    main()
