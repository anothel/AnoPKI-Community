#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-tests for the Community authorization boundary evidence runner."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_authorization_boundary",
    ROOT / "scripts" / "verify-authorization-boundary.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fake_go(root: Path, *, version: str = "go1.25.12", fail: str = "", omit: str = "", race_fail: bool = False, sensitive: str = "") -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    script = root / "fake-go.py"
    payload = {
        "version": version,
        "tests": list(MODULE.TESTS),
        "package": MODULE.PACKAGE,
        "fail": fail,
        "omit": omit,
        "race_fail": race_fail,
        "sensitive": sensitive,
    }
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"P={json.dumps(payload)!r}\n"
        "P=json.loads(P)\n"
        "if len(sys.argv)>1 and sys.argv[1]=='version':\n"
        " print('go version '+P['version']+' linux/amd64'); raise SystemExit(0)\n"
        "race='-race' in sys.argv\n"
        "if P['sensitive']: print(P['sensitive'])\n"
        "code=0\n"
        "for name in P['tests']:\n"
        " if name==P['omit']: continue\n"
        " action='pass'\n"
        " if name==P['fail'] or (race and P['race_fail']): action='fail'; code=1\n"
        " print(json.dumps({'Action':action,'Package':P['package'],'Test':name}))\n"
        "raise SystemExit(code)\n",
        encoding="utf-8",
    )
    return [os.sys.executable, str(script)]


def main() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go"), "a" * 40)
        assert evidence["result"] == "passed"
        assert len(evidence["tests"]) == len(MODULE.TESTS) * 2
        assert all(check["status"] == "passed" for check in evidence["checks"])

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", version="go1.23.2"), "b" * 40)
        assert evidence["result"] == "failed"
        assert not evidence["tests"]

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", fail=MODULE.TESTS[0]), "c" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", omit=MODULE.TESTS[1]), "d" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", race_fail=True), "e" * 40)
        assert evidence["result"] == "failed"
        assert evidence["checks"][-2]["status"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", fake_go(root / "go", sensitive="raw-token-secret"), "f" * 40)
        assert evidence["result"] == "failed"
        assert evidence["redaction"]["request_payload_values_found"] is True

    try:
        MODULE.resolve_commit(ROOT, "bad")
    except MODULE.DrillFailure:
        pass
    else:
        raise AssertionError("invalid commit passed")

    print("authorization boundary drill tests passed: 7")


if __name__ == "__main__":
    main()
