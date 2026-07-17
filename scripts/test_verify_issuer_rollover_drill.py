#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for the intermediate issuer rollover drill."""

from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "verify-issuer-rollover-drill.py"
SPEC = importlib.util.spec_from_file_location("issuer_rollover_drill", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load issuer rollover drill")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def fake_go(path: Path, *, version: str = "go1.25.12", failing_test: str = "", omitted_test: str = "") -> Path:
    events = []
    for package, test in MODULE.EXPECTED_TESTS:
        if test == omitted_test:
            continue
        events.append(json.dumps({"Action": "fail" if test == failing_test else "pass", "Package": package, "Test": test}))
    output = "\n".join(events)
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'version': print('go version {version} linux/amd64'); raise SystemExit(0)\n"
        f"if sys.argv[1] == 'test': print({output!r}); raise SystemExit({1 if failing_test else 0})\n"
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
        written = json.loads((root / "out" / "issuer-rollover-verification.json").read_text(encoding="utf-8"))
        assert len(written["checks"]) == 10

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", str(fake_go(root / "go", version="go1.23.2")), "b" * 40)
        assert evidence["result"] == "failed"
        assert not evidence["tests"]

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", str(fake_go(root / "go", failing_test=MODULE.EXPECTED_TESTS[0][1])), "c" * 40)
        assert evidence["result"] == "failed"

    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        evidence = MODULE.run_drill(ROOT, root / "out", str(fake_go(root / "go", omitted_test=MODULE.EXPECTED_TESTS[1][1])), "d" * 40)
        assert evidence["result"] == "failed"

    try:
        MODULE.resolve_commit(ROOT, "bad")
    except MODULE.DrillFailure:
        pass
    else:
        raise AssertionError("invalid commit passed")

    print("issuer rollover drill tests passed: 5")


if __name__ == "__main__":
    main()
