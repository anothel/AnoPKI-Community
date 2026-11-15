#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Reject release SBOMs missing shipped Go dependency inventory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_MODULES = (
    "pkg:golang/github.com/jackc/pgx/v5@",
    "pkg:golang/modernc.org/sqlite@",
)


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def validate(path: Path) -> None:
    try:
        if path.stat().st_size > 25_000_000:
            fail("release SBOM exceeds the size limit")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"missing or invalid release SBOM: {exc}")
    if (
        not isinstance(data, dict)
        or data.get("bomFormat") != "CycloneDX"
        or data.get("specVersion") != "1.6"
    ):
        fail("release SBOM identity is invalid")
    components = data.get("components")
    if not isinstance(components, list) or not components:
        fail("release SBOM has no catalogued dependencies")
    if not all(isinstance(component, dict) for component in components):
        fail("release SBOM components have invalid shape")
    purls = [
        component.get("purl")
        for component in components
        if isinstance(component.get("purl"), str)
    ]
    missing = [
        module
        for module in REQUIRED_MODULES
        if not any(purl.startswith(module) for purl in purls)
    ]
    if missing:
        fail("release SBOM missing shipped Go module inventory: " + ", ".join(missing))
    print(f"release SBOM ok: {len(components)} components")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate-release-sbom.py path/to/anopki.sbom.cdx.json")
    validate(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
