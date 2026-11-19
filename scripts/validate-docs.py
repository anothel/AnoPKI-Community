#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Cheap docs-as-code checks for the PKI documentation baseline."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
SOURCE_HEADER_EXTENSIONS = {".cpp", ".go", ".hpp", ".ps1", ".py"}
SOURCE_HEADER_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".gocache",
    ".gomodcache",
    ".tmp",
    ".tmp-gocache",
    ".vscode",
    "build",
    "build-fuzz",
    "build-release",
}


LEGACY_IDENTIFIER_ALLOWED_PATHS = {
    "CHANGELOG.md",
    "docs/adr/0005-project-rename-to-anopki.md",
    "docs/reference/project-identity-and-license.md",
    "docs/runbooks/anopki-rename-migration.md",
}
LEGACY_IDENTIFIER_TOKENS = (
    "modern" + "-pki",
    "MODERN" + "_PKI",
    "X-Modern" + "-PKI",
)
LEGACY_SCAN_EXTENSIONS = {
    "",
    ".cpp",
    ".go",
    ".hpp",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".txt",
    ".yaml",
    ".yml",
}
LEGACY_SCAN_FILENAMES = {
    ".env.example",
    ".gitignore",
    "CMakeLists.txt",
}

REQUIRED = [
    "LICENSE",
    "CHANGELOG.md",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/ROADMAP.md",
    "docs/INDEX.md",
    "docs/acme-client-compatibility.md",
    "docs/acme-rfc8555-conformance.md",
    "docs/architecture/pki-context.md",
    "docs/architecture/ca-hierarchy.md",
    "docs/architecture/issuance-flow.md",
    "docs/architecture/renewal-flow.md",
    "docs/architecture/revocation-flow.md",
    "docs/policy/certificate-profiles.md",
    "docs/policy/algorithm-policy.md",
    "docs/policy/cp-cps-map.md",
    "docs/operations/issuance-runbook.md",
    "docs/operations/renewal-runbook.md",
    "docs/operations/revocation-runbook.md",
    "docs/operations/mass-revocation-plan.md",
    "docs/operations/key-ceremony.md",
    "docs/operations/backup-restore-runbook.md",
    "docs/runbooks/production-hardening-checklist.md",
    "docs/security/threat-model.md",
    "docs/security/access-model.md",
    "docs/security/audit-log-schema.md",
    "docs/security/audit-tamper-evidence.md",
    "docs/security/key-provider-semantics.md",
    "docs/security/siem-detections.md",
    "docs/adr/0001-ca-backend-selection.md",
    "docs/adr/0002-acme-adoption.md",
    "docs/adr/0003-hsm-kms-strategy.md",
    "docs/reference/improvement-analysis-alignment.md",
    "docs/reference/release-readiness-action-plan.md",
    "docs/reference/core-cli-contract.md",
    "docs/reference/core-boundary-integration.md",
    "docs/reference/api-surface-status.md",
    "docs/reference/fuzzing.md",
    "docs/reference/release-evidence.md",
    "docs/reference/openapi.json",
    "docs/reference/project-identity-and-license.md",
    "docs/reference/source-file-header-policy.md",
    "docs/reference/documentation-governance.md",
    "docs/reference/crypto-backend-strategy.md",
    "docs/runbooks/anopki-rename-migration.md",
    "docs/adr/0004-license-change-to-mpl-2.0.md",
    "docs/adr/0005-project-rename-to-anopki.md",
    "docs/adr/0006-crypto-backend-direction-anocrypto.md",
    "docs/adr/0007-key-provider-signing-boundary.md",
]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def check_required_files(root: Path) -> None:
    missing = [path for path in REQUIRED if not (root / path).is_file()]
    if missing:
        fail("missing required docs:\n" + "\n".join(missing))


def check_openapi_json(root: Path) -> None:
    path = root / "docs/reference/openapi.json"
    try:
        with path.open(encoding="utf-8") as fh:
            json.load(fh)
    except json.JSONDecodeError as exc:
        fail(f"invalid OpenAPI JSON: {path}: {exc}")


ATX_HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$")
LIST_ITEM = re.compile(r"^[ \t]*(?:[-+*]|\d+[.)])[ \t]+")
INLINE_CODE_PATTERN = (
    r"(?<!\x60)(?P<ticks>\x60+)(?!\x60)"
    r"(?P<code>(?:(?!\n[ \t]*\n).)+?)(?<!\x60)(?P=ticks)(?!\x60)"
)
INLINE_CODE = re.compile(INLINE_CODE_PATTERN, re.S)
MARKDOWN_BLOCKS = re.compile(
    r"^ {0,3}(?P<fence>(?P<fence_char>[\x60~])(?P=fence_char){2,})(?!(?P=fence_char))"
    r"[^\n]*(?:\n|\Z).*?(?:^ {0,3}(?P=fence)(?P=fence_char)*[ \t]*$|\Z)"
    r"|<!--.*?(?:-->|\Z)|" + INLINE_CODE_PATTERN,
    re.M | re.S,
)
LINK_LABEL = r"(?:\\.|[^\[\]\\]|\[[^\[\]]*\])+?"
LINK_DESTINATION = r"<[^<>\n]*>|(?:\\.|[^\s()\\]|\([^\s()]*\))+"
LINK = re.compile(
    rf"(?<!\\)(?P<image>!)?\[(?P<label>{LINK_LABEL})\]"
    rf"(?:(?P<inline>\()[ \t\n]*(?P<destination>{LINK_DESTINATION})?"
    r"""(?:[ \t\n]+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?[ \t\n]*\)"""
    r"|\[(?P<reference>[^\[\]\n]*)\])?"
)
REFERENCE_DEFINITION = re.compile(
    rf"^ {{0,3}}\[(?P<label>[^\[\]\n]+)\]:[ \t]*(?:\n[ \t]*)?"
    rf"(?P<destination>{LINK_DESTINATION})(?=[ \t\n]|$)[^\n]*",
    re.MULTILINE,
)
INDEX_REPEAT = re.compile(r"<!--\s*index-repeat:\s*\S.+?-->")


def maintained_markdown(root: Path) -> list[Path]:
    docs = list(root.glob("*.md"))
    docs.extend(
        path for path in (root / "docs").rglob("*.md")
        if not is_generated_or_ignored_path(path, root)
        and "superpowers" not in path.relative_to(root / "docs").parts
    )
    docs.extend(path for path in (
        root / "service/README.md",
        root / "scripts/acme-smoke/README.md",
        *root.glob("tests/fixtures/*/README.md"),
    ) if path.is_file())
    return sorted(docs)


def markdown_blocks(text: str) -> str:
    """Blank fenced code and HTML comments while preserving line positions."""
    return MARKDOWN_BLOCKS.sub(lambda match: match[0] if match["ticks"] else mask_markdown(match), text)


def mask_markdown(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match[0])


def markdown_links(text: str) -> Iterator[tuple[int, int, str, bool]]:
    """Yield source line, zero-based column, destination and image flag."""
    text = INLINE_CODE.sub(mask_markdown, text)
    references = {}
    for definition in REFERENCE_DEFINITION.finditer(text):
        key = " ".join(definition["label"].casefold().split())
        references.setdefault(key, definition["destination"])
    text = REFERENCE_DEFINITION.sub(mask_markdown, text)
    def destination_for(match: re.Match[str]) -> str | None:
        destination = match["destination"]
        if not match["inline"]:
            key = " ".join((match["reference"] or match["label"]).casefold().split())
            destination = references.get(key)
        return destination

    for match in LINK.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        column = match.start() - text.rfind("\n", 0, match.start()) - 1
        destination = destination_for(match)
        if destination:
            yield line, column, destination, bool(match["image"])
            for nested in LINK.finditer(match["label"]):
                if nested["image"] and (image_destination := destination_for(nested)):
                    yield line + match["label"].count("\n", 0, nested.start()), column, image_destination, True


def heading_anchors(text: str) -> set[str]:
    anchors = set()
    used_slugs: set[str] = set()
    previous = ""
    for line in text.splitlines():
        markup = INLINE_CODE.sub(mask_markdown, line)
        anchors.update(re.findall(r"""<a\b[^>]*?\s(?:id|name)=["']([^"']+)["']""", markup, re.I))
        match = ATX_HEADING.match(line)
        heading = match[2] if match else ""
        if previous and re.fullmatch(r" {0,3}(?:=+|-+)[ \t]*", line):
            heading = previous
        previous = line.strip() if (
            not match and not line.startswith(("    ", "\t"))
            and not re.match(r"^\s*(?:[-*+]\s|[>|<])", line)
        ) else ""
        if not heading:
            continue
        parts = []
        start = 0
        for code in INLINE_CODE.finditer(heading):
            parts.append(heading_prose(heading[start:code.start()]))
            parts.append(code["code"])
            start = code.end()
        parts.append(heading_prose(heading[start:]))
        heading = "".join(parts).strip().lower()
        slug = "".join(
            "-" if char == " " else char
            for char in heading
            if char in " _-" or unicodedata.category(char)[0] in "LMN"
        )
        unique = slug
        suffix = 1
        while unique in used_slugs:
            unique = f"{slug}-{suffix}"
            suffix += 1
        used_slugs.add(unique)
    return anchors | used_slugs


def heading_prose(text: str) -> str:
    text = LINK.sub(lambda link: link["label"], text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"(?<!\w)(_+)(?=\S)(.+?)(?<=\S)\1(?!\w)", r"\2", text)
    return html.unescape(text)


def local_destination(root: Path, source: Path, destination: str) -> tuple[Path, str] | None:
    url = html.unescape(re.sub(r"\\([^\w\s])", r"\1", destination.strip("<>")))
    if url.startswith("//") or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url):
        return None
    path, _, fragment = url.partition("#")
    path = unquote(path.partition("?")[0])
    target = source
    if path:
        target = root / path.lstrip("/") if path.startswith("/") else source.parent / path
    return target.resolve(), unquote(fragment)


def is_index_entry(line: str, column: int) -> bool:
    if LIST_ITEM.match(line):
        return True
    # The first column contains navigation. Later columns are descriptions.
    prefix = line[:column].strip()
    return "|" in line[column:] and prefix in ("", "|")


def check_markdown_links(root: Path) -> None:
    problems = []
    anchors: dict[Path, set[str]] = {}
    index_targets: dict[tuple[Path, str], int] = {}
    for source in maintained_markdown(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_text(encoding="utf-8")
        text = markdown_blocks(raw)
        raw_lines = raw.splitlines()
        lines = text.splitlines()
        for line, column, destination, image in markdown_links(text):
            resolved = local_destination(root, source, destination)
            if resolved is None:
                continue
            target, fragment = resolved
            location = f"{relative}:{line}"
            if not target.is_relative_to(root) or not target.exists():
                problems.append(f"{location}: missing repository path: {destination}")
                continue
            if fragment and target.is_file() and target.suffix.lower() == ".md":
                if target not in anchors:
                    anchors[target] = heading_anchors(markdown_blocks(target.read_text(encoding="utf-8")))
                if fragment not in anchors[target]:
                    problems.append(f"{location}: missing heading or anchor: {destination}")
            if relative == "docs/INDEX.md" and not image and is_index_entry(lines[line - 1], column):
                first = index_targets.get(resolved)
                if first is None:
                    index_targets[resolved] = line
                elif not INDEX_REPEAT.search(raw_lines[line - 1]):
                    problems.append(
                        f"{location}: duplicate INDEX target {target.relative_to(root).as_posix()}"
                        f"{'#' + fragment if fragment else ''} (first at line {first})"
                    )
    if problems:
        fail("invalid documentation links:\n" + "\n".join(problems))


def check_license_state(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    if "No `LICENSE` file has been selected yet" in readme or "all rights are reserved" in readme:
        fail("README still says license is undecided")
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    if "Mozilla Public License Version 2.0" not in license_text or "mozilla.org/MPL/2.0" not in license_text:
        fail("LICENSE is not MPL-2.0 text")


def is_generated_or_ignored_path(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts
    return any(
        part in SOURCE_HEADER_SKIP_DIRS or part.startswith("build-")
        for part in parts
    )


def first_party_source_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if is_generated_or_ignored_path(path, root):
            continue
        if path.name == "CMakeLists.txt" or path.suffix in SOURCE_HEADER_EXTENSIONS:
            files.append(path)
    return files


def check_source_file_headers(root: Path) -> None:
    missing = []
    for path in first_party_source_files(root):
        head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:5])
        if "SPDX-License-Identifier: MPL-2.0" not in head:
            missing.append(str(path.relative_to(root)))
    if missing:
        fail("first-party source files missing SPDX header:\n" + "\n".join(sorted(missing)))


def check_readme_verify_local_commands(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    script = (root / "scripts/verify-local.ps1").read_text(encoding="utf-8")
    commands = re.findall(r'Display\s*=\s*"([^"]+)"', script)
    missing = [command for command in commands if command not in readme]
    if missing:
        fail("README quickstart missing verify-local commands:\n" + "\n".join(missing))


def check_readme_current_execution_state(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    if "unless public TLS issuance enables a linting hook" in readme:
        fail("README still treats public TLS lint hook as future work")
    stale_scope = [
        "external AnoCrypto-C capability parity",
        "selecting a real local provider only after deployment",
    ]
    stale = [text for text in stale_scope if text in readme]
    if stale:
        fail("README still contains non-Community execution focus:\n" + "\n".join(stale))


def roadmap_work_items(roadmap: str) -> list[tuple[int, str]]:
    """Collect list entries and their wrapped continuation lines."""
    items = []
    for number, line in enumerate(roadmap.splitlines(), start=1):
        if LIST_ITEM.match(line):
            items.append((number, LIST_ITEM.sub("", line)))
        elif items and line.startswith((" ", "\t")) and line.strip():
            start, text = items[-1]
            items[-1] = start, text + " " + line.strip()
    return items


def check_future_only_roadmap(root: Path) -> None:
    roadmap = markdown_blocks((root / "docs/ROADMAP.md").read_text(encoding="utf-8"))
    completed_heading = re.compile(
        r"^ {0,3}#{1,6}\s+(?:completed|delivered|shipped|done)\s*(?:$|[\s:—-])",
        re.I,
    )
    completed_item = re.compile(
        r"^(?:\[[xX]\](?:\s|$)|(?:completed|delivered|shipped|done)\s*:"
        r"|phase\s+\d+\s+(?:(?:is|was)\s+)?(?:complete[d]?|closed|shipped)\b)",
        re.I,
    )
    problems = [
        (number, line.strip()) for number, line in enumerate(roadmap.splitlines(), start=1)
        if completed_heading.match(line)
    ]
    problems.extend(
        (number, text) for number, text in roadmap_work_items(roadmap)
        if completed_item.match(text.lstrip("*_"))
    )
    if problems:
        fail("ROADMAP lists completed work; record delivery in CHANGELOG or evidence:\n" + "\n".join(
            f"docs/ROADMAP.md:{number}: {text}" for number, text in sorted(problems)
        ))


def check_anocrypto_direction(root: Path) -> None:
    strategy = (root / "docs/reference/crypto-backend-strategy.md").read_text(encoding="utf-8")
    adr = (root / "docs/adr/0006-crypto-backend-direction-anocrypto.md").read_text(encoding="utf-8")
    roadmap = (root / "docs/ROADMAP.md").read_text(encoding="utf-8")
    required = ["AnoCrypto-C", "OpenSSL", "backend-neutral"]
    missing = [text for text in required if text not in strategy + adr]
    if missing:
        fail("External adapter boundary docs missing required wording:\n" + "\n".join(missing))
    separate_project_rule = "Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles: Enterprise project."
    if separate_project_rule not in roadmap:
        fail("ROADMAP does not mention the external AnoCrypto-C adapter direction")
    stale_execution = [
        "Pin a real immutable AnoCrypto-C SDK artifact",
        "Expand the external AnoCrypto-C adapter",
        "Keep Enterprise/AnoCrypto-C production release blocked",
        "Add negative tests proving that unsupported AnoCrypto-C operations",
    ]
    work = "\n".join(text for _, text in roadmap_work_items(markdown_blocks(roadmap)))
    stale = [text for text in stale_execution if text in work]
    if stale:
        fail("ROADMAP still contains separate-project adapter execution work:\n" + "\n".join(stale))


def check_key_provider_direction(root: Path) -> None:
    adr = (root / "docs/adr/0007-key-provider-signing-boundary.md").read_text(encoding="utf-8")
    semantics = (root / "docs/security/key-provider-semantics.md").read_text(encoding="utf-8")
    roadmap = (root / "docs/ROADMAP.md").read_text(encoding="utf-8")
    adr_required = ["deliberately scoped hybrid", "FileKeyProvider", "Remote KMS", "test-only software-token"]
    semantics_required = [
        "deliberately scoped hybrid",
        "provider.invalid_reference",
        "test-only software-token resolver contract",
        "GET /version",
        "anopki-release-metadata.json",
    ]
    missing = [text for text in adr_required if text not in adr]
    missing += [text for text in semantics_required if text not in semantics]
    if missing:
        fail("KeyProvider signing direction docs missing required wording:\n" + "\n".join(missing))
    work = "\n".join(text for _, text in roadmap_work_items(markdown_blocks(roadmap)))
    stale_roadmap = [
        "Implement ADR 0007 certificate-issuance `FileKeyProvider` vertical slice",
        "Implement one file-provider signing vertical slice",
        "adapter that still reads file keys directly",
    ]
    stale = [text for text in stale_roadmap if text in work]
    if stale:
        fail("ROADMAP still lists the completed certificate FileKeyProvider slice:\n" + "\n".join(stale))
    completed_roadmap = ["Add a mock/software-token provider", "Add a PKCS#11 mock or software-token test path"]
    completed = [text for text in completed_roadmap if text in work]
    if completed:
        fail("ROADMAP still lists completed software-token contract work:\n" + "\n".join(completed))
    if re.search(r"^(?:Add|Complete|Implement) provider-result audit correlation\b", work, re.M):
        fail("ROADMAP still lists completed provider-result audit correlation work")
    if "Expose selected product profile and backend metadata through the Go service/version and release manifests" in work:
        fail("ROADMAP still lists completed service/release profile metadata work")
    remaining_scope = "Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision."
    if remaining_scope not in roadmap:
        fail("ROADMAP does not contain the remaining KeyProvider scope rule")
    if "Remove known warnings that prevent a clean whole-repository warning-as-error build." in work:
        fail("ROADMAP still lists completed whole-repository warning cleanup")

def should_scan_legacy_identifiers(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if is_generated_or_ignored_path(path, root):
        return False
    if str(rel).replace("\\", "/") in LEGACY_IDENTIFIER_ALLOWED_PATHS:
        return False
    return path.name in LEGACY_SCAN_FILENAMES or path.suffix in LEGACY_SCAN_EXTENSIONS


def check_legacy_identifier_scope(root: Path) -> None:
    hits: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or not should_scan_legacy_identifiers(path, root):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for token in LEGACY_IDENTIFIER_TOKENS:
            for line_number, line in enumerate(content.splitlines(), start=1):
                if token in line:
                    hits.append(f"{rel}:{line_number}: {token}")
    if hits:
        fail(
            "legacy project identifiers found outside migration or historical docs:\n"
            + "\n".join(sorted(hits))
        )

def check_ci_docs_validation_commands(root: Path) -> None:
    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    required = [
        "python scripts/validate-docs.py",
        "python scripts/test_validate_docs.py",
        "python scripts/test_verify_local.py",
    ]
    missing = [command for command in required if command not in ci]
    if missing:
        fail("CI docs job missing docs validation commands:\n" + "\n".join(missing))


def check_acme_compatibility_matrix(root: Path) -> None:
    compatibility = (root / "docs/acme-client-compatibility.md").read_text(encoding="utf-8")
    required = [
        "| Client | OS / shell | Account key | Challenge | Smoke result | Evidence |",
        "lego v4.35.2+dev-release",
        "Windows non-admin PowerShell",
        "| P-256 |",
        "lego v4.35.2+dev-release | Windows non-admin PowerShell | P-256 | HTTP-01 webroot | Pass",
        "certbot 5.6.0",
        "WSL Ubuntu, PowerShell 7.6.3",
        "| RSA |",
        "certbot 5.6.0 | WSL Ubuntu, PowerShell 7.6.3 | RSA | HTTP-01 webroot | Pass",
        "| HTTP-01 webroot | Pass |",
        "Successfully received certificate.",
        "| not reached |",
        "certbot 5.6.0 | Windows non-admin PowerShell | not reached | HTTP-01 webroot / standalone | Blocked before ACME traffic",
        "| HTTP-01 webroot / standalone | Blocked before ACME traffic |",
        "Blocked before ACME traffic",
        "certbot must be run on a shell with administrative rights",
    ]
    missing = [text for text in required if text not in compatibility]
    if missing:
        fail("ACME compatibility matrix missing required evidence:\n" + "\n".join(missing))


def check_current_release_and_client_status(root: Path) -> None:
    readme = markdown_blocks((root / "README.md").read_text(encoding="utf-8"))
    current_status = re.search(r"^## Current Status[ \t]*\n(.*?)(?=^#{1,6}\s|\Z)", readme, re.M | re.S)
    evidence_path = "docs/reference/release-evidence.md"
    evidence = markdown_blocks((root / evidence_path).read_text(encoding="utf-8"))
    compatibility_path = "docs/acme-client-compatibility.md"
    compatibility = markdown_blocks((root / compatibility_path).read_text(encoding="utf-8"))
    problems = []

    # Check the two publication facts explicitly recorded by the evidence owner.
    # The July alpha.0 closeout is a different record from the later tag attempt.
    publication = evidence.replace("\x60", "")
    alpha0_rows = re.findall(
        r"^\|[^|\n]*\bsigned v?0\.1\.0-alpha\.0 attempt\b[^|\n]*\|(.+)\|$",
        publication, re.M | re.I,
    )
    if len(alpha0_rows) != 1 or not re.search(
        r"\bNo (?:v?0\.1\.0-)?alpha\.0 GitHub Release was published\b", alpha0_rows[0], re.I,
    ):
        problems.append(f"{evidence_path}: alpha.0 tag attempt must show that no GitHub Release was published")
    alpha1_rows = re.findall(
        r"^\|[^|\n]*\bpublished v?0\.1\.0-alpha\.1\b[^|\n]*\|(.+)\|$", publication, re.M | re.I,
    )
    if len(alpha1_rows) != 1 or not all(
        token in alpha1_rows[0]
        for token in ("/releases/tag/v0.1.0-alpha.1)", "draft=false", "prerelease=true")
    ) or re.search(r"\b(?:draft=true|prerelease=false)\b", alpha1_rows[0]):
        problems.append(f"{evidence_path}: alpha.1 publication record must show the published prerelease")

    # Look only for affirmative, unqualified claims in current status prose.
    release_claim = re.compile(
        r"^ *(?:[-*] )?(?:"
        r"no\s+(?:GitHub\s+)?(?:pre)?releases?\s+(?:has|have)\s+(?:yet\s+)?been\s+published"
        r"|(?:the\s+)?(?:current|latest)\s+(?:published\s+)?(?:GitHub\s+)?(?:pre)?release\s+is\s+(?:v?0\.1\.0-)?alpha\.0"
        r"|(?:v?0\.1\.0-)?alpha\.1\s+(?:(?:has|have)\s+not\s+(?:yet\s+)?been\s+published|is\s+(?:still\s+)?unpublished)"
        r"|(?:(?:published\s+)?(?:v?0\.1\.0-)?alpha\.1|(?:the\s+)?(?:current|latest)\s+(?:pre)?release)"
        r"\s+is\s+(?:a\s+)?(?:production[- ]ready|stable(?:\s+release)?|supported production release|generally available)"
        r")\b",
        re.I | re.M,
    )
    client_claim = re.compile(
        r"^ *(?:[-*] )?(?:"
        r"all\s+ACME\s+clients\s+are\s+(?:fully\s+)?supported"
        r"|(?:Certbot\s+and\s+lego|lego\s+and\s+Certbot)\s+are\s+fully\s+supported"
        r"|(?:AnoPKI(?:-Community)?|the\s+service|ACME)\s+(?:fully\s+supports\s+all\s+ACME\s+clients"
        r"|(?:is\s+fully\s+compliant\s+with|implements\s+all\s+of)\s+RFC\s*8555)"
        r"|(?:Windows\s+non-admin\s+Certbot|Certbot\s+on\s+Windows\s+without\s+administrator\s+rights)"
        r"\s+is\s+(?:fully\s+)?(?:supported|verified)"
        r")\b",
        re.I | re.M,
    )
    if current_status:
        status = current_status[1].replace("\x60", "")
        problems.extend(f"README.md: current release claim conflicts with release evidence: {m[0].strip()}"
                        for m in release_claim.finditer(status))
    else:
        status = ""
    scenario_summary = compatibility.split("\n## Issuance environments\n", 1)[0]
    for path, prose in (
        ("README.md", status), (compatibility_path, scenario_summary.replace("\x60", "")),
    ):
        problems.extend(f"{path}: current client claim exceeds verified scenarios: {m[0].strip()}"
                        for m in client_claim.finditer(prose))
    for number, line in enumerate(compatibility.splitlines(), start=1):
        if re.match(
            r"^\|\s*certbot(?:/acme)? 5\.6\.0\s*\|\s*Windows non-admin PowerShell\s*\|"
            r"[^|]*\|[^|]*\|\s*(?:Pass(?:ed)?|Supported|Verified)\b",
            line, re.I,
        ):
            problems.append(f"{compatibility_path}:{number}: conflicting Certbot evidence: {line.strip()}")
    if problems:
        fail("inconsistent documentation status:\n" + "\n".join(problems))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=ROOT, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    check_required_files(root)
    check_openapi_json(root)
    check_markdown_links(root)
    check_license_state(root)
    check_source_file_headers(root)
    check_future_only_roadmap(root)
    check_anocrypto_direction(root)
    check_key_provider_direction(root)
    check_readme_verify_local_commands(root)
    check_readme_current_execution_state(root)
    check_legacy_identifier_scope(root)
    check_ci_docs_validation_commands(root)
    check_acme_compatibility_matrix(root)
    check_current_release_and_client_status(root)
    print("docs ok")


if __name__ == "__main__":
    main()
