#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Cheap Go-to-core CLI JSON contract parity checks."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


CONTRACTS = {
    "issue request": {
        "go": "IssueRequest",
        "cpp_parser": "issue_request_from_json",
    },
    "issue result": {
        "go": "IssueResult",
        "cpp_emitter": "issue_result_to_json",
    },
    "csr inspect result": {
        "go": "CSRInfo",
        "cpp_emitter": "csr_info_to_json",
    },
    "crl request": {
        "go": "crlFileRequest",
        "cpp_parser": "crl_request_from_json",
    },
    "crl result": {
        "go": "GenerateCRLResult",
        "cpp_emitter": "crl_result_to_json",
    },
    "ocsp certificate id": {
        "go": "OCSPCertificateID",
        "cpp_emitter": "ocsp_info_to_json",
    },
    "ocsp inspect result": {
        "go": "OCSPRequestInfo",
        "cpp_emitter": "ocsp_info_to_json",
    },
    "ocsp issuer info": {
        "go": "OCSPIssuerInfo",
        "cpp_emitter": "ocsp_issuer_info_to_json",
    },
    "ocsp responder validation result": {
        "go": "ValidateOCSPResponderResult",
        "cpp_emitter": "ocsp_responder_validation_to_json",
    },
    "ocsp response request": {
        "go": "ocspResponseFileRequest",
        "cpp_parser": "ocsp_response_request_from_json",
    },
    "command error": {
        "go": "commandErrorPayload",
        "cpp_emitter": "write_error",
    },
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def read_text(root: Path, path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def struct_body(go_source: str, name: str) -> str:
    match = re.search(rf"type\s+{re.escape(name)}\s+struct\s+\{{(?P<body>.*?)\n\}}", go_source, flags=re.S)
    if not match:
        fail(f"Go struct not found: {name}")
    return match.group("body")


def go_json_fields(go_source: str, name: str) -> set[str]:
    fields = set()
    for tag in re.findall(r'`json:"([^"]+)"`', struct_body(go_source, name)):
        field = tag.split(",", 1)[0]
        if field and field != "-":
            fields.add(field)
    return fields


def function_body(cpp_source: str, name: str) -> str:
    match = re.search(rf"\n[^\n]*\b{re.escape(name)}\([^)]*\)\s*\{{(?P<body>.*?)\n\}}", cpp_source, flags=re.S)
    if not match:
        fail(f"C++ function not found: {name}")
    return match.group("body")


def cpp_parser_fields(cpp_source: str, name: str) -> set[str]:
    body = function_body(cpp_source, name)
    return set(re.findall(r'get_[a-z0-9_]+_field\(object,\s*"([a-z0-9_]+)"', body))


def cpp_emitter_fields(cpp_source: str, name: str) -> set[str]:
    body = function_body(cpp_source, name)
    return set(re.findall(r'\\"([a-z0-9_]+)\\"', body))


def documented_fields(doc_source: str) -> dict[str, set[str]]:
    sections: dict[str, set[str]] = {}
    matches = list(re.finditer(r"^### (?P<name>[a-z0-9 ]+)\n(?P<body>.*?)(?=^### |\Z)", doc_source, flags=re.M | re.S))
    for match in matches:
        sections[match.group("name")] = set(re.findall(r"^- `([a-z0-9_]+)`", match.group("body"), flags=re.M))
    return sections


def check_contracts(root: Path) -> None:
    go_source = read_text(root, "service/internal/corecli/runner.go")
    cpp_source = read_text(root, "src/cli/main.cpp")
    doc_source = read_text(root, "docs/reference/core-cli-contract.md")
    docs = documented_fields(doc_source)
    messages: list[str] = []

    for name, contract in CONTRACTS.items():
        doc_fields = docs.get(name)
        if doc_fields is None:
            messages.append(f"core CLI contract doc missing section: {name}")
            continue

        go_fields = go_json_fields(go_source, contract["go"])
        if go_fields != doc_fields:
            messages.append(
                diff_message(
                    "Go corecli JSON fields drift / core CLI contract doc drift",
                    name,
                    go_fields,
                    doc_fields,
                    "Go",
                    "docs",
                )
            )

        if "cpp_parser" in contract:
            cpp_fields = cpp_parser_fields(cpp_source, contract["cpp_parser"])
            if cpp_fields != doc_fields:
                messages.append(diff_message("C++ core CLI parser fields drift", name, doc_fields, cpp_fields, "docs", "C++ parser"))

        if "cpp_emitter" in contract:
            cpp_fields = cpp_emitter_fields(cpp_source, contract["cpp_emitter"])
            missing = go_fields - cpp_fields
            if missing:
                messages.append(
                    "C++ core CLI emitter fields drift for "
                    f"{name}: missing {', '.join(sorted(missing))}"
                )

    extra_sections = sorted(set(docs) - set(CONTRACTS))
    if extra_sections:
        messages.append("core CLI contract doc has unknown sections:\n" + "\n".join(extra_sections))
    if messages:
        fail("\n\n".join(messages))


def diff_message(prefix: str, name: str, expected: set[str], actual: set[str], expected_label: str, actual_label: str) -> str:
    parts = [f"{prefix} for {name}:"]
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        parts.append(f"missing from {actual_label} vs {expected_label}: " + ", ".join(missing))
    if extra:
        parts.append(f"extra in {actual_label} vs {expected_label}: " + ", ".join(extra))
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()
    check_contracts(args.root.resolve())
    print("core CLI contracts ok")


if __name__ == "__main__":
    main()
