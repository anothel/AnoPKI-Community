#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Cheap service API/config/error documentation parity checks."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

ACME_PROTOCOL_PATHS = {
    "/acme/directory",
    "/acme/new-nonce",
    "/acme/new-account",
    "/acme/account/{id}",
    "/acme/new-order",
    "/acme/key-change",
    "/acme/order/{id}",
    "/acme/authz/{id}",
    "/acme/challenge/{id}",
    "/acme/order/{id}/finalize",
    "/acme/revoke-cert",
    "/acme/cert/{id}",
}

OPERATIONAL_PATHS = {
    "/debug/vars",
    "/healthz",
    "/readyz",
    "/version",
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def read_text(root: Path, path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def registered_routes(root: Path) -> set[tuple[str, str]]:
    files = [
        "service/internal/httpapi/server.go",
        "service/cmd/anopki-service/main.go",
    ]
    routes: set[tuple[str, str]] = set()
    pattern = re.compile(r'(?:[A-Za-z0-9_]+\.)?mux\.Handle(?:Func)?\("([A-Z]+) ([^"]+)"')
    for path in files:
        for method, route in pattern.findall(read_text(root, path)):
            if method in HTTP_METHODS:
                routes.add((method, route))
    return routes


def registered_route_handlers(root: Path) -> dict[tuple[str, str], str]:
    text = read_text(root, "service/internal/httpapi/server.go")
    pattern = re.compile(
        r'mux\.HandleFunc\("([A-Z]+) ([^"]+)",\s*s\.([A-Za-z0-9_]+)\)'
    )
    handlers: dict[tuple[str, str], str] = {}
    for method, route, handler in pattern.findall(text):
        if method in HTTP_METHODS:
            handlers[(method, route)] = handler
    return handlers


def httpapi_text(root: Path) -> str:
    return "\n".join(
        read_text(root, path)
        for path in (
            "service/internal/httpapi/server.go",
            "service/internal/httpapi/acme.go",
        )
    )


def openapi_routes(root: Path) -> set[tuple[str, str]]:
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    routes: set[tuple[str, str]] = set()
    for path, operations in data.get("paths", {}).items():
        for method in operations:
            upper = method.upper()
            if upper in HTTP_METHODS:
                routes.add((upper, path))
    return routes


def resolve_openapi_param(params: dict, param: dict) -> dict:
    if "$ref" not in param:
        return param
    name = param["$ref"].removeprefix("#/components/parameters/")
    resolved = params.get(name)
    if resolved is None:
        fail(f"unknown OpenAPI parameter ref: {param['$ref']}")
    return resolved


def openapi_query_params(root: Path) -> dict[tuple[str, str], set[str]]:
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    params = data.get("components", {}).get("parameters", {})
    routes: dict[tuple[str, str], set[str]] = {}
    for path, operations in data.get("paths", {}).items():
        for method, operation in operations.items():
            upper = method.upper()
            if upper not in HTTP_METHODS:
                continue
            names: set[str] = set()
            for param in operation.get("parameters", []):
                param = resolve_openapi_param(params, param)
                if param.get("in") == "query":
                    names.add(param["name"])
            routes[(upper, path)] = names
    return routes


def openapi_path_params(root: Path) -> dict[tuple[str, str], set[str]]:
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    params = data.get("components", {}).get("parameters", {})
    routes: dict[tuple[str, str], set[str]] = {}
    for path, operations in data.get("paths", {}).items():
        for method, operation in operations.items():
            upper = method.upper()
            if upper not in HTTP_METHODS:
                continue
            names: set[str] = set()
            for param in operation.get("parameters", []):
                param = resolve_openapi_param(params, param)
                if param.get("in") == "path":
                    names.add(param["name"])
            routes[(upper, path)] = names
    return routes


def openapi_operation_ids(root: Path) -> dict[tuple[str, str], str]:
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    operation_ids: dict[tuple[str, str], str] = {}
    for path, operations in data.get("paths", {}).items():
        for method, operation in operations.items():
            upper = method.upper()
            if upper in HTTP_METHODS and "operationId" in operation:
                operation_ids[(upper, path)] = operation["operationId"]
    return operation_ids


def function_body(text: str, name: str) -> str:
    pattern = re.compile(
        rf"func (?:\([^)]*\) )?{re.escape(name)}\([^)]*\)[^{{]*\{{"
    )
    match = pattern.search(text)
    if not match:
        fail(f"handler/helper function not found: {name}")
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    fail(f"handler/helper function body not closed: {name}")
    return ""


def query_params_from_function(text: str, name: str, seen: set[str] | None = None) -> set[str]:
    if seen is None:
        seen = set()
    if name in seen:
        return set()
    seen.add(name)
    body = function_body(text, name)
    names = set(re.findall(r'\.Get\("([^"]+)"\)', body))
    if "paginationFromQuery(r)" in body:
        names.update({"limit", "offset"})
    for helper in re.findall(r"\b([A-Za-z0-9_]+(?:FromQuery|FromRequest))\(r\)", body):
        if helper != name:
            names.update(query_params_from_function(text, helper, seen))
    return names


def service_query_params(root: Path) -> dict[tuple[str, str], set[str]]:
    text = httpapi_text(root)
    return {
        route: query_params_from_function(text, handler)
        for route, handler in registered_route_handlers(root).items()
        if route[0] == "GET"
        and route[1] not in ACME_PROTOCOL_PATHS
        and route[1] not in OPERATIONAL_PATHS
    }


def openapi_expected_routes(root: Path) -> set[tuple[str, str]]:
    return {
        route
        for route in registered_routes(root)
        if route[1] not in ACME_PROTOCOL_PATHS and route[1] not in OPERATIONAL_PATHS
    }


def check_route_openapi_parity(root: Path) -> None:
    expected = openapi_expected_routes(root)
    documented = openapi_routes(root)
    missing = sorted(expected - documented)
    extra = sorted(documented - expected)
    messages = []
    if missing:
        messages.append(
            "routes registered in service but missing from OpenAPI:\n"
            + "\n".join(f"{method} {path}" for method, path in missing)
        )
    if extra:
        messages.append(
            "OpenAPI routes not registered in service:\n"
            + "\n".join(f"{method} {path}" for method, path in extra)
        )
    if messages:
        fail("\n\n".join(messages))


def check_path_param_openapi_parity(root: Path) -> None:
    documented = openapi_path_params(root)
    missing_lines = []
    extra_lines = []
    for route in sorted(openapi_expected_routes(root)):
        expected_params = set(re.findall(r"\{([^}/]+)\}", route[1]))
        documented_params = documented.get(route, set())
        missing = sorted(expected_params - documented_params)
        extra = sorted(documented_params - expected_params)
        if missing:
            missing_lines.append(f"{route[0]} {route[1]}: {', '.join(missing)}")
        if extra:
            extra_lines.append(f"{route[0]} {route[1]}: {', '.join(extra)}")
    messages = []
    if missing_lines:
        messages.append(
            "path parameters missing from OpenAPI operations:\n"
            + "\n".join(missing_lines)
        )
    if extra_lines:
        messages.append(
            "path parameters documented in OpenAPI but absent from routes:\n"
            + "\n".join(extra_lines)
        )
    if messages:
        fail("\n\n".join(messages))


def check_query_openapi_parity(root: Path) -> None:
    expected = service_query_params(root)
    documented = openapi_query_params(root)
    messages = []
    missing_lines = []
    extra_lines = []
    for route, expected_params in sorted(expected.items()):
        documented_params = documented.get(route, set())
        missing = sorted(expected_params - documented_params)
        extra = sorted(documented_params - expected_params)
        if missing:
            missing_lines.append(f"{route[0]} {route[1]}: {', '.join(missing)}")
        if extra:
            extra_lines.append(f"{route[0]} {route[1]}: {', '.join(extra)}")
    if missing_lines:
        messages.append(
            "query parameters parsed by service but missing from OpenAPI:\n"
            + "\n".join(missing_lines)
        )
    if extra_lines:
        messages.append(
            "query parameters documented in OpenAPI but not parsed by service:\n"
            + "\n".join(extra_lines)
        )
    if messages:
        fail("\n\n".join(messages))


def check_common_query_parameter_schemas(root: Path) -> None:
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    params = data.get("components", {}).get("parameters", {})
    expected = {
        "limit": {"type": "integer", "minimum": 1},
        "offset": {"type": "integer", "minimum": 0},
        "expiresWithinDays": {"type": "integer", "minimum": 1, "enum": [1, 3, 7, 14, 30]},
        "enrollmentStatus": {"type": "string", "enum": ["pending", "approved", "rejected", "issued", "canceled"]},
        "revocationState": {"type": "string", "enum": ["valid", "suspended", "revoked", "expired"]},
        "renewalState": {"type": "string", "enum": ["notified", "unnotified"]},
        "outboxStatus": {"type": "string", "enum": ["pending", "processing", "completed", "failed", "dead_letter"]},
        "sort": {"type": "string", "enum": ["asc", "desc"]},
        "auditSort": {"type": "string", "enum": ["asc", "desc"]},
    }
    drift = [
        f"{name}: {params.get(name, {}).get('schema')} != {schema}"
        for name, schema in expected.items()
        if params.get(name, {}).get("schema") != schema
    ]
    if drift:
        fail("OpenAPI common query parameter schema drift:\n" + "\n".join(drift))


def check_readme_example_openapi_parity(root: Path) -> None:
    readme = read_text(root, "service/README.md")
    urls = re.findall(r"https?://localhost:8080[^\s\"`]+", readme)
    endpoints = re.findall(r"`(?:GET|HEAD|POST|PUT|PATCH|DELETE) (/[^`\s]+)`", readme)
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    paths = data.get("paths", {})
    params = data.get("components", {}).get("parameters", {})
    query_params_by_path: dict[str, set[str]] = {}
    for path, operations in paths.items():
        names: set[str] = set()
        for operation in operations.values():
            for param in operation.get("parameters", []):
                param = resolve_openapi_param(params, param)
                if param.get("in") == "query":
                    names.add(param["name"])
        query_params_by_path[path] = names

    missing_routes = []
    missing_params = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.path not in paths:
            missing_routes.append(parsed.path)
            continue
        documented_params = query_params_by_path.get(parsed.path, set())
        example_params = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        missing = sorted(example_params - documented_params)
        if missing:
            missing_params.append(f"{parsed.path}: {', '.join(missing)}")

    missing_endpoint_routes = []
    missing_endpoint_params = []
    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        if parsed.path in ACME_PROTOCOL_PATHS or parsed.path in OPERATIONAL_PATHS:
            continue
        if parsed.path not in paths:
            missing_endpoint_routes.append(parsed.path)
            continue
        documented_params = query_params_by_path.get(parsed.path, set())
        example_params = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        missing = sorted(example_params - documented_params)
        if missing:
            missing_endpoint_params.append(f"{parsed.path}: {', '.join(missing)}")

    messages = []
    if missing_routes:
        messages.append(
            "service README examples reference routes missing from OpenAPI:\n"
            + "\n".join(sorted(set(missing_routes)))
        )
    if missing_params:
        messages.append(
            "service README examples use query params missing from OpenAPI:\n"
            + "\n".join(missing_params)
        )
    if missing_endpoint_routes:
        messages.append(
            "service README endpoint examples reference routes missing from OpenAPI:\n"
            + "\n".join(sorted(set(missing_endpoint_routes)))
        )
    if missing_endpoint_params:
        messages.append(
            "service README endpoint examples use query params missing from OpenAPI:\n"
            + "\n".join(missing_endpoint_params)
        )
    if messages:
        fail("\n\n".join(messages))


def check_operation_id_parity(root: Path) -> None:
    expected = {
        route: handler
        for route, handler in registered_route_handlers(root).items()
        if route[1] not in ACME_PROTOCOL_PATHS and route[1] not in OPERATIONAL_PATHS
    }
    documented = openapi_operation_ids(root)
    drift = [
        f"{method} {path}: OpenAPI {documented.get((method, path), '<missing>')} != handler {handler}"
        for (method, path), handler in sorted(expected.items())
        if documented.get((method, path)) != handler
    ]
    if drift:
        fail("OpenAPI operationId drift:\n" + "\n".join(drift))


def used_env_vars(root: Path) -> set[str]:
    text = read_text(root, "service/cmd/anopki-service/main.go")
    pattern = re.compile(
        r'(?:envOrDefault|os\.Getenv|parse[A-Za-z0-9_]*Env)\("'
        r"(ANOPKI_[A-Z0-9_]+)"
        r'"'
    )
    return set(pattern.findall(text))


def documented_env_vars(root: Path) -> set[str]:
    text = read_text(root, "service/README.md")
    return set(re.findall(r"^\|\s*`(ANOPKI_[A-Z0-9_]+)`\s*\|", text, flags=re.MULTILINE))


def check_env_doc_parity(root: Path) -> None:
    used = used_env_vars(root)
    documented = documented_env_vars(root)
    missing = sorted(used - documented)
    extra = sorted(documented - used)
    messages = []
    if missing:
        messages.append(
            "env vars used by service but missing from service/README.md table:\n"
            + "\n".join(missing)
        )
    if extra:
        messages.append(
            "env vars documented in service/README.md table but not used by service:\n"
            + "\n".join(extra)
        )
    if messages:
        fail("\n\n".join(messages))


def mapped_public_errors(root: Path) -> set[str]:
    text = read_text(root, "service/internal/httpapi/server.go")
    match = re.search(r"func publicErrorMessage\(err error\) string \{(?P<body>.*?)\n\}", text, flags=re.S)
    if not match:
        fail("publicErrorMessage function not found")
    return set(re.findall(r"errors\.Is\(err,\s*domain\.(Err[A-Za-z0-9]+)\)", match.group("body")))


def domain_errors(root: Path) -> set[str]:
    text = read_text(root, "service/internal/domain/errors.go")
    return set(re.findall(r"\b(Err[A-Za-z0-9]+)\s*=\s*errors\.New", text))


def domain_error_messages(root: Path) -> dict[str, str]:
    text = read_text(root, "service/internal/domain/errors.go")
    return {
        error_name: message
        for error_name, message in re.findall(
            r'\b(Err[A-Za-z0-9]+)\s*=\s*errors\.New\("([^"]+)"\)',
            text,
        )
    }


def documented_http_errors(root: Path) -> set[str]:
    text = read_text(root, "docs/reference/api-errors.md")
    match = re.search(r"## HTTP Mapping(?P<body>.*?)## ACME Problem Types", text, flags=re.S)
    if not match:
        fail("HTTP Mapping section not found in docs/reference/api-errors.md")
    return set(re.findall(r"^\|\s*`(Err[A-Za-z0-9]+)`\s*\|", match.group("body"), flags=re.MULTILINE))


def mapped_public_error_statuses(root: Path) -> dict[str, int]:
    text = read_text(root, "service/internal/httpapi/server.go")
    match = re.search(r"func statusForError\(err error\) int \{(?P<body>.*?)\n\}", text, flags=re.S)
    if not match:
        fail("statusForError function not found")
    http_statuses = {
        "StatusBadRequest": 400,
        "StatusUnsupportedMediaType": 415,
        "StatusUnauthorized": 401,
        "StatusForbidden": 403,
        "StatusTooManyRequests": 429,
        "StatusConflict": 409,
        "StatusNotFound": 404,
        "StatusUnprocessableEntity": 422,
        "StatusBadGateway": 502,
        "StatusInternalServerError": 500,
    }
    mapped: dict[str, int] = {}
    for case_body, status_name in re.findall(
        r"case (?P<case_body>.*?):\s*return http\.(?P<status>Status[A-Za-z0-9]+)",
        match.group("body"),
        flags=re.S,
    ):
        if status_name not in http_statuses:
            fail(f"unknown http status constant in statusForError: {status_name}")
        for error_name in re.findall(r"domain\.(Err[A-Za-z0-9]+)", case_body):
            mapped[error_name] = http_statuses[status_name]
    return mapped


def documented_http_error_statuses(root: Path) -> dict[str, int]:
    text = read_text(root, "docs/reference/api-errors.md")
    match = re.search(r"## HTTP Mapping(?P<body>.*?)## ACME Problem Types", text, flags=re.S)
    if not match:
        fail("HTTP Mapping section not found in docs/reference/api-errors.md")
    return {
        error_name: int(status)
        for error_name, status in re.findall(
            r"^\|\s*`(Err[A-Za-z0-9]+)`\s*\|[^|]*\|\s*(\d+)\s*\|",
            match.group("body"),
            flags=re.MULTILINE,
        )
    }


def documented_http_error_messages(root: Path) -> dict[str, str]:
    text = read_text(root, "docs/reference/api-errors.md")
    match = re.search(r"## HTTP Mapping(?P<body>.*?)## ACME Problem Types", text, flags=re.S)
    if not match:
        fail("HTTP Mapping section not found in docs/reference/api-errors.md")
    return {
        error_name: message
        for error_name, message in re.findall(
            r"^\|\s*`(Err[A-Za-z0-9]+)`\s*\|\s*`([^`]+)`\s*\|",
            match.group("body"),
            flags=re.MULTILINE,
        )
    }


def mapped_acme_problem_types(root: Path) -> set[str]:
    text = read_text(root, "service/internal/httpapi/server.go")
    match = re.search(r"func acmeProblemType\(err error\) string \{(?P<body>.*?)\n\}", text, flags=re.S)
    if not match:
        fail("acmeProblemType function not found")
    return set(re.findall(r'return "(urn:ietf:params:acme:error:[^"]+)"', match.group("body")))


def documented_acme_problem_types(root: Path) -> set[str]:
    text = read_text(root, "docs/reference/api-errors.md")
    match = re.search(r"## ACME Problem Types(?P<body>.*?)## Audit Error Codes", text, flags=re.S)
    if not match:
        fail("ACME Problem Types section not found in docs/reference/api-errors.md")
    return set(re.findall(r"`(urn:ietf:params:acme:error:[^`]+)`", match.group("body")))


def check_error_doc_parity(root: Path) -> None:
    mapped = mapped_public_errors(root)
    documented = documented_http_errors(root)
    domain_messages = domain_error_messages(root)
    documented_messages = documented_http_error_messages(root)
    mapped_statuses = mapped_public_error_statuses(root)
    documented_statuses = documented_http_error_statuses(root)
    known = domain_errors(root)
    messages = []
    missing = sorted(mapped - documented)
    unknown_docs = sorted(documented - known)
    if missing:
        messages.append(
            "public errors mapped in service but missing from api-errors.md:\n"
            + "\n".join(missing)
        )
    if unknown_docs:
        messages.append(
            "api-errors.md documents unknown domain errors:\n"
            + "\n".join(unknown_docs)
        )
    status_drift = [
        f"{error_name}: {documented_statuses.get(error_name)} != {status}"
        for error_name, status in sorted(mapped_statuses.items())
        if documented_statuses.get(error_name) != status
    ]
    if status_drift:
        messages.append("api-errors.md HTTP status drift:\n" + "\n".join(status_drift))
    message_drift = [
        f"{error_name}: {documented_messages.get(error_name)!r} != {domain_messages.get(error_name)!r}"
        for error_name in sorted(mapped)
        if documented_messages.get(error_name) != domain_messages.get(error_name)
    ]
    if message_drift:
        messages.append("api-errors.md public message drift:\n" + "\n".join(message_drift))
    mapped_acme_types = mapped_acme_problem_types(root)
    documented_acme_types = documented_acme_problem_types(root)
    acme_type_drift = sorted(mapped_acme_types ^ documented_acme_types)
    if acme_type_drift:
        messages.append("api-errors.md ACME problem type drift:\n" + "\n".join(acme_type_drift))
    if "ACME bad nonce" not in read_text(root, "docs/reference/api-errors.md"):
        messages.append("api-errors.md missing ACME bad nonce mapping")
    if "unknown error" not in read_text(root, "docs/reference/api-errors.md"):
        messages.append("api-errors.md missing unknown error mapping")
    if messages:
        fail("\n\n".join(messages))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    check_route_openapi_parity(root)
    check_operation_id_parity(root)
    check_path_param_openapi_parity(root)
    check_query_openapi_parity(root)
    check_common_query_parameter_schemas(root)
    check_readme_example_openapi_parity(root)
    check_env_doc_parity(root)
    check_error_doc_parity(root)
    print("service contracts ok")


if __name__ == "__main__":
    main()
