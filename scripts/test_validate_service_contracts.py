#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for service contract validation."""

from __future__ import annotations

import shutil
import subprocess
import sys
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-service-contracts.py"


def run_validator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def copy_contract_inputs(dst: Path) -> None:
    files = [
        "service/internal/httpapi/server.go",
        "service/internal/httpapi/acme.go",
        "service/cmd/anopki-service/main.go",
        "service/internal/domain/errors.go",
        "service/README.md",
        "docs/reference/openapi.json",
        "docs/reference/api-errors.md",
    ]
    for name in files:
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def test_current_service_contracts_pass() -> None:
    result = run_validator(ROOT)
    assert result.returncode == 0, result.stderr + result.stdout


def test_missing_env_doc_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    readme = tmp_path / "service" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace("`ANOPKI_ADDR`", "`ANOPKI_ADDR_DOC_DRIFT`", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "env vars used by service but missing from service/README.md table" in result.stderr


def test_missing_openapi_route_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    del data["paths"]["/identities"]
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "routes registered in service but missing from OpenAPI" in result.stderr


def test_extra_openapi_route_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/contract-drift"] = {
        "get": {
            "operationId": "getContractDrift",
            "responses": {"200": {"description": "OK"}},
        }
    }
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "OpenAPI routes not registered in service" in result.stderr


def test_missing_openapi_query_param_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/identities"]["get"]["parameters"] = [
        param
        for param in data["paths"]["/identities"]["get"]["parameters"]
        if param.get("$ref") != "#/components/parameters/owner"
    ]
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "query parameters parsed by service but missing from OpenAPI" in result.stderr


def test_extra_openapi_query_param_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/identities"]["get"]["parameters"].append(
        {"name": "contract_drift", "in": "query", "schema": {"type": "string"}}
    )
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "query parameters documented in OpenAPI but not parsed by service" in result.stderr


def test_unknown_openapi_parameter_ref_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/identities"]["get"]["parameters"].append(
        {"$ref": "#/components/parameters/contractDrift"}
    )
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "unknown OpenAPI parameter ref" in result.stderr


def test_missing_openapi_path_param_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/identities/{id}"]["get"]["parameters"] = []
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "path parameters missing from OpenAPI operations" in result.stderr


def test_extra_openapi_path_param_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/identities/{id}"]["get"]["parameters"].append(
        {"name": "contract_drift", "in": "path", "schema": {"type": "string"}}
    )
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "path parameters documented in OpenAPI but absent from routes" in result.stderr


def test_openapi_operation_id_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["paths"]["/identities"]["get"]["operationId"] = "listIdentityDrift"
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "OpenAPI operationId drift" in result.stderr


def test_openapi_list_parameter_schema_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["components"]["parameters"]["limit"]["schema"]["minimum"] = 0
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "OpenAPI common query parameter schema drift" in result.stderr


def test_openapi_expiry_window_schema_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["components"]["parameters"]["expiresWithinDays"]["schema"].pop("enum", None)
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "OpenAPI common query parameter schema drift" in result.stderr


def test_openapi_status_enum_schema_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    data["components"]["parameters"]["outboxStatus"]["schema"].pop("enum", None)
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "OpenAPI common query parameter schema drift" in result.stderr


def test_readme_example_route_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    readme = tmp_path / "service" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "http://localhost:8080/identities",
            "http://localhost:8080/identity-drift",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "service README examples reference routes missing from OpenAPI" in result.stderr


def test_readme_example_query_param_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    readme = tmp_path / "service" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "http://localhost:8080/identities?owner=platform",
            "http://localhost:8080/identities?owner_drift=platform",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "service README examples use query params missing from OpenAPI" in result.stderr


def test_readme_endpoint_route_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    readme = tmp_path / "service" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "`GET /certificate-profiles`",
            "`GET /certificate-profile-drift`",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "service README endpoint examples reference routes missing from OpenAPI" in result.stderr


def test_readme_endpoint_query_param_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    readme = tmp_path / "service" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace(
            "`GET /certificates?expires_within_days=30`",
            "`GET /certificates?expires_within_days_drift=30`",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "service README endpoint examples use query params missing from OpenAPI" in result.stderr


def test_api_error_status_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    errors_doc = tmp_path / "docs" / "reference" / "api-errors.md"
    errors_doc.write_text(
        errors_doc.read_text(encoding="utf-8").replace(
            "| `ErrInvalidTransition` | `invalid lifecycle transition` | 409 |",
            "| `ErrInvalidTransition` | `invalid lifecycle transition` | 400 |",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "api-errors.md HTTP status drift" in result.stderr


def test_api_error_message_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    errors_doc = tmp_path / "docs" / "reference" / "api-errors.md"
    errors_doc.write_text(
        errors_doc.read_text(encoding="utf-8").replace(
            "| `ErrInvalidTransition` | `invalid lifecycle transition` | 409 |",
            "| `ErrInvalidTransition` | `invalid transition drift` | 409 |",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "api-errors.md public message drift" in result.stderr


def test_acme_problem_type_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    errors_doc = tmp_path / "docs" / "reference" / "api-errors.md"
    errors_doc.write_text(
        errors_doc.read_text(encoding="utf-8").replace(
            "urn:ietf:params:acme:error:badNonce",
            "urn:ietf:params:acme:error:badNonceDrift",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "api-errors.md ACME problem type drift" in result.stderr


def test_unknown_api_error_doc_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    errors_doc = tmp_path / "docs" / "reference" / "api-errors.md"
    errors_doc.write_text(
        errors_doc.read_text(encoding="utf-8").replace(
            "| `ErrInvalidTransition` | `invalid lifecycle transition` | 409 |",
            "| `ErrInvalidTransitionDocsDrift` | `invalid lifecycle transition` | 409 |",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "api-errors.md documents unknown domain errors" in result.stderr


def main() -> None:
    test_current_service_contracts_pass()
    import tempfile

    with tempfile.TemporaryDirectory() as dirname:
        test_missing_env_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_openapi_route_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_extra_openapi_route_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_openapi_query_param_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_extra_openapi_query_param_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_unknown_openapi_parameter_ref_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_openapi_path_param_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_extra_openapi_path_param_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_openapi_operation_id_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_openapi_list_parameter_schema_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_openapi_expiry_window_schema_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_openapi_status_enum_schema_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_readme_example_route_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_readme_example_query_param_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_readme_endpoint_route_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_readme_endpoint_query_param_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_api_error_status_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_api_error_message_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_acme_problem_type_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_unknown_api_error_doc_fails(Path(dirname))
    print("service contract validator tests ok")


if __name__ == "__main__":
    main()
