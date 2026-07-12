#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-community-boundary.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_community_boundary", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_required_root(root: Path) -> None:
    (root / "CMakeLists.txt").write_text(
        """find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_library(anopki_core)
add_library(anopki_openssl_adapter)
target_link_libraries(anopki_openssl_adapter PRIVATE OpenSSL::Crypto)
add_executable(anopki-core)
target_link_libraries(anopki-core PRIVATE anopki_core anopki_openssl_adapter)
""",
        encoding="utf-8",
    )
    for rel in (
        "src/backends/openssl/openssl_backend.hpp",
        "src/backends/openssl/openssl_backend.cpp",
        "src/backends/openssl/csr.cpp",
        "src/backends/openssl/issue.cpp",
        "src/backends/openssl/crl.cpp",
        "src/backends/openssl/ocsp.cpp",
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// adapter\n", encoding="utf-8")


def assert_fails(root: Path, expected: str) -> None:
    validator = load_validator()
    try:
        validator.validate(root)
    except SystemExit as exc:
        assert expected in str(exc)
    else:
        raise AssertionError("validator unexpectedly passed")


def test_clean_community_root_passes() -> None:
    validator = load_validator()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        (root / "docs" / "adr").mkdir(parents=True)
        (root / "docs" / "adr" / "0006-crypto-backend-direction-anocrypto.md").write_text(
            "AnoCrypto implementation pending. OpenSSL remains current.\n",
            encoding="utf-8",
        )

        validator.validate(root)


def test_finds_enterprise_license_tokens() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        (root / "README.md").write_text("LicenseRef-AnoPKI-Enterprise\n", encoding="utf-8")

        assert_fails(root, "Enterprise-only tokens")


def test_finds_enterprise_only_paths() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        (root / "service" / "internal" / "enterprise").mkdir(parents=True)

        assert_fails(root, "Enterprise-only paths")


def test_finds_premature_anocrypto_claims() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        (root / "docs" / "bad.md").parent.mkdir(parents=True)
        (root / "docs" / "bad.md").write_text(
            "AnoCrypto is the default production backend.\n",
            encoding="utf-8",
        )

        assert_fails(root, "premature AnoCrypto claims")


def test_finds_kcmvp_certification_claims() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        (root / "docs" / "bad.md").parent.mkdir(parents=True)
        (root / "docs" / "bad.md").write_text("KCMVP certified module.\n", encoding="utf-8")

        assert_fails(root, "KCMVP certification claims")


def test_skips_generated_directories() -> None:
    validator = load_validator()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        (root / "build").mkdir()
        (root / "build" / "leak.txt").write_text("LicenseRef-AnoPKI-Enterprise\n", encoding="utf-8")

        validator.validate(root)



def test_rejects_direct_openssl_include_in_core() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        path = root / "src" / "core" / "issue.cpp"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#include <openssl/x509.h>\n", encoding="utf-8")

        assert_fails(root, "direct OpenSSL includes")


def test_rejects_direct_openssl_link_from_core_target() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_required_root(root)
        cmake = root / "CMakeLists.txt"
        cmake.write_text(
            cmake.read_text(encoding="utf-8")
            + "target_link_libraries(anopki_core PRIVATE OpenSSL::Crypto)\n",
            encoding="utf-8",
        )

        assert_fails(root, "anopki_core must not link OpenSSL::Crypto directly")

def main() -> None:
    test_clean_community_root_passes()
    test_finds_enterprise_license_tokens()
    test_finds_enterprise_only_paths()
    test_finds_premature_anocrypto_claims()
    test_finds_kcmvp_certification_claims()
    test_skips_generated_directories()
    test_rejects_direct_openssl_include_in_core()
    test_rejects_direct_openssl_link_from_core_target()
    print("community boundary validator tests ok")


if __name__ == "__main__":
    main()
