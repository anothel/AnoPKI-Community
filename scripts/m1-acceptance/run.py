#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""PKI-16 Community API-key/SQLite acceptance. Stdout is sanitized JSON."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
CONFIG = Path(__file__).with_name("openssl.cnf")
DNS, IP, SUBJECT = "edge-01.example.test", "127.0.0.1", "CN=edge-01"
OPERATOR, WRITER = "m1-operator", "m1-write"
CASES = {
    "SETUP": "Local service readiness, scoped keys and disposable CA",
    "C-PKI-01": "Real CSR with matching DNS/IP SANs, pending enrollment and approval",
    "C-NEG-01": "Authentication, scope, CSR and pre-approval denials preserve signing state",
    "C-PKI-02": "Issued leaf, chain, key usages, serial, inventory and repeat without signing",
    "C-PKI-03": "Renewal and reissue with serial linkage, then isolated revocation",
}
HTTP_ERRORS = {401: "unauthorized", 403: "forbidden", 409: "invalid lifecycle transition"}


class CheckFailed(Exception):
    """A failure message constructed from fixed labels and non-sensitive values."""


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def command(args, **options):
    return subprocess.run(args, capture_output=True, check=True, timeout=15, **options).stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def expiry(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")


def resource_id(obj):
    value = obj["id"]
    require(str(uuid.UUID(value)) == value, "expected canonical resource UUID")
    return value


def preflight(report):
    report["missing"] = [name for name in ("ANOPKI_CORE_BIN", "ANOPKI_SERVICE_BIN")
                         if not os.environ.get(name)]
    report["missing"] += [tool for tool in ("go", "openssl") if not shutil.which(tool)]
    report["commit_sha"] = command(["git", "-C", ROOT, "rev-parse", "HEAD"]).decode().strip()
    report["dirty"] = bool(command(["git", "-C", ROOT, "status", "--porcelain"]))
    report["toolchain"] = {"system": platform.system(), "architecture": platform.machine(),
                           "kernel": platform.release(), "python": platform.python_version()}
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Linux x86_64 runner required")
    report["fixture_sha256"] = sha256(CONFIG.read_bytes())
    if report["missing"]:
        return None
    for tool in ("go", "openssl"):
        args = [tool, "version"]
        result = command(args, env=os.environ | {"GOTOOLCHAIN": "local"}).decode().strip()
        report["toolchain"][tool] = result.splitlines()[0]
    version = re.search(r"\bgo(\d+)\.(\d+)\.(\d+)\b", report["toolchain"]["go"])
    require(version and tuple(map(int, version.groups())) >= (1, 25, 11),
            "Go 1.25.11 or newer required")
    require(report["toolchain"]["openssl"].startswith("OpenSSL 3."), "OpenSSL 3 required")
    binaries = {}
    report["binaries"] = {}
    for name in ("core", "service"):
        path = Path(os.environ[f"ANOPKI_{name.upper()}_BIN"]).resolve()
        require(path.is_file() and os.access(path, os.X_OK), f"{name} binary must be executable")
        data = path.read_bytes()
        require(data.startswith(b"\x7fELF"), f"{name} binary must be a Linux ELF executable")
        binaries[name] = path
        report["binaries"][name] = {"name": path.name, "sha256": sha256(data)}
    info = json.loads(command([binaries["core"], "backend", "info"]))
    require(info["product_profile"] == "community-openssl" and info["selected_backend"] == "openssl"
            and info["backend_readiness"] == "ready" and info["fallback_enabled"] is False,
            "ready Community OpenSSL Core required")
    report["toolchain"]["core_backend"] = {
        key: info[key] for key in ("backend_version", "backend_build_fingerprint")
    }
    return binaries


def owns_listener(pid, port):
    # Check the listening inode belongs to the child before sending it a bearer key.
    fds = Path(f"/proc/{pid}/fd")
    if not fds.exists():
        return False
    inodes = set()
    for fd in fds.iterdir():
        try:
            inodes.add(os.readlink(fd))
        except FileNotFoundError:
            continue
    with Path(f"/proc/{pid}/net/tcp").open() as table:
        next(table)
        return any(
            fields[1] == f"0100007F:{port:04X}" and fields[3] == "0A"
            and f"socket:[{fields[9]}]" in inodes
            for fields in map(str.split, table)
        )


class Run:
    def __init__(self, work, binaries, report):
        self.work, self.binaries, self.report = work, binaries, report
        self.env = {
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(work),
            "TMPDIR": str(work), "LC_ALL": "C", "TZ": "UTC",
        }
        self.bootstrap, self.pepper = secrets.token_hex(32), secrets.token_hex(32)
        self.private_values = [self.bootstrap, self.pepper]
        self.case = report["cases"][0]
        self.stopped = True

    @contextmanager
    def stage(self, index, *, complete=True):
        self.case = self.report["cases"][index]
        self.case.update(status="FAIL", actual="did not complete")
        yield
        if complete:
            self.case.update(status="PASS", actual=self.case["expected"])
        else:
            self.case.update(status="NOT_RUN", actual="pending enrollment verified; approval outstanding")

    def tool(self, binary, *args):
        path = "openssl" if binary == "openssl" else self.binaries[binary]
        safe_args = ["<fixture-config>" if arg == CONFIG else str(arg) for arg in args]
        self.case["commands"].append(shlex.join([binary, *safe_args]))
        try:
            return command([path, *args], cwd=self.work, env=self.env)
        except subprocess.CalledProcessError as error:
            raise CheckFailed(f"{binary} {args[0]} exited with status {error.returncode}") from None

    @contextmanager
    def service(self):
        with socket.socket() as reserved:
            reserved.bind((IP, 0))
            self.port = reserved.getsockname()[1]
        env = self.env | {
            "ANOPKI_ADDR": f"{IP}:{self.port}",
            "ANOPKI_DB_DRIVER": "sqlite", "ANOPKI_DB_DSN": str(self.work / "acceptance.db"),
            "ANOPKI_CORE_BIN": str(self.binaries["core"]), "ANOPKI_AUTH_MODE": "api_key",
            "ANOPKI_BOOTSTRAP_API_KEY": self.bootstrap, "ANOPKI_API_KEY_PEPPER": self.pepper,
            "ANOPKI_ACME_BOOTSTRAP_DEFAULTS": "false", "ANOPKI_OUTBOX_ENABLED": "false",
            "ANOPKI_EXPIRATION_SCAN_ENABLED": "false",
        }
        self.case["commands"].append("anopki-service [api_key, localhost, disposable SQLite]")
        proc = subprocess.Popen([self.binaries["service"]], cwd=self.work, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        self.process = proc
        self.stopped = False
        try:
            yield
        finally:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except ProcessLookupError:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
            # The service can exit before an active Core child in its process group.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.stopped = True

    def ready(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(self.process.poll() is None, "service exited before readiness")
            if owns_listener(self.process.pid, self.port):
                self.request("GET", "/readyz", None, 200)
                return
            time.sleep(0.1)
        raise CheckFailed("service did not own a loopback listener before deadline")

    def request(self, method, path, token, expected, body=None, error=None):
        require(owns_listener(self.process.pid, self.port), "service does not own the listener")
        connection = HTTPConnection(IP, self.port, timeout=10)
        headers = {"Content-Type": "application/json", "X-Actor": "m1-ignored-header"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None, headers)
            response = connection.getresponse()
            self.case["commands"].append(f"{method} {path} (expected {expected}, got {response.status})")
            require(response.status == expected, f"{method} {path}: unexpected HTTP status")
            payload = json.loads(response.read(4 * 1024 * 1024))
            if expected >= 400:
                require(payload.get("error") == (error or HTTP_ERRORS[expected]),
                        f"{method} {path}: unexpected API error")
            return payload
        finally:
            connection.close()

    def create_key(self, token, scope, expires_at=None):
        payload = {"name": "m1-" + scope, "actor": "m1-" + scope, "scopes": [scope]}
        if expires_at:
            payload["name"] = "m1-short-lived"
            payload["expires_at"] = expires_at.isoformat(timespec="seconds")
        result = self.request("POST", "/api-keys", token, 201, payload)
        require(result["scopes"] == [scope] and result["actor"] == payload["actor"]
                and result["token"] and not result.get("token_hash"),
                f"unexpected {scope} API-key response")
        self.private_values.append(result["token"])
        return result["token"]

    def pem(self, name):
        return (self.work / name).read_text(encoding="ascii")

    def make_csr(self, name):
        self.tool("openssl", "req", "-new", "-newkey", "ec",
                  "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc", "-config", CONFIG,
                  "-keyout", f"{name}.key", "-out", f"{name}.csr")
        self.tool("openssl", "req", "-verify", "-noout", "-in", f"{name}.csr")
        info = json.loads(self.tool("core", "csr", "inspect", "--in", f"{name}.csr", "--out", "json"))
        require(info["subject"] == "/CN=edge-01" and info["dns_names"] == [DNS]
                and info["ip_addresses"] == [IP], "Core CSR subject or SAN mismatch")
        der = self.tool("openssl", "req", "-in", f"{name}.csr", "-outform", "DER")
        self.report["artifacts"][name + "-csr-der"] = sha256(der)
        return self.pem(f"{name}.csr")

    def verify_certificate(self, certificate, name, links, enrollment, expected_expiry):
        for key, value in (links | {"enrollment_id": enrollment, "status": "valid",
                                    "dns_names": [DNS], "ip_addresses": [IP]}).items():
            require(certificate[key] == value, f"{name}: certificate {key} mismatch")
        cert = name + ".crt"
        (self.work / cert).write_text(certificate["certificate_pem"], encoding="ascii")
        self.tool("openssl", "verify", "-trusted", "ca.crt", "-x509_strict", "-purpose", "sslserver",
                  "-verify_hostname", DNS, "-verify_ip", IP, cert)
        exts = self.tool("openssl", "x509", "-in", cert, "-noout", "-ext",
                         "subjectAltName,keyUsage,extendedKeyUsage,basicConstraints").decode("ascii")
        for expected in (f"DNS:{DNS}, IP Address:{IP}", "Digital Signature",
                         "TLS Web Server Authentication", "CA:FALSE"):
            require(expected in {line.strip() for line in exts.splitlines()},
                    f"{name}: certificate extension mismatch")
        cert_key = self.tool("openssl", "x509", "-in", cert, "-noout", "-pubkey")
        csr_key = self.tool("openssl", "req", "-in", name + ".csr", "-noout", "-pubkey")
        require(cert_key == csr_key, f"{name}: certificate public key differs from CSR")
        serial = self.tool("openssl", "x509", "-in", cert, "-noout", "-serial").decode().strip()
        require(str(int(serial.removeprefix("serial="), 16)) == certificate["serial_number"],
                f"{name}: certificate serial differs from API")
        dates = self.tool("openssl", "x509", "-in", cert, "-noout", "-dates",
                          "-dateopt", "iso_8601").decode().splitlines()
        for field, date in zip(("not_before", "not_after"), dates, strict=True):
            require(datetime.fromisoformat(date.split("=", 1)[1]) ==
                    datetime.fromisoformat(certificate[field]), f"{name}: validity differs from API")
        require(datetime.fromisoformat(certificate["not_after"]) == datetime.fromisoformat(expected_expiry),
                f"{name}: issued expiry differs from requested validity")
        self.report["artifacts"][name + "-cert-der"] = sha256(
            self.tool("openssl", "x509", "-in", cert, "-outform", "DER"))
        self.report["certificates"][name] = {"id": resource_id(certificate),
                                             "serial": certificate["serial_number"]}

    def sign_calls(self, operator):
        metrics = self.request("GET", "/debug/vars", operator, 200)["anopki_operations_total"]
        return metrics.get("signer:issue:success", 0) + metrics.get("signer:issue:error", 0)

    def issue(self, writer, reader, enrollment):
        certificate = self.request("POST", "/certificates", writer, 201, {"enrollment_id": enrollment})
        persisted = self.request("GET", f"/enrollments/{enrollment}", reader, 200)
        require(persisted["status"] == "issued", "enrollment did not become issued")
        require(certificate == self.request("GET", f"/certificates/{resource_id(certificate)}", reader, 200),
                "persisted certificate differs from issuance response")
        return certificate

    def audit(self, operator, action, subject, actor):
        events = self.request("GET", "/audit-events", operator, 200)
        serialized = json.dumps(events)
        require(not any(value in serialized for value in self.private_values)
                and str(self.work) not in serialized and "PRIVATE KEY-----" not in serialized,
                "audit response exposed temporary credentials or private fixture paths")
        matches = [event for event in events
                   if event["action"] == action and event["resource_id"] == subject]
        require(len(matches) == 1 and matches[0]["actor"] == actor,
                f"expected one {action} event with scoped actor")
        metadata = json.loads(matches[0]["metadata_json"])
        require(metadata["auth_method"] == "api_key" and metadata["api_key_actor"] == actor,
                f"{action} audit metadata did not identify API-key actor")
        return metadata

    def lifecycle(self):
        with self.stage(0):
            self.ready()
            require((self.work / "acceptance.db").is_file(), "service did not create its SQLite database")
            version = self.request("GET", "/version", None, 200)
            require(version["commit"] == self.report["commit_sha"],
                    "service /version commit differs from checkout")
            operator = self.create_key(self.bootstrap, "operator")
            writer = self.create_key(operator, "write")
            reader = self.create_key(operator, "read")
            keys = self.request("GET", "/api-keys", operator, 200)
            require(len(keys) == 4 and all(not key.get("token") and not key.get("token_hash")
                                           for key in keys),
                    "operator key listing did not omit credential material")
            self.tool("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                      "ec_paramgen_curve:P-256", "-noenc", "-sha256", "-days", "14",
                      "-config", CONFIG, "-extensions", "ca", "-subj", "/CN=AnoPKI M1 test CA",
                      "-keyout", "ca.key", "-out", "ca.crt")
            self.report["artifacts"]["ca-cert-der"] = sha256(
                self.tool("openssl", "x509", "-in", "ca.crt", "-outform", "DER"))

        with self.stage(1, complete=False):
            issuer = self.request("POST", "/issuers", operator, 201, {
                "name": "m1-test-ca", "kind": "root_ca", "certificate_pem": self.pem("ca.crt"),
                "key_ref": str(self.work / "ca.key"),
            })
            identity = self.request("POST", "/identities", writer, 201, {
                "type": "machine", "name": "edge-01", "external_id": "m1-edge-01",
                "allowed_dns_names": [DNS], "allowed_ip_addresses": [IP],
            })
            profile = self.request("POST", "/certificate-profiles", operator, 201, {
                "name": "m1-test-server", "issuer_id": resource_id(issuer),
                "validity_period_seconds": 7 * 86400, "subject_template": "CN={{identity.name}}",
                "allowed_dns_patterns": [DNS], "allowed_ip_ranges": [IP + "/32"],
                "allowed_key_algorithms": ["ecdsa"], "min_key_size_bits": 256,
                "basic_constraints": {"critical": True, "ca": False},
                "key_usage": {"critical": True, "values": ["digital_signature"]},
                "extended_key_usage": {"values": ["server_auth"]},
                "subject_key_identifier": True, "authority_key_identifier": True,
            })
            links = {"issuer_id": resource_id(issuer), "identity_id": resource_id(identity),
                     "profile_id": resource_id(profile)}
            payload = links | {
                "csr_pem": self.make_csr("initial"), "requested_subject": SUBJECT,
                "requested_dns_names": [DNS], "requested_ip_addresses": [IP],
                "requested_not_after": expiry(1),
            }
            pending = self.request("POST", "/enrollments", writer, 201, payload)
            enrollment = resource_id(pending)
            enroll_path = f"/enrollments/{enrollment}"
            require(pending["status"] == "pending" and pending["csr_dns_names"] == [DNS]
                    and pending["csr_ip_addresses"] == [IP],
                    "enrollment did not persist matching CSR SANs in pending state")
            require(pending == self.request("GET", enroll_path, reader, 200),
                    "read key could not retrieve unchanged pending enrollment")

        with self.stage(2):
            wrong = secrets.token_hex(32)
            self.private_values.append(wrong)
            for token in (None, wrong):
                self.request("GET", enroll_path, token, 401)
            for token in (reader, writer):
                self.request("GET", "/api-keys", token, 403)
                self.request("GET", "/audit-events", token, 403)
            self.request("POST", enroll_path + "/approve", reader, 403)
            self.request("POST", "/certificates", reader, 403, {"enrollment_id": enrollment})
            self.request("POST", "/certificates", writer, 409, {"enrollment_id": enrollment})
            self.request("POST", "/enrollments", writer, 400,
                         payload | {"requested_dns_names": ["mismatch.example.test"]},
                         "invalid request")
            self.request("POST", "/enrollments", writer, 422, payload | {"csr_pem": "invalid CSR"},
                         "csr parse failed")
            expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=5)
            expiring = self.create_key(operator, "read", expires_at)
            self.request("GET", enroll_path, expiring, 200)
            time.sleep(max(0, (expires_at - datetime.now(timezone.utc)).total_seconds()) + 0.1)
            self.request("GET", enroll_path, expiring, 401)
            require(self.request("GET", "/enrollments", reader, 200) == [pending]
                    and self.request("GET", "/certificates", reader, 200) == []
                    and self.sign_calls(operator) == 0, "denied requests changed enrollment or signer state")

        with self.stage(1):
            approved = self.request("POST", enroll_path + "/approve", operator, 200)
            require(approved["status"] == "approved" and approved["approved_by"] == OPERATOR,
                    "enrollment was not approved by the operator key")
            self.audit(operator, "enrollment.created", enrollment, WRITER)
            self.audit(operator, "enrollment.approved", enrollment, OPERATOR)

        with self.stage(3):
            self.request("POST", "/certificates", reader, 403, {"enrollment_id": enrollment})
            require(self.request("GET", enroll_path, reader, 200) == approved
                    and self.request("GET", "/certificates", reader, 200) == []
                    and self.sign_calls(operator) == 0, "denied issuance changed state or called the signer")
            initial = self.issue(writer, reader, enrollment)
            self.verify_certificate(initial, "initial", links, enrollment, payload["requested_not_after"])
            require(self.sign_calls(operator) == 1, "initial issuance did not sign exactly once")
            require(self.issue(writer, reader, enrollment) == initial and self.sign_calls(operator) == 1,
                    "issuance retry changed certificate or signer call count")
            require(self.request("GET", "/certificates", reader, 200) == [initial],
                    "initial inventory did not contain exactly the issued certificate")
            self.audit(operator, "certificate.issued", resource_id(initial), WRITER)

        with self.stage(4):
            source = resource_id(initial)
            cert_path = f"/certificates/{source}"
            successors = []
            for verb in ("renew", "reissue"):
                replacement = {"csr_pem": self.make_csr(verb)}
                expected_expiry = initial["not_after"]
                if verb == "renew":
                    expected_expiry = replacement["requested_not_after"] = expiry(2)
                successor = self.request("POST", cert_path + "/" + verb, writer, 201, replacement)
                for key, value in (links | {"source_certificate_id": source, "status": "pending"}).items():
                    require(successor[key] == value, f"{verb}: replacement enrollment {key} mismatch")
                require(datetime.fromisoformat(successor["requested_not_after"]) ==
                        datetime.fromisoformat(expected_expiry), f"{verb}: replacement expiry mismatch")
                successor_id = resource_id(successor)
                successor_path = f"/enrollments/{successor_id}"
                approved = self.request("POST", successor_path + "/approve", operator, 200)
                require(approved["status"] == "approved" and approved["approved_by"] == OPERATOR,
                        f"{verb}: replacement was not approved by the operator key")
                certificate = self.issue(writer, reader, successor_id)
                self.verify_certificate(certificate, verb, links, successor_id, expected_expiry)
                metadata = self.audit(operator, "certificate.issued", resource_id(certificate), WRITER)
                require(metadata["source_certificate_id"] == source
                        and metadata["previous_serial_number"] == initial["serial_number"]
                        and metadata["successor_serial_number"] == certificate["serial_number"],
                        f"{verb}: audit serial linkage mismatch")
                successors.append(certificate)

            require(len({cert["serial_number"] for cert in [initial, *successors]}) == 3
                    and self.sign_calls(operator) == 3, "expected three distinct signed certificates")
            revoke = {"reason": "superseded"}
            self.request("POST", cert_path + "/revoke", reader, 403, revoke)
            require(self.request("GET", cert_path, reader, 200) == initial,
                    "denied revoke changed the source certificate")
            revoked = self.request("POST", cert_path + "/revoke", operator, 200, revoke)
            require(revoked["status"] == "revoked" and revoked["id"] == source
                    and revoked["serial_number"] == initial["serial_number"]
                    and revoked["certificate_pem"] == initial["certificate_pem"],
                    "revocation did not preserve the source certificate and serial")
            self.request("POST", cert_path + "/revoke", operator, 409, revoke)
            inventory = self.request("GET", "/certificates", reader, 200)
            require(len(inventory) == 3 and {resource_id(cert): cert for cert in inventory} ==
                    {resource_id(cert): cert for cert in [revoked, *successors]},
                    "post-revocation inventory did not preserve all certificate states")
            self.audit(operator, "certificate.revoked", source, OPERATOR)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="start the real disposable lifecycle")
    parser.add_argument("--authorized-runner", action="store_true",
                        help="attest owner approval for this runner, temporary keys and SQLite")
    args = parser.parse_args()
    report = {
        "preflight": "NOT_RUN", "live": "NOT_RUN", "cleanup": "no live resources created",
        "profile": "community-openssl", "database": "sqlite", "auth": "api_key",
        "command": "python3 scripts/m1-acceptance/run.py"
                   + (" --live" if args.live else "")
                   + (" --authorized-runner" if args.authorized_runner else ""),
        "cases": [{"case_id": name, "expected": expected, "actual": None,
                   "status": "NOT_RUN", "commands": []} for name, expected in CASES.items()],
        "artifacts": {}, "certificates": {},
    }
    run = None
    try:
        if args.live and not args.authorized_runner:
            report["reason"] = "--authorized-runner is required for live execution"
        else:
            binaries = preflight(report)
            if binaries is None:
                report["reason"] = "preflight prerequisites missing"
            elif not args.live:
                report["preflight"] = "PASS"
                report["reason"] = "preflight only"
            else:
                require(not report["dirty"], "live execution requires a clean checkout")
                report["preflight"] = "PASS"
                report["live"] = "FAIL"
                report["cleanup"] = "cleanup incomplete"
                os.umask(0o077)
                with tempfile.TemporaryDirectory(prefix="anopki-m1-", dir="/tmp") as scratch:
                    run = Run(Path(scratch), binaries, report)
                    with run.service():
                        run.lifecycle()
                report["cleanup"] = "service stopped and private scratch removed"
                report["live"] = "PASS"
    except (CheckFailed, OSError, subprocess.SubprocessError, HTTPException,
            IndexError, KeyError, ValueError, TypeError, KeyboardInterrupt) as failure:
        # Do not emit arbitrary error strings, command stderr, or raw HTTP responses.
        report["reason"] = str(failure) if isinstance(failure, CheckFailed) else type(failure).__name__
        if report["live"] == "FAIL":
            if run is not None and not run.work.exists():
                report["cleanup"] = ("service stopped and private scratch removed" if run.stopped
                                     else "private scratch removed; service shutdown unconfirmed")
            if run is not None and run.case["status"] != "PASS":
                run.case.update(status="FAIL", actual=report["reason"])
        else:
            report["preflight"] = "FAIL"
    print(json.dumps(report, indent=2))
    return int("FAIL" in (report["preflight"], report["live"]))


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
