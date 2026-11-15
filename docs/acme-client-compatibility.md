# ACME client compatibility

Only verified or deliberately blocked client states belong here.

| Client | OS / shell | Account key | Challenge | Smoke result | Evidence |
| --- | --- | --- | --- | --- | --- |
| lego v4.35.2+dev-release | Linux amd64, PowerShell 7.4.13 | P-256 | HTTP-01 webroot | Pass, isolated Community/OpenSSL | [Phase 5 PR #24](https://github.com/anothel/AnoPKI-Community/pull/24): real client account, order, validation, finalize and certificate download; OpenSSL parsed the returned certificate. |
| lego v4.35.2+dev-release | Windows non-admin PowerShell | P-256 | HTTP-01 webroot | Pass | `scripts/acme-smoke/run-certbot-smoke.ps1 -Client lego -LegoPath .tmp\lego-bin\lego.exe -WorkDir .tmp\acme-smoke-fresh -StartService -Run -DirectoryTimeoutSec 60`; output included `Server responded with a certificate.` |
| certbot 5.6.0 | WSL Ubuntu, PowerShell 7.6.3 | RSA | HTTP-01 webroot | Pass | `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/acme-smoke/run-certbot-smoke.ps1 -CertbotPath /snap/bin/certbot -WorkDir .tmp/acme-smoke-certbot-wsl -StartService -DirectoryTimeoutSec 60 -Run`; output included `Successfully received certificate.` |
| certbot/acme 5.6.0 | Linux amd64, Python 3.12, PowerShell 7.4.13 | RSA | HTTP-01 webroot | Pass, isolated Community/OpenSSL | Real run on `0cad69ed` before adding CI; `ACME live Certbot HTTP-01 smoke` repeats account through retrieval with the locked Python dependencies and OpenSSL issuer/hostname/time/key checks. |
| certbot 5.6.0 | Windows non-admin PowerShell | not reached | HTTP-01 webroot / standalone | Blocked before ACME traffic | certbot exits with `certbot must be run on a shell with administrative rights`; rerun from Linux or elevated Windows. |

Protocol fixture coverage:

- `TestACMEProtocolCertbotCompatibilityFixture` covers directory, nonce,
  account, order, POST-as-GET, HTTP-01 challenge, finalize, and certificate
  chain behavior that the smoke clients exercise.
- `TestNormalizeACMEFinalizeRequestDefaultsSubjectFromCSRIdentifier` covers the
  certbot CSR shape where the CSR subject is empty and the DNS name is carried
  in SAN.
- RSA, P-256, and Ed25519 account-key protocol tests cover local key-type
  compatibility independent of live client support.
- `TestACMEProtocolResponseNonceSequenceAndFinalizeReplay` chains response
  nonces through account, order, authorization polling, challenge, finalization
  and certificate retrieval. It rejects an identical finalize JWS after both
  success and signing failure, and allows a newly signed request with a fresh
  nonce after the signing failure is resolved.

Phase 5's initial live-client failure was a smoke bootstrap configuration
mismatch: its issuer key is RSA, but its profile omitted a signing algorithm,
selecting the service's ECDSA default. The provider correctly rejected signing
with `provider.algorithm_mismatch` (HTTP 502). Lego's HTTP transport retried
the identical signed request, whose already-consumed nonce was correctly
rejected with HTTP 400 `badNonce`, masking the earlier error. The bootstrap
profile now explicitly selects `rsa_with_sha256`; nonce storage, JWS verification,
replay protection and provider algorithm checks are unchanged.

This is isolated evaluation evidence for the implemented HTTP-01 path, not
production readiness or general RFC8555 interoperability. DNS-01 and EAB remain
outside this test. The published alpha.1 release is unchanged.

Certbot evidence classification:

The WSL row is a historical local report, without a locked dependency set or
exact-commit CI run; the new Linux row has reproducible execution evidence.

- `scripts/acme-smoke/test-run-certbot-smoke.ps1` uses a directory stub,
  fake client and fake service to check invocation and exit behavior. It does
  not perform certificate issuance. The Go protocol fixtures similarly use
  test signers and are regression coverage, not external-client execution.
- The Linux `run-live-certbot.sh` runner invokes the real pinned client against
  a fresh SQLite service, native Community/OpenSSL core and local webroot
  responder. It verifies certificate download, fullchain assembly, issuer trust
  against the service database, hostname, current validity, at least one hour
  remaining, and leaf/private-key match using OpenSSL. Wrong-hostname and
  two-day validity checks must fail for the 24-hour smoke certificate.
- Certbot debug logs contain signed request bodies. The runner captures all
  harness output in a mode-0700 temporary directory and deletes it and all
  throwaway state on exit; no raw logs, SQLite files or keys are uploaded.
  Failures expose only the failed stage, so deeper diagnosis requires an
  isolated local reproduction. Certificate metadata is safe console evidence.
- This covers fresh single-name issuance with the default RSA account key and
  ECDSA leaf key. Renewal, revocation, standalone, multi-name orders and live
  negative ACME protocol cases are not established by this lane. Replay and
  invalid-JWS coverage remains in the existing regression tests. DNS-01, EAB,
  public DNS/port-80 operation and the Windows non-admin gap remain outside it.
