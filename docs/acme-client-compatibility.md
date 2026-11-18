# ACME client compatibility

Only verified or deliberately blocked client states belong here. Evidence below
is for development after the published alpha.1; it does not expand that release.

## Verified scenario map

The sections below own client scope and limitations; revocation semantics and
results live in the [dedicated revocation reference](acme-revocation.md).
All live CI scenarios use isolated Linux/SQLite/Community OpenSSL and local
HTTP-01 responders. They do not establish public DNS/port-80 operation,
DNS-01, EAB, production readiness or general RFC 8555 conformance.

| Scenario | Verified scope | Exact post-merge evidence |
| --- | --- | --- |
| Single-name issuance | Pinned lego v4.35.2 and Certbot/acme 5.6.0; account through certificate retrieval | PRs [#24](https://github.com/anothel/AnoPKI-Community/pull/24)/[#25](https://github.com/anothel/AnoPKI-Community/pull/25); [CI 43758808293](https://github.com/anothel/AnoPKI-Community/actions/runs/43758808293) at `13adc2bf643d6a764c65c6cae86ca8a40de5389d` |
| Two-name issuance | Both clients; exactly two valid DNS authorizations and exact SANs | [#26](https://github.com/anothel/AnoPKI-Community/pull/26); [CI 43791064443](https://github.com/anothel/AnoPKI-Community/actions/runs/43791064443) at `3fd23a579b15738f15a79ef54a0c6adb23335a54` |
| Certbot renewal | Ordinary not-due skip, then forced single-name renewal with saved account/lineage | [#27](https://github.com/anothel/AnoPKI-Community/pull/27); [CI 43880094164](https://github.com/anothel/AnoPKI-Community/actions/runs/43880094164) at `ad29a0c3e219de81c3b90861b98efdf5a52d9fbf` |
| lego renewal | Dynamic not-due skip, ordinary threshold renewal and unconditional renewal | [#28](https://github.com/anothel/AnoPKI-Community/pull/28); [CI 43979370109](https://github.com/anothel/AnoPKI-Community/actions/runs/43979370109) at `0eecee493495534891f5602acd5f1ba0cce0db85` |
| Scoped revocation | [Client/key/reason scenarios and signed status evidence](acme-revocation.md#real-clients-and-signed-status-evidence) | [#32](https://github.com/anothel/AnoPKI-Community/pull/32); [CI 44201929495](https://github.com/anothel/AnoPKI-Community/actions/runs/44201929495) at `28cd7b9a4e02848d9dc37266536f996b361696b1` |

Issue [#21](https://github.com/anothel/AnoPKI-Community/issues/21) remains open
for remaining interoperability scope. The following local reports are separate
from exact-commit CI evidence.

## Issuance environments

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
  ECDSA leaf key. This issuance lane alone does not establish renewal,
  revocation, standalone or live negative ACME protocol cases; separate
  renewal and revocation evidence is linked above. Replay and
  invalid-JWS coverage remains in the existing regression tests. DNS-01, EAB,
  public DNS/port-80 operation and the Windows non-admin gap remain outside it.


## Multi-name HTTP-01 evidence

The separate `ACME multi-name lego HTTP-01` and
`ACME multi-name Certbot HTTP-01` CI jobs exercise fresh two-DNS-name
orders (`edge-01.example.test`, `edge-02.example.test`) with the same pinned
clients as the single-name lanes. These lanes use a local responder override,
throwaway issuer and fresh SQLite database; no public CA or public DNS is used.
The verifier requires exactly one valid order, two distinct valid DNS
authorizations, distinct HTTP-01 tokens and a valid challenge with a validation
timestamp for each name. OpenSSL checks the exact SAN list, issuer trust,
server purpose, current validity, both hostnames and private-key match.
Wrong-hostname and excessive remaining-validity checks must fail.

Reproduce with `bash scripts/acme-smoke/run-live-multisan.sh lego PATH_TO_LEGO
PATH_TO_CORE` or replace `lego` with `certbot` and pass the pinned Certbot path.
Run from the repository root after provisioning the same tools as the existing
single-name jobs, with ports 8080, 5002 and (lego only) 8443 free. All raw
logs and private state are captured under a private temporary directory and
removed on exit; only stage errors and public certificate metadata are printed.
The harness adds an optional `-AdditionalDomain`; its default single-name
behavior and existing lanes are preserved.

Passing these issuance scenarios establishes only fresh two-name HTTP-01
issuance in this isolated configuration. Separate renewal and revocation lanes
are linked above; this lane does not establish multi-name renewal or revocation,
authorization reuse, wildcard/DNS-01, EAB, public DNS/port-80 operation,
production readiness or general RFC 8555 conformance. Service changes are
unnecessary if both live jobs pass; protocol and signing security checks remain
in the unchanged full CI suite. Exact run/commit evidence is recorded in Issue
[#21](https://github.com/anothel/AnoPKI-Community/issues/21).

## Certbot forced renewal evidence

The separate `ACME Certbot forced renewal HTTP-01` lane uses real Certbot/acme
5.6.0, the existing locked dependencies, Linux/Python 3.12, SQLite and the
Community/OpenSSL core. A single local service and responder remain alive
through initial issuance and both renewal commands. The four existing
single-name/two-name issuance lanes are preserved.

The initial 24-hour certificate is **not due** under Certbot 5.6.0's default
half-lifetime rule for certificates lasting less than ten days. Ordinary
`renew` must skip it: zero exit status alone is never counted as renewal.
The subsequent `renew --force-renewal` must issue a second certificate, reuse
the saved account and lineage, rotate the leaf key (Certbot's default), and
advance the archive/live links from version 1 to version 2. Both renewal
invocations restore the server, identifiers, account and webroot from saved
configuration; they receive no replacement enrollment parameters.
The runner does not change clocks, certificate validity, due-date settings,
database contents or saved account keys. Certbot's ARI retry cache may change;
the remaining renewal settings and all account files must be preserved.
The runner rejects Certbot's global/user `cli.ini` defaults before any client
invocation, preventing ambient hooks or renewal options from affecting the run.

The evidence verifier requires exactly two distinct valid orders and
certificates under one valid account, distinct valid DNS authorizations and
HTTP-01 tokens with validation timestamps, and downloaded leaf DER matching
each order's database certificate. OpenSSL verifies both versions against the
actual bootstrap issuer: exact single DNS SAN, hostname, TLS server purpose,
current validity, roughly 24-hour lifetime, at least one hour remaining,
distinct positive serial numbers, each leaf's private-key match, different
leaf public keys, exact downloaded issuer chain and fullchain assembly.
Wrong-hostname and excessive remaining-validity checks must fail.

`TestACMERenewalNewOrderRequiresFreshNonceAndAuthorization` independently
chains response nonces through two orders under the same account, rejects a
consumed first-issuance nonce on renewal newOrder, rejects exact newOrder and
finalize JWS replays, prevents signing before fresh authorization, and
downloads both chains. It is a protocol fixture with a test signer, not live
client negative-request evidence. Existing nonce expiry, cross-node replay,
JWS, authentication, SSRF, bootstrap and signing-security regressions remain
enabled; no protection or service/API/CLI behavior is changed.

Reproduction and private-state handling are documented in the
[smoke README](../scripts/acme-smoke/README.md#pinned-linux-certbot-forced-renewal).
Exact commits, workflow runs and observed results are recorded in Issue #21.
This slice proves forced single-name HTTP-01 renewal and ordinary not-due
skipping. It does not prove ordinary aged-certificate renewal, ARI,
authorization reuse, key reuse, multi-name renewal, restart recovery,
or live malicious-protocol requests, public DNS/port-80 routing,
DNS-01/EAB, production readiness or general RFC 8555 conformance. Signed
alpha.1 remains unchanged; PostgreSQL intermittency #5 remains separate.

## lego renewal evidence

Pinned lego v4.35.2 (including the source-installed `+dev-release` build)
performs initial single-name issuance, `renew --dynamic --no-random-sleep`
not-due skipping, ordinary `renew --no-random-sleep`, then unconditional
`renew --no-random-sleep --days -1`. Its default 30-day threshold makes the
fresh 24-hour leaf due for ordinary renewal; dynamic lifetime calculation is
opt-in. Zero exit status alone is not counted as issuance.

The runner verifies retained account/issuer state, three distinct valid orders
and certificates with fresh authorizations, and OpenSSL trust, SAN, validity,
chain and rotated-key evidence. Reproduction, private-state handling and
transport details are maintained in the
[lego renewal runbook](../scripts/acme-smoke/README.md#pinned-linux-lego-renewal).
This does not establish aged dynamic renewal, ARI, key reuse, multi-name renewal,
restart recovery or live malicious-protocol cases. Revocation is separate.

## Scoped RFC revocation

Pinned Certbot 5.6.0 issuing-account and certificate-key revocation, plus pinned
lego v4.35.2 default-zero and explicit-superseded revocation, are exercised by
separate live CI runners. A separately identified pinned-acme protocol probe
covers omitted reasons; neither CLI's default is presented as omission.
All scenarios verify revoked database/audit/outbox state and actual signed
CRL/OCSP output with OpenSSL. See [request semantics, evidence and
limitations](acme-revocation.md). The certificate-ID/string extension remains
supported. Cross-account identifier authorization remains deferred under #31;
this is partial RFC 8555 support and evaluation-only functionality.
