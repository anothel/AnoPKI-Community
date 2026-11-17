# ACME certificate revocation

Community/OpenSSL supports an additive, scoped RFC 8555 §7.6 revocation path alongside the existing certificate-ID extension. This remains evaluation-only, with **partial RFC support**: cross-account authorization based on authorizations for every certificate identifier is deferred under [#31](https://github.com/anothel/AnoPKI-Community/issues/31) and fails closed. No complete RFC 8555 conformance or production-readiness claim is made.

## Requests and authority

The advertised `/acme/revoke-cert` accepts two distinct shapes inside the existing signed JWS envelope:

- Legacy: `{"certificate_id":"...","reason":"superseded"}`. Existing ownership checks, string-reason validation, HTTP error behavior and `{}` success response remain in place. Empty reasons and the internal `not_provided` marker remain invalid legacy inputs.
- RFC: `{"certificate":"BASE64URL_DER","reason":4}`, with optional integer `reason`. Strict unpadded base64url, exactly one DER certificate, canonical field names and unambiguous JSON are required. Duplicate or unknown fields, mixed formats, null/noninteger reasons and malformed/trailing certificate data are rejected.

Both paths retain the existing JWS signature, algorithm, exact protected URL and one-time nonce checks. The RFC path adds a separate rate-limit bucket using the existing configured limit/window; the legacy path retains its prior rate behavior.

The RFC path resolves a stored issuer and uses the indexed issuer-ID/serial lookup, then requires exact stored leaf DER equality. A serial, public key or matching issuer name alone cannot identify the target. It does not load the complete certificate inventory for unregistered JWK requests.

RFC authority is limited to:

1. A valid issuing account whose stored order links to the target certificate. Inactive accounts are rejected on the new RFC path; the legacy path is unchanged.
2. A verified JWK whose SubjectPublicKeyInfo equals the target certificate's public key. That key does not need an ACME account. A key shared by another certificate does not bypass exact target DER matching.

Other accounts remain unauthorized, including accounts with identifier authorizations. Revocation authority does not expand for legacy requests or other endpoints. The existing lifecycle state-transition rules, transactional revocation record, audit event and outbox event are reused. Failures roll back those changes together.

RFC success is HTTP 200 with an empty body and fresh `Replay-Nonce`. Unsupported integer reason codes return `badRevocationReason`; authorized attempts to revoke an already revoked certificate return `alreadyRevoked`. These are scoped RFC responses; legacy error mappings remain unchanged. Unauthorized requests are checked before exposing the already-revoked state. Exact replays return `badNonce` after success or rejection.

## Reason semantics and approved internal transport

Supported numeric codes are 0, 1, 2, 3, 4, 5 and 9, mapped to the existing explicit domain reasons. Codes 6, 8 and 10 are not supported by this lifecycle and are rejected. No new certificate-hold/remove-from-CRL authority is introduced.

| RFC input | Stored/audit/outbox/Core reason | CRL/OCSP encoding |
| --- | --- | --- |
| Omitted `reason` | `not_provided` | No CRL entry reasonCode extension; no OCSP revocationReason field |
| Explicit `reason: 0` | `unspecified` | Existing explicit code-0 encoding retained |
| Explicit supported nonzero code | Existing reason string | Existing reason encoding retained |

The owner explicitly approved `not_provided` as an internal absence marker. It is created only by the optional-reason RFC path, through a separate lifecycle entry point; public legacy reason validators exclude it. It is not a numeric reason code or an arbitrary default. The marker round-trips unchanged through SQLite/PostgreSQL TEXT storage, lifecycle reads, audit/outbox JSON and internal Core CLI reason arrays. No schema migration or historical record rewrite is needed.

Only the new marker changes native encoding: CRL skips the per-entry reason extension; OCSP uses OpenSSL's `OCSP_REVOKED_STATUS_NOSTATUS` (-1). Existing empty and `unspecified` Core values retain their prior meaning. This work does not reinterpret historical unspecified values or make a broader PKIX conformance claim about existing explicit-reason behavior.

## Real clients and signed status evidence

The Certbot runner uses locked Certbot/acme 5.6.0 and fresh local issuer/SQLite state for each scenario:

- Genuine `certbot revoke --reason superseded --no-delete-after-revoke` with its saved issuing account.
- Genuine `certbot revoke --key-path LEAF_KEY --reason unspecified --no-delete-after-revoke` with the matching certificate key.
- A separately identified **protocol probe**, using the pinned acme network and a certificate-only payload, tests omitted reason. This probe is not a Certbot CLI omission claim.

The lego runner uses v4.35.2 and fresh state for each scenario:

- Genuine `lego revoke --keep` sends explicit numeric 0.
- Genuine `lego revoke --keep --reason 4` sends superseded.

The pinned lego CLI's `cmd/cmd_revoke.go` always passes a pointer to its numeric flag value. Omitting the CLI flag therefore does **not** omit the wire field. Both CLIs' actual behavior is kept distinct from the omitted-reason protocol probe.

For every scenario, OpenSSL checks downloaded leaf DER against the database, actual issuer trust and hostname. Before revocation, a service-signed CRL and signature-verified OCSP response show good status. After revocation, the verifier requires revoked certificate state, exactly one revocation with the expected reason, matching audit/outbox metadata, a signature-verified CRL causing `openssl verify -crl_check` to fail specifically with `certificate revoked`, and a signature-verified OCSP response reporting revoked. It also checks reason presence/absence in both signed objects, distinguishing `not_provided`, explicit 0 and superseded.

Reproduce from the repository root with the native Community/OpenSSL core and pinned client dependencies installed:

```sh
python scripts/acme-smoke/run_live_revocation.py PATH_TO_CERTBOT_VENV/bin/certbot PATH_TO_CORE
python scripts/acme-smoke/run_lego_revocation.py PATH_TO_LEGO PATH_TO_CORE
```

Both runners use local responders, throwaway keys and private temporary state, capturing raw logs and deleting keys/databases/logs on exit. The lego runner retains the existing throwaway loopback TLS adapter and transport-only `--tls-skip-verify`; issuer trust is independently checked with OpenSSL. No public CA or production credentials are used. No raw private artifacts are uploaded. Abrupt termination can leave state until ephemeral runner teardown.

## Regression coverage and limits

Focused tests cover authorization, exact DER mismatch, malformed/ambiguous payloads, omitted versus explicit reasons, inactive accounts, rate limits, nonce replay after rejection/success, and `alreadyRevoked`. Marker persistence/serialization tests run against memory, SQLite and PostgreSQL parity fixtures. Lifecycle audit/outbox failures test transactional rollback. Native ASN.1 tests verify absence for the marker and unchanged explicit/old-empty encodings. Existing issuance, renewal, signing, authentication, SSRF and replay suites remain enabled.

The historical baseline `bd93661d30f70a503279e4784fee2334fe756ef7` rejected both real Certbot revocation modes with HTTP 400 because it accepted only ID/string requests. The earlier conformance matrix's revocation “Pass” was based on that service extension. Exact new commit, PR/client results, full CI and post-merge evidence are recorded in [#21](https://github.com/anothel/AnoPKI-Community/issues/21).

Other-account identifier authorization (#31), live malicious-client traffic, public DNS/port-80 routing, DNS-01 and EAB remain outside this slice. Audit intermittency [#29](https://github.com/anothel/AnoPKI-Community/issues/29) and PostgreSQL intermittency [#5](https://github.com/anothel/AnoPKI-Community/issues/5) remain independent and unresolved. Signed alpha.1 tags and release assets are unchanged.
