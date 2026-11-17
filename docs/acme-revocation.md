# ACME revocation investigation

At starting main `0eecee493495534891f5602acd5f1ba0cce0db85`, standard revocation is **unsupported**. This corrects the previous conformance matrix's “Pass”, which referred only to an internal service-extension fixture. No runtime contract or authorization change is included in this investigation.

## Actual pinned-client evidence

The isolated `run_live_revocation.py` runner uses Certbot/acme 5.6.0 with the existing locked dependencies, a fresh SQLite service and Community/OpenSSL issuer. Initial HTTP-01 issuance supplies a throwaway target for revocation, not additional issuance/renewal compatibility claims. OpenSSL verifies that leaf against the actual issuer and hostname.

Both real commands fail with HTTP 400 `urn:ietf:params:acme:error:malformed`, detail `invalid request`:

- `certbot revoke --cert-path LEAF --reason superseded --no-delete-after-revoke` uses the retained account key and `kid`.
- The same command with `--key-path LEAF_KEY` uses the matching leaf key and `jwk`.

The runner internally parses each command's private debug-log segment. It requires a JWS addressed to this local revoke endpoint, the expected `kid`/`jwk` form, exactly `certificate` and `reason` payload fields, decoded DER equal to the actual OpenSSL leaf, numeric reason 4, and the exact HTTP problem. After each failure it requires unchanged certificate rows, zero revocations, and the original valid order/authorization/challenge state. Raw logs, keys and database remain inside a private temporary directory and are removed on exit; nothing private is uploaded. Abrupt process termination can leave state until ephemeral runner teardown.

Reproduce from the repository root, with the pinned requirements installed and the native core built:

```sh
python scripts/acme-smoke/run_live_revocation.py PATH_TO_CERTBOT PATH_TO_CORE
```

This is live Certbot evidence. Lego v4.35.2 was inspected at `certificate/certificates.go` (`RevokeWithReason`), `acme/commons.go` (`RevokeCertMessage`) and `acme/api/certificate.go` (`Revoke`): it sends base64url DER in `certificate`, with an optional numeric reason, through the account-signing transport. A live lego revocation execution is not claimed here.

## Why it fails and what remains protected

`httpapi/acme.go` first verifies JWS media type, exact protected URL, supported algorithm, exclusive kid/jwk, one-time nonce, key lookup and signature. Payload decoding then expects `certificate_id` and a required string `reason`. Numeric reason fails JSON decoding; omission still fails because certificate ID/reason are empty. No DER lookup occurs.

`requireACMECertificateAccount` requires a nonempty account ID and an order belonging to that account with the target certificate ID. A verified JWK alone supplies no account ID, so even a matching certificate key cannot authorize this extension. Other accounts cannot revoke through it. Certificates contain PEM, issuer, serial and lifecycle status; order records link certificate IDs to accounts. Lifecycle revocation validates its reason and atomically changes status, records the revocation, audit event and outbox event, rolling back on failure.

`TestACMERevocationContractAndSecurity` pins owner success and duplicate transition rejection, other-account rejection, forged owner signatures, unrelated JWK and owner-JWK-without-kid rejection, malformed standard payloads, invalid reasons and exact JWS replays after both rejection and success. Rejections must leave certificate status and issuer revocation entries unchanged. This repository fixture does not establish live malicious-client coverage or DER parsing support.

The standard request fails before revocation, so no newly revoked serial can be verified in CRL/OCSP as a result of these client commands. Existing CRL/OCSP regressions remain enabled; their results must not be presented as successful ACME revocation. A combined live revocation-to-CRL/OCSP test remains a gap after the contract decision.

## Minimal proposed design — pending owner approval

[RFC 8555 §7.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.6) requires the base64url DER certificate and permits an omitted or numeric reason. It requires acceptance of the issuing account and accounts holding authorizations for all identifiers, and acceptance of the certificate private key, without requiring an ACME account for that key. Current behavior does not provide these semantics.

Proposed additive implementation, **not authorized or implemented by this PR**:

1. Preserve the ID/string extension and all service API/CLI contracts. Add a separate, unambiguous RFC payload shape on the advertised endpoint. Reject mixed certificate/ID formats; validate strict DER, encoding and numeric reason types. Define supported reason codes and omitted-reason semantics explicitly rather than silently mapping to an existing string default.
2. Resolve DER to one stored certificate by issuer identity and serial, then require exact DER equality. Never trust a caller-selected serial or public key alone. Reject malformed, foreign and unknown certificates without changing state.
3. Keep the existing issuing-account ownership check for kid requests. Supporting other accounts with authorizations for every identifier requires explicit authorization freshness/scope rules; absence of those rules must fail closed and be documented as partial support.
4. For RFC JWK requests only, verify the JWS with that JWK and require its public key to equal the target certificate's SubjectPublicKeyInfo. This is a new authorization path requiring owner approval. Do not expand JWK authority for the existing ID format or other endpoints. Preserve nonce consumption, signature/algorithm and exact-URL validation.
5. Reuse transactional lifecycle revocation, audit and outbox. Specify RFC `alreadyRevoked`, unauthorized and bad-reason errors without changing legacy error contracts. Add actual client success lanes, security negatives for malformed DER/unrelated keys/foreign issuers/replays, and real CRL/OCSP/OpenSSL evidence before claiming support.

Owner decision required: approve the additive payload/reason/error semantics and certificate-key authorization, and decide whether all-identifiers-authorized accounts are included or explicitly deferred. Until then the endpoint remains incompatible with standard revocation.

Evaluation-only. No production-readiness or general RFC 8555 conformance claim. Existing issuance/renewal lanes, signing/SSRF/authentication guards and signed alpha.1 assets remain unchanged. PostgreSQL #5 and audit incident #29 are independent unresolved issues. Exact PR and CI evidence belongs in Issue #21.
