# RFC 8555 conformance matrix

This matrix tracks implemented ACME protocol behavior in `anopki-service`.

| Area | RFC 8555 behavior | Status | Evidence |
| --- | --- | --- | --- |
| Directory | Advertise nonce, account, order, key-change, and revoke-cert endpoints | Pass | `TestACMEProtocolDirectoryAndNonce` |
| Nonce | Issue `Replay-Nonce`, reject replay, allow badNonce retry | Pass | `TestACMEProtocolRejectsReplayNonce`, `TestACMEProtocolBadNonceRetry` |
| JWS | Require exact request URL, one of `kid` or `jwk`, supported alg, valid signature | Pass | `TestACMEProtocolMalformedJWSProblemResponses` |
| Account create | Create/reuse account by key thumbprint | Pass | `TestACMEProtocolAccountManagementReusesUpdatesAndDeactivatesAccount` |
| Account update/deactivate | Contact update and deactivation | Pass | `TestACMEProtocolAccountManagementReusesUpdatesAndDeactivatesAccount` |
| Account key rollover | Nested key-change JWS signed by new key and authorized by old key | Pass | `TestACMEProtocolAccountKeyRollover` |
| Orders | Create order, authorizations, finalize URL, expiration | Pass | `TestACMEProtocolOrderChallengeAndFinalize` |
| Authorizations | POST-as-GET and challenge listing | Pass | `TestACMEProtocolCertbotCompatibilityFixture` |
| HTTP-01 | Key authorization validation, challenge `Link: rel="up"`, and polling behavior | Pass | `TestValidateACMEHTTP01ChallengeVerifiesKeyAuthorizationAndPromotesOrder`, `TestACMEProtocolCertbotCompatibilityFixture`, live lego and certbot smoke |
| Finalize | RFC `csr` payload, empty-subject SAN CSR handling, and local `csr_pem` compatibility payload | Pass | `TestACMEProtocolFinalizesRFC8555CSRPayload`, `TestNormalizeACMEFinalizeRequestDefaultsSubjectFromCSRIdentifier`, compatibility fixture |
| Certificate download | PEM certificate chain via GET and POST-as-GET | Pass | `TestACMEProtocolCertbotCompatibilityFixture` |
| Revocation | DER certificate, optional numeric reason, issuing-account or matching certificate-key authorization | Partial support | Live pinned Certbot and lego; omitted-reason protocol probe; exact DER/JWS/replay/transaction/native reason tests. Other-account identifier authorization deferred under #31. [Scope and evidence](acme-revocation.md) |
| Rate limits | Rate-limit account, order, challenge, and finalize POST paths | Pass | `TestACMEProtocolRateLimitsAccountRequests` |
| External Account Binding | EAB for external subscriber/account integration | Deferred | No real subscriber/account integration selected |
| DNS-01 | DNS challenge validation | Deferred | No operator-owned DNS provider integration selected |
| certbot live smoke | Linux/elevated Windows live client run | Pass | WSL certbot 5.6.0 HTTP-01 webroot smoke |
| Certbot forced renewal | New order using saved account and renewal lineage | Scoped evidence | `ACME Certbot forced renewal HTTP-01`: pinned 5.6.0 ordinary not-due skip, then real `renew --force-renewal`; [scope and limits](acme-client-compatibility.md#certbot-forced-renewal-evidence) |
