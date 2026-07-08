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
| Revocation | Revoke issued certificate through ACME endpoint | Pass | `TestACMEProtocolOrderChallengeAndFinalize` |
| Rate limits | Rate-limit account, order, challenge, and finalize POST paths | Pass | `TestACMEProtocolRateLimitsAccountRequests` |
| External Account Binding | EAB for external subscriber/account integration | Deferred | No real subscriber/account integration selected |
| DNS-01 | DNS challenge validation | Deferred | No operator-owned DNS provider integration selected |
| certbot live smoke | Linux/elevated Windows live client run | Pass | WSL certbot 5.6.0 HTTP-01 webroot smoke |
