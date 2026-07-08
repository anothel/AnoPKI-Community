# Incident Response Runbook

Use this runbook for PKI incidents. Preserve audit evidence first, then reduce
issuance and status-publication risk.

## First Actions

1. Assign one incident lead and one evidence recorder.
2. Stop risky traffic at the gateway if issuance, revocation, or auth behavior
   may be unsafe.
3. Preserve database snapshot, service logs, reverse-proxy logs, key-provider
   audit logs, and webhook delivery records.
4. Record current `GET /version`, `GET /readyz`, and active service nodes.
5. Do not delete audit events, outbox messages, CRL artifacts, OCSP responder
   records, or issuance attempts.

## Mis-Issuance

1. Disable issuance traffic for affected profiles or issuers.
2. Identify affected certificates by issuer, profile, SAN, owner, service, and
   issuance time window.
3. Revoke affected valid or suspended certificates. Use forced revocation only
   when the certificate is suspended and still must be revoked.
4. Publish a fresh CRL with `POST /crls`.
5. Verify OCSP returns `revoked` for sampled affected serials.
6. Notify affected owners through outbox/webhook channels or external incident
   comms.
7. Document policy gap and add a regression test before re-enabling issuance.

## Issuer Or Responder Key Exposure

1. Disable issuance and responder rotation for affected issuers.
2. Preserve key-provider audit logs and identify exposed `key_ref` values.
3. Revoke or distrust affected issuer/responder certificates according to the
   CA hierarchy operating model.
4. Rotate OCSP responders with
   `POST /issuers/{id}/ocsp-responders/rotate` after new key material is ready.
5. Publish new CRLs and verify OCSP behavior.
6. Rotate any API keys or webhook secrets exposed through the same channel.

## CA Outage

1. Check `/readyz`, database reachability, core CLI availability, and active
   issuer key references.
2. Disable issuance if signer or key-provider access is inconsistent.
3. Keep CRL and OCSP distribution online if safe; status publication matters
   during issuer outages.
4. Restore DB/key-provider access using
   [Production Recovery Runbook](production-recovery.md).
5. Run a non-production issuance profile before re-enabling production issuance.

## Failed Renewal

1. Query certificates near expiry and owners from operator inventory.
2. Check expiration scan worker settings and audit events for
   `certificate.expiration_warning`.
3. Retry renewal for affected valid certificates after confirming identity,
   profile, and CSR policy still match.
4. If renewal cannot finish before expiry, notify owner and prepare emergency
   reissue through an approved profile.

## Failed Revocation

1. Identify whether failure is API validation, storage, CRL generation, OCSP
   signing, or distribution.
2. If revocation row exists but CRL publication failed, fix signer/key-provider
   access and call `POST /crls`.
3. If revocation row does not exist, retry revocation after confirming current
   certificate state.
4. Verify newest CRL number and OCSP sampled serials before closing.

## Webhook Outage

1. Check outbox `failed` and `dead_letter` messages.
2. Do not bulk replay mixed event types.
3. Fix receiver TLS, DNS, auth secret, or availability.
4. Replay by event type and bounded time window with
   `POST /outbox/messages/dead-letter/replay`.
5. Confirm receiver signature verification accepts current
   `X-AnoPKI-Signature` values.

## Closure

- Record timeline, impact, root cause, revoked serials, CRL numbers, OCSP
  verification, owner notifications, and follow-up tests.
- Move any discovered future work into [ROADMAP](../ROADMAP.md).
- Keep evidence snapshots according to retention policy.
