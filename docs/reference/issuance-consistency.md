# Issuance Consistency

Certificate issuance uses a DB-backed `certificate_issuance_attempts` record keyed by `enrollment_id`.

## Signing Claim

Before calling the core signer, the service creates or takes a `signing` attempt with a short lease. A second service node that sees an unexpired `signing` lease rejects the request with an invalid lifecycle transition and does not call the signer.

Expired `signing` leases can be taken over by a later request. This is the recovery path for a service process that stopped before storing signed material.

## Signed Material Recovery

After the signer returns, the service stores the certificate PEM, serial, subject, validity window, and planned certificate ID in the issuance attempt as `signed`. If DB finalization later fails, a retry or restarted service finalizes from that stored `signed` attempt without signing again.

If signed material cannot be persisted after signing succeeds, the service returns the storage error. The signed certificate is not recoverable from the service DB. The attempt remains recoverable only after its signing lease expires, at which point retry can sign again. Operators should treat this as a storage incident and investigate possible external serial gaps at the issuer.

## Finalization And Audit Repair

Finalization updates the enrollment to `issued`, creates the certificate, and marks the attempt `finalized` in one DB transaction. The `certificate.issued` audit event is written after finalization so audit failure cannot roll back issued state.

If `certificate.issued` is missing for an already stored certificate, either retrying issuance for that enrollment or calling:

```text
POST /audit-events/repair/issuance
```

repairs the missing audit event. The repair endpoint requires operator scope in API key mode and returns `repaired_count`.
