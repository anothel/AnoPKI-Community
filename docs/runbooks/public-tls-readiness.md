# Public TLS Readiness Runbook

## Validity Ceilings

Public TLS issuance must enforce configurable maximum certificate validity:

| Era start | Certificate max | Domain/IP validation reuse max |
| --- | ---: | ---: |
| 2026-03-15 | 200 days | 200 days |
| 2027-03-15 | 100 days | 100 days |
| 2029-03-15 | 47 days | 10 days |

Private PKI profiles may use different limits. Public TLS profiles must not.
Set certificate profiles with `public_tls=true` to enforce these limits. Leave
`ANOPKI_PUBLIC_TLS_MAX_VALIDITY` unset to use the schedule above, or set it
to a shorter positive duration for an emergency or operator-specific ceiling.

## Validation Reuse

Track Domain/IP validation reuse age separately from certificate `not_after`.

- Certificate validity answers: how long this cert can live.
- Validation reuse answers: whether existing domain/IP control evidence can authorize a new cert.

Renewal must fail closed when validation evidence age exceeds the active era limit.

## CAA Checks

Where public TLS issuance is enabled:

- Configure `ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN` and
  `ANOPKI_PUBLIC_TLS_CAA_RESOLVER` before enabling public TLS profiles.
- Query CAA for DNS identifiers before issuance.
- Treat DNSSEC bogus/indeterminate answers as policy failures unless
  `ANOPKI_PUBLIC_TLS_CAA_ALLOW_DNSSEC_INDETERMINATE=true` is explicitly set.
- Enforce RFC 8657 `accounturi` and `validationmethods` parameters when records
  include them.
- Store validation evidence references in audit metadata.

## Mass-Revocation Tabletop

Checklist:

- Identify affected issuer, profile, SAN set, serials, owners, and deployment targets.
- Freeze affected issuance paths.
- Revoke affected certificates and publish CRLs.
- Verify OCSP returns revoked for sampled serials.
- Notify owners through webhook/outbox and operator channels.
- Track replacements through `GET /operator/expiry-slo` and inventory.
- Record audit gaps and repair only supported issuance audit gaps with `POST /audit-events/repair/issuance`.
