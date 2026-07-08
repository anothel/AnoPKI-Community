# ADR 0002: ACME Adoption

## Status

Accepted baseline.

## Decision

Expose ACME protocol support for automated account, order, HTTP-01 challenge,
finalize, certificate download, revocation, nonce, and account-key rollover
flows.

## Consequences

- ACME is the default automation path for compatible clients.
- DNS-01 waits for a real operator-owned DNS provider integration.
- External Account Binding waits for a real subscriber/account integration.
- Certbot and lego HTTP-01 smoke are compatibility evidence; Windows non-admin
  certbot remains environment-dependent.
