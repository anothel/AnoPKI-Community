# Certificate Profile Policy

Certificate profiles are policy-as-code. They must define issuance limits before
signing happens.

## Enforced Today

- Validity ceiling through `validity_period_seconds`.
- Public TLS validity ceilings for 200/100/47-day eras.
- Basic Constraints.
- Key Usage.
- Extended Key Usage.
- Subject Alternative Name DNS/IP patterns.
- CSR public key algorithm allow-list and minimum key size.
- Selected signing algorithm allow-list.
- Profile extension-combination checks reject CA signing key usage on leaf
  profiles and leaf EKUs on CA profiles.
- CSR linting rejects CN-only/missing SAN requests, forbidden CSR-requested Key
  Usage, Extended Key Usage, and Basic Constraints extensions, wildcards without
  an explicit wildcard profile pattern, public TLS IP SANs without an explicit
  profile range, and SAN lists over 100 entries.
- Core CSR fixtures include a real 1024-bit RSA CSR to prove weak-key metadata
  is surfaced before profile policy enforcement.
- Core issuance rejects expired or not-yet-valid issuer certificates and DNS
  SANs outside issuer DNS name constraints before signing.
- Subject Key Identifier and Authority Key Identifier settings.
- Public TLS CAA DNSSEC and RFC 8657 parameter checks.
- Public TLS issuance fails closed unless a pre-signing lint hook accepts the
  enrollment, profile, and inspected CSR metadata.
- Issued DER assertions for SAN, KU, EKU, Basic Constraints, AIA, CRL
  Distribution Points, SKI, and AKI.

## Required Review For New Profiles

- Intended usage: serverAuth, clientAuth, internal mTLS, device, public TLS, or
  future code signing.
- Allowed DNS and IP namespace.
- Wildcard allowance.
- Public TLS flag and validation evidence requirement.
- Expiration window and renewal margin.

## Gaps

- External public TLS lint tool selection and fixture corpus expansion.
