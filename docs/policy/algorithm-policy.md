# Algorithm Policy

## Current Baseline

- SHA-1 issuance is not a supported target.
- Public TLS must follow current CA/Browser Forum Baseline Requirements.
- New weak-algorithm certificates have a target of zero.
- Private key material is outside the service DB/API boundary.
- Certificate profiles can allow-list CSR public key algorithms, require a
  minimum key size, and select allowed signing algorithms.

## Community Backend And Algorithm Direction

Community/OpenSSL is the only runtime profile managed in this project.
Algorithm policy and capability reporting are evaluated against the exact
OpenSSL version and immutable `community-openssl` artifact metadata.

Backend selection is explicit. Missing capability, provider failure, or
algorithm incompatibility fails closed and never switches to another provider,
backend, or product profile.

External adapters such as AnoCrypto-C, their SDK evidence, and KCMVP claims are
outside the Community project. Community must not implement those algorithms,
bundle external SDK material, or describe an external adapter skeleton as
algorithm support.

## Migration Expectations

- Maintain inventory fields for key and signature algorithms.
- Keep RSA/ECDSA policy-change plans and relying-party compatibility evidence.
- Keep RSA/ECDSA provider success, mismatch, binding, and encrypted-key rejection fixtures current when algorithm policy changes.
- Record the exact OpenSSL version, capability set, and build fingerprint for
  every release candidate.

## PQC Position

PQC and hybrid certificates are lab-only until dependencies, providers, TLS
libraries, ingress, service mesh, and client platforms prove compatibility.
