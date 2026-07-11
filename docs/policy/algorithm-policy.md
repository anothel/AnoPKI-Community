# Algorithm Policy

## Current Baseline

- SHA-1 issuance is not a supported target.
- Public TLS must follow current CA/Browser Forum Baseline Requirements.
- New weak-algorithm certificates have a target of zero.
- Private key material is outside the service DB/API boundary.
- Certificate profiles can allow-list CSR public key algorithms, require a
  minimum key size, and select allowed signing algorithms.

## Backend And Algorithm Direction

Community/OpenSSL is the current complete public profile.

AnoCrypto-C is a separate external C99 module consumed only through the
Enterprise AnoCrypto-C adapter. AnoPKI must not reimplement AnoCrypto-C
algorithms or describe an adapter skeleton as algorithm support.

Backend selection is explicit:

- OpenSSL profile: OpenSSL is selected and reported from startup.
- AnoCrypto-C profile: only proven AnoCrypto-C capabilities are available.
- Missing capability fails explicitly; OpenSSL is not called automatically.

Algorithm policy and capability reporting must be evaluated for the selected
product profile and exact backend version.

## Required Before Enterprise/AnoCrypto-C Production Expansion

- Complete required Community operation parity.
- Inventory fields for key algorithm, signature algorithm, adapter, backend
  dependency, provider, and relying-party compatibility.
- Stable capability-unavailable and dependency-failure errors.
- Tests proving that unsupported AnoCrypto-C operations do not invoke OpenSSL.
- Migration plans for RSA/ECDSA policy changes.
- Exact release evidence for the AnoCrypto-C SDK version, build, platform, and
  supported algorithms.

## KCMVP Position

KCMVP claims apply only to the exact AnoCrypto-C module shape and evidence, not
automatically to AnoPKI Enterprise as a whole. Until evidence exists, use
`not_validated` and prohibit validation or certified-product claims.

## PQC Position

PQC and hybrid certificates are lab-only until dependencies, providers, TLS
libraries, ingress, service mesh, and client platforms prove compatibility.
