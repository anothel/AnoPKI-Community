# CA Hierarchy

## Current Model

- Issuers can be root or intermediate CA records.
- Issuers can link to a parent issuer.
- Trust anchors can be exported.
- Issuer chains can be exported.
- CRL and OCSP status derive from service inventory and issuer state.

## Production Rules

- Root CA private key should be offline unless this project explicitly owns an
  online-root operating model.
- Intermediate CAs should be separated by purpose and environment.
- Production issuer and responder keys should use non-exportable HSM/KMS or
  PKCS#11-backed references.
- Backups must preserve issuer metadata and `key_ref`, not private key bytes.

## Gaps

- HSM/KMS/PKCS#11 signing boundary.
- Intermediate rollover operating model.
- Key ceremony evidence and dual-control procedure.

