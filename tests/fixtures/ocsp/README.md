# OCSP Test Vectors

This directory contains curated OCSP request fixtures for core parser and CLI boundary tests.

Do not bulk-copy legacy fixture directories into this tree. Add only reviewed vectors with:

- source or generation note
- license compatibility note
- expected serial number
- expected issuer name hash
- expected issuer key hash
- expected nonce presence

## curated-single-request.der.b64

Generated for AnoPKI test-vector intake. It is not copied from a legacy project.

Expected fields:

```text
serial_number = 1001
issuer_name_hash = 84378ae02c8a13718b0efda0e3a283b0006a4265
issuer_key_hash = d5dcea91c8d109ec61e84d07bea04fab0b720ac3
hash_algorithm = sha1
has_nonce = false
```
