# Core CLI JSON Contract

This document defines the JSON fields shared by the Go service core runner and
the C++ `anopki-core` CLI. Field names are wire format: changing them is a
compatibility change and must update both sides plus validator tests.

Binary inputs and outputs are passed as files and are intentionally excluded:
CSR PEM, issuer/responder PEM, OCSP request DER, and OCSP response DER are file
payloads at the process boundary.

## JSON Payloads

### issue request

- Direction: Go service to C++ core, `cert issue --request`.
- Go source: `IssueRequest`.
- C++ source: `issue_request_from_json`.
- `csr_pem`
- `issuer_certificate_pem`
- `issuer_key_ref`
- `aia_url`
- `crl_distribution_points`
- `subject`
- `dns_names`
- `ip_addresses`
- `not_before`
- `not_after`
- `signature_algorithm`
- `profile_id`
- `basic_constraints_critical`
- `basic_constraints_ca`
- `basic_constraints_max_path_len`
- `key_usage_critical`
- `key_usage`
- `extended_key_usage_critical`
- `extended_key_usage`
- `subject_key_identifier`
- `authority_key_identifier`

### issue result

- Direction: C++ core to Go service, `cert issue --out`.
- Go source: `IssueResult`.
- C++ source: `issue_result_to_json`.
- `certificate_pem`
- `serial_number`
- `subject`
- `not_before`
- `not_after`

### csr inspect result

- Direction: C++ core to Go service, `csr inspect --out json`.
- Go source: `CSRInfo`.
- C++ source: `csr_info_to_json`.
- `subject`
- `dns_names`
- `ip_addresses`
- `public_key_algorithm`
- `public_key_size_bits`
- `signature_algorithm`
- `extension_oids`

### crl request

- Direction: Go service to C++ core, `crl generate --request`.
- Go source: `crlFileRequest`.
- C++ source: `crl_request_from_json`.
- `issuer_certificate_pem`
- `issuer_key_ref`
- `crl_number`
- `this_update`
- `next_update`
- `revoked_serial_numbers`
- `revoked_at_times`
- `revocation_reasons`

### crl result

- Direction: C++ core to Go service, `crl generate --out`.
- Go source: `GenerateCRLResult`.
- C++ source: `crl_result_to_json`.
- `crl_pem`

### ocsp certificate id

- Direction: C++ core to Go service, nested under `ocsp inspect` certificates.
- Go source: `OCSPCertificateID`.
- C++ source: `ocsp_info_to_json`.
- `serial_number`
- `issuer_name_hash`
- `issuer_key_hash`
- `hash_algorithm`

### ocsp inspect result

- Direction: C++ core to Go service, `ocsp inspect --out`.
- Go source: `OCSPRequestInfo`.
- C++ source: `ocsp_info_to_json`.
- `certificates`
- `has_nonce`
- `nonce_hex`

### ocsp issuer info

- Direction: C++ core to Go service, `ocsp inspect-issuer --out`.
- Go source: `OCSPIssuerInfo`.
- C++ source: `ocsp_issuer_info_to_json`.
- `issuer_name_hash`
- `issuer_key_hash`
- `hash_algorithm`

### ocsp responder validation result

- Direction: C++ core to Go service, `ocsp validate-responder --out`.
- Go source: `ValidateOCSPResponderResult`.
- C++ source: `ocsp_responder_validation_to_json`.
- `valid`

### ocsp response request

- Direction: Go service to C++ core, `ocsp respond --request`.
- Go source: `ocspResponseFileRequest`.
- C++ source: `ocsp_response_request_from_json`.
- `issuer_certificate_pem`
- `issuer_key_ref`
- `this_update`
- `next_update`
- `serial_numbers`
- `hash_algorithms`
- `issuer_name_hashes`
- `issuer_key_hashes`
- `statuses`
- `revoked_at_times`
- `revocation_reasons`

### backend info result

- Direction: C++ core CLI to operator/release tooling, `backend info`.
- `product_profile`
- `edition`
- `selected_backend`
- `fallback_enabled`
- `backend_id`
- `backend_dependency`
- `backend_version`
- `backend_readiness`
- `backend_capabilities`
- `backend_abi_version`
- `backend_build_fingerprint`

### command error

- Direction: C++ core to Go service, stderr on failed commands.
- Go source: `commandErrorPayload`.
- C++ source: `write_error`.
- `code`
- `message`
- `openssl_errors` (current Community/OpenSSL diagnostic field; omitted when the OpenSSL error queue is empty)

`code` and `message` are the stable cross-adapter contract. `openssl_errors` is
an OpenSSL-profile diagnostic and must not become a required field for other
adapters. The AnoCrypto-C profile must use stable backend error codes and
redacted operator diagnostics; it must not populate `openssl_errors` or retry
the operation through OpenSSL. A future backend-neutral diagnostic extension is
a compatibility change and must update both sides and validator tests.

## Stable Backend Errors

Product-profile and adapter control failures use these stable codes:

- `backend.capability_unavailable`
- `backend.dependency_unavailable`
- `backend.version_incompatible`
- `backend.initialization_failed`
- `backend.module_not_operational`
- `backend.profile_mismatch`
- `backend.operation_failed`

`backend info` reports the build-selected product profile, adapter identity,
dependency version, readiness, capabilities, ABI metadata, and the explicit
`fallback_enabled` value. It does not change any existing issuance/status wire
payload.
