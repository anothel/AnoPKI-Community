# OpenSSL Baseline Fixture

This directory records the OpenSSL-backed semantic baseline used before any
AnoCrypto wiring.

The C++ test generates fresh local RSA keys, so exact PEM/DER bytes are not
stable. The checked fixture values are stable request fields and semantic output
fields: subject, SAN, key algorithm, extension OIDs, certificate validity, CRL
number, revoked-count, OCSP CertID fields, OCSP nonce handling, and OCSP response
status.
