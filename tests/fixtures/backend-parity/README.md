# Crypto Backend Parity Fixture

`manifest.txt` is backend-neutral and line-oriented: UTF-8 `key=value`, blank
lines and `#` comments ignored. `format.version` changes only for incompatible
format changes.

Each `operation.<name>.comparison` is `semantic` or `exact_der`. Semantic cases
compare stable decoded fields. Exact DER cases compare complete encoded bytes;
none are active yet because this harness generates fresh keys.

Harness results are `semantic_equal`, `exact_der_equal`,
`unsupported_pending`, or `failure`. OpenSSL runs all five operations. A future
backend may report `unsupported_pending` with an explicit reason until its
implementation can consume the same fixture.
