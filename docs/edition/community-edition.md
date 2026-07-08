# Community Edition Boundary

AnoPKI Community is the public upstream edition. It uses the OpenSSL-backed C++
core as the active crypto implementation and keeps the AnoCrypto work as an
architectural direction until parity evidence exists.

## Public repository content

Keep in Community:

- lifecycle API and core CLI source,
- OpenAPI and core CLI contracts,
- security policy, threat model, roadmap, release evidence, and ADRs,
- test fixtures and smoke harnesses that do not contain real production secrets,
- docs required by users, operators, contributors, and security reviewers.

Keep out of Community:

- proprietary Enterprise overlay source,
- AnoCrypto C99 implementation and certification evidence,
- customer-specific deployment packages,
- commercial licensing terms,
- private support, SLA, and pricing material.
