# Edition Boundary Matrix

| Area | Community | Enterprise |
| --- | --- | --- |
| Repository | Public `anopki-community` | Private `anopki-enterprise` |
| License | MPL-2.0 | Commercial overlay plus upstream MPL obligations |
| Crypto backend | OpenSSL-backed C++ core | AnoCrypto direction with OpenSSL fallback until parity closes |
| KCMVP material | Not included | Private preparation and submission evidence |
| Key providers | Interfaces, semantics, tests, local file provider | HSM/KMS/PKCS#11 implementations when selected |
| Auth and access | API key scopes | SSO/OIDC/SAML, RBAC/ABAC, approval workflows |
| Deployment | Manual/API-driven | Productized deploy adapters and rollback checks |
| Audit | Baseline audit | Tamper evidence, SIEM export, compliance reporting |
| Support | Community issue workflow | Commercial support and release channels |
