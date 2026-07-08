# CP/CPS Map

This is an evidence map, not a formal CP/CPS.

| CP/CPS area | Current evidence | Gap |
| --- | --- | --- |
| Identity and certificate lifecycle | Service README, OpenAPI, state transitions. | Human approval workflow policy. |
| Certificate profiles | Profile policy docs and tests. | Key/signature algorithm policy. |
| Validation | Identity allow-lists, ACME HTTP-01, public TLS CAA checks. | DNS-01/EAB only after real integration. |
| Key management | `key_ref`, production recovery/deployment docs. | HSM/KMS/PKCS#11 ceremony evidence. |
| Revocation/status | Revocation API, CRL, OCSP, incident runbook. | HA drills and SLA evidence. |
| Audit | Audit metadata reference, query/retention support, tamper-evidence plan, and SIEM detection examples. | Tamper-evident hash-chain implementation and SIEM exporter integration. |
| Operations | Deployment, recovery, incident, public TLS runbooks. | Scheduled tabletop/drill artifacts. |
