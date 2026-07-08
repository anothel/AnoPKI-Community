# Manual Enrollment Lifecycle Demo

This demo proves the MVP lifecycle path:

1. Create an issuer.
2. Create an identity.
3. Submit a CSR enrollment.
4. Approve the enrollment.
5. Issue a certificate through `anopki-core`.
6. List certificate inventory.
7. Revoke the certificate.
8. List audit events.

The repository owner runs all commands.

## Build Core CLI

```powershell
cmake -S . -B build
cmake --build build
```

Use the produced executable path for `ANOPKI_CORE_BIN`. On the default Windows multi-config generator this is usually:

```powershell
..\build\Debug\anopki-core.exe
```

## Create Demo Key Material

Run from the repository root:

```powershell
New-Item -ItemType Directory -Force .tmp-demo | Out-Null
openssl ecparam -name prime256v1 -genkey -noout -out .tmp-demo\issuer.key
openssl req -new -x509 -key .tmp-demo\issuer.key -days 365 -subj "/CN=AnoPKI-demo-ca" -out .tmp-demo\issuer.crt
openssl ecparam -name prime256v1 -genkey -noout -out .tmp-demo\leaf.key
openssl req -new -key .tmp-demo\leaf.key -subj "/CN=edge-01" -out .tmp-demo\leaf.csr
```

## Start Service

Run from `service\` in a separate terminal:

```powershell
$env:ANOPKI_ADDR = ":8080"
$env:ANOPKI_DB_DRIVER = "sqlite"
$env:ANOPKI_DB_DSN = "anopki.db"
$env:ANOPKI_CORE_BIN = "..\build\Debug\anopki-core.exe"
go run .\cmd\anopki-service
```

## Run Lifecycle Flow

Run from the repository root:

```powershell
$base = "http://localhost:8080"
$headers = @{ "X-Actor" = "demo-admin" }

$issuer = Invoke-RestMethod -Method Post -Uri "$base/issuers" -Headers $headers -ContentType "application/json" -Body (@{
    name = "demo-intermediate"
    kind = "intermediate_ca"
    certificate_pem = Get-Content -Raw .tmp-demo\issuer.crt
    key_ref = (Resolve-Path .tmp-demo\issuer.key).Path
} | ConvertTo-Json)

$identity = Invoke-RestMethod -Method Post -Uri "$base/identities" -Headers $headers -ContentType "application/json" -Body (@{
    type = "machine"
    name = "edge-01"
    external_id = "asset-edge-01"
} | ConvertTo-Json)

$enrollment = Invoke-RestMethod -Method Post -Uri "$base/enrollments" -Headers $headers -ContentType "application/json" -Body (@{
    identity_id = $identity.id
    issuer_id = $issuer.id
    csr_pem = Get-Content -Raw .tmp-demo\leaf.csr
    requested_subject = "CN=edge-01"
    requested_dns_names = @("edge-01.example.test")
    requested_ip_addresses = @("127.0.0.1")
    requested_not_after = (Get-Date).ToUniversalTime().AddDays(30).ToString("o")
} | ConvertTo-Json)

$approved = Invoke-RestMethod -Method Post -Uri "$base/enrollments/$($enrollment.id)/approve" -Headers $headers

$certificate = Invoke-RestMethod -Method Post -Uri "$base/certificates" -Headers $headers -ContentType "application/json" -Body (@{
    enrollment_id = $approved.id
} | ConvertTo-Json)

Invoke-RestMethod -Method Get -Uri "$base/certificates"

$revoked = Invoke-RestMethod -Method Post -Uri "$base/certificates/$($certificate.id)/revoke" -Headers $headers -ContentType "application/json" -Body (@{
    reason = "key_compromise"
} | ConvertTo-Json)

Invoke-RestMethod -Method Get -Uri "$base/audit-events"
```

Expected result: the certificate status starts as `valid`, revocation changes it to `revoked`, and audit events include issuer, identity, enrollment, approval, issuance, and revocation actions.

Audit metadata field semantics are documented in [audit-metadata.md](../reference/audit-metadata.md).
