# Bootstrap API Key Runbook

Bootstrap keys exist only to create durable operator-scoped API keys. Remove
the bootstrap key from runtime config after operator keys are created.

## Provision First Operator

1. Generate two secrets outside the repository:
   - `ANOPKI_API_KEY_PEPPER`: long random secret.
   - `ANOPKI_BOOTSTRAP_API_KEY`: one-time operator bootstrap token, at
     least 32 characters.
2. Start one service node with:

```powershell
$env:ANOPKI_ENV = "production"
$env:ANOPKI_AUTH_MODE = "api_key"
$env:ANOPKI_API_KEY_PEPPER = "<32+ chars random secret>"
$env:ANOPKI_BOOTSTRAP_API_KEY = "<one-time bootstrap token>"
$env:ANOPKI_BOOTSTRAP_API_KEY_NAME = "bootstrap"
$env:ANOPKI_BOOTSTRAP_API_KEY_ACTOR = "ops-bootstrap"
```

3. Verify readiness:

```powershell
curl.exe http://localhost:8080/readyz
```

4. Create a named operator key:

```powershell
curl.exe -X POST http://localhost:8080/api-keys `
  -H "Authorization: Bearer <one-time bootstrap token>" `
  -H "Content-Type: application/json" `
  -d '{"name":"ops-admin-1","actor":"ops-admin-1","scopes":["operator"]}'
```

5. Store the returned token in the secret manager. The token is returned once.

## Remove Bootstrap Access

1. Remove `ANOPKI_BOOTSTRAP_API_KEY` from runtime config.
2. Restart every service node.
3. Verify the bootstrap token no longer authenticates.
4. Keep `ANOPKI_API_KEY_PEPPER` unchanged. Changing it before rotating
   existing keys can break HMAC-hashed key lookup.

The bootstrap row can remain disabled or unused in the database. Runtime
removal is the important access-control step.

## Rotate Operator Key

Use an existing operator key:

```powershell
curl.exe -X POST http://localhost:8080/api-keys/<old-key-id>/rotate `
  -H "Authorization: Bearer <operator token>"
```

The old key is disabled and the replacement token is returned once. Update the
secret manager and dependent clients immediately.

## Disable Operator Key

```powershell
curl.exe -X POST http://localhost:8080/api-keys/<key-id>/disable `
  -H "Authorization: Bearer <operator token>"
```

Disabling is irreversible through current APIs. Create or rotate a replacement
instead of expecting to re-enable the same key.

## Expiry Guidance

- Use short expiry for break-glass and automation keys where rotation is
  operationally ready.
- Keep at least two active operator keys held by separate trusted operators.
- Review `last_used_at` and `token_fingerprint` during access reviews.
