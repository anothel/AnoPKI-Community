# AnoPKI Rename Migration Runbook

This runbook is for operators migrating from the previous `modern-pki` development name to **AnoPKI**.

## Required changes

1. Rename the core CLI reference from `modern-pki-core` to `anopki-core`.
2. Rename the service command from `modern-pki-service` to `anopki-service`.
3. Replace `MODERN_PKI_` environment variables with `ANOPKI_` variables.
4. Replace webhook receiver headers from `X-Modern-PKI-*` to `X-AnoPKI-*`.
5. Replace local database filenames such as `modern-pki.db` with `anopki.db` for new deployments.
6. Update internal runbooks, dashboards, alerts, CI artifact names, and release notes.

## Verification

Run:

```powershell
python scripts\validate-docs.py
python scripts\validate-version-metadata.py
python scripts\validate-release-evidence.py
python scripts\validate-release-artifacts.py dist
```

For full local verification:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-local.ps1
```

## Compatibility note

This rename is intentionally explicit. Do not silently mix `MODERN_PKI_*` and `ANOPKI_*` configuration in production environments without a documented compatibility window.
