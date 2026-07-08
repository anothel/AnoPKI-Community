# Renewal Runbook

## Normal Renewal

1. Review expiry SLO and expiration scan output.
2. Confirm owner and deployment target.
3. Request renewal for the existing certificate.
4. Approve generated enrollment.
5. Issue replacement certificate.
6. Deploy replacement using the selected deployment process.
7. Confirm old certificate is no longer active before revocation or expiry.

## Failure Handling

- If renewal cannot finish before expiry, notify owner and platform/security
  channels.
- If signing failed after claim, inspect issuance attempt before retry.
- If deployment failed, keep old certificate active when still valid.

## Gaps

- Automated deployment adapter.
- Post-deploy synthetic health check.

