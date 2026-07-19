# Access Model

This is the selected human RBAC/ABAC model for the pre-1.0 service. Current
enforcement still uses API key scopes: `read`, `write`, and `operator`.

## Human Roles

| Role | Purpose | Minimum API scope |
| --- | --- | --- |
| Requester | Creates identities and enrollment requests for owned services. | `write` |
| Approver | Reviews and approves or rejects enrollment requests. | `write` |
| Operator | Manages issuers, profiles, revocation, CRL/OCSP, outbox, inventory, and API keys. | `operator` |
| Auditor | Reads audit events, inventory, expiry SLOs, and evidence packs. | `read` for lifecycle data; `operator` until audit-only scope exists |
| Break-glass | Time-limited emergency operator for incident response. | `operator` with short expiry |

## ABAC Attributes

Use these attributes for future policy checks and audit review:

- `owner`
- `team`
- `service`
- `environment`
- `deployment_target`
- `identity_id`
- `issuer_id`
- `profile_id`

Requester and approver should not be the same human for production public TLS
or high-risk issuer/profile changes.

## Break-Glass Rules

- Create a named API key with `operator` scope and short `expires_at`.
- Use actor names prefixed with `break-glass-`.
- Record incident ID in external incident notes until audit reason fields exist.
- Rotate or disable the key after the incident.
- Review all audit events for that actor before closing the incident.

## Implementation Trigger

Add first-class role and ABAC enforcement when a real identity provider or
operator directory is selected. Until then, map API keys to human actors and
use scopes plus audit review.

## Generic Authorization Extension Boundary

Community enforcement remains the API-key `read`, `write`, and `operator` scope model.
An optional `httpapi.RequestAuthorizer` may evaluate a protected route only after
authentication and scope checks succeed. It receives canonical route metadata and
redacted request context, not credentials, cookies, bodies, query values, or path
parameter values.

The call has a two-second default deadline and fails closed on timeout, cancellation,
evaluator error, empty outcome, `deny`, or `approval_required`. Implementations must
honor context cancellation and must not fall back to another policy engine. Public
CRL, OCSP, and RFC 8555 protocol routes keep their existing protocol controls and do
not invoke this seam. `GET /debug/vars` is operator-scoped in API-key mode.

This boundary is not a Community RBAC/ABAC, OIDC/SAML, approval-workflow, or
commercial entitlement implementation. Product-specific policy remains outside the
Community repository.
