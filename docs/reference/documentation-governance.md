# Documentation Governance

This document defines what belongs in the public repository, what belongs in internal project sources, and how to retire stale documentation.

## Goals

- Keep public docs accurate for users, operators, contributors, and security reviewers.
- Keep internal analysis and AI-assistant working notes available without turning them into public product commitments.
- Prevent duplicated roadmap, architecture, and runbook content from drifting.
- Make docs-as-code validation protect current facts instead of preserving old plans.

## Public Repository Docs

Commit documents that meet at least one of these criteria:

- A user, operator, security reviewer, or contributor needs it to build, run, evaluate, or safely operate AnoPKI.
- It defines a stable contract: API, CLI, error codes, audit metadata, state transitions, configuration, release evidence, or security behavior.
- It records an architectural or governance decision that future changes must preserve.
- It is release-facing evidence or a runbook that must be reviewed with code changes.

Examples:

- `README.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`
- `docs/INDEX.md`
- `docs/adr/*.md`
- `docs/reference/*.md`
- `docs/security/*.md`
- `docs/policy/*.md`
- `docs/architecture/*.md`
- `docs/runbooks/*.md`
- `docs/operations/*.md`

## Internal Or GPT Project Source Material

Keep these outside public Git unless they are promoted into maintained docs:

- raw repository analysis reports,
- AI-assistant scratchpads and generated document packs,
- dated implementation plans that are already completed,
- broad replacement matrices,
- one-off review logs,
- evidence inventories that duplicate maintained reference docs,
- large planning trees such as `docs/superpowers/`.

These can be uploaded to the AnoPKI GPT project sources so future project chats can use them as context, but they should not be treated as current public documentation unless copied into a maintained document.

## Retirement Rules

- When work is completed, move the durable facts to a reference doc, runbook, ADR, or changelog entry.
- Remove completed tasks from `docs/ROADMAP.md`; the roadmap is future-only.
- Delete or archive dated plans after their useful implementation context has been extracted.
- Keep only one owner for each fact:
  - API facts: `docs/reference/openapi.json`, `service/README.md`, and API validators.
  - Security status: `SECURITY.md`, `docs/security/*`, and release evidence.
  - Release process: `docs/runbooks/release-process.md` and `docs/reference/release-evidence.md`.
  - Crypto direction: `docs/reference/crypto-backend-strategy.md`, `docs/policy/algorithm-policy.md`, and ADRs.

## Review Checklist

Before merging a documentation change:

1. Confirm every linked document exists.
2. Confirm the document does not reintroduce the previous project name except in migration or historical context.
3. Confirm license references say `MPL-2.0`.
4. Confirm current implementation claims are backed by code, tests, or release evidence.
5. Confirm future work is either in `docs/ROADMAP.md` or explicitly marked as a non-goal/deferred item.
6. Confirm internal/GPT-only material is not copied into public docs without being converted into maintained form.
7. Run `python scripts/validate-docs.py` and relevant contract validators.
