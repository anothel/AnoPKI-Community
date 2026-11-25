# Repository agent instructions

Read and follow [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [docs/ROADMAP.md](docs/ROADMAP.md). Preserve Community/Enterprise product boundaries and the existing requirement for explicit Git-write authorization in the current task.

## Codex result handoff

- Check the existing task/issue, its latest authorized scope, the exact base revision, and open PRs before starting or resuming. Do not duplicate active work or silently change an approved baseline.
- Use an isolated task branch/worktree. Follow this repository's existing contribution, test, review, security, and authorization rules; this section grants no additional implementation, Git-write, merge, deployment, or release permission.
- For an authorized task, record the outcome on its existing GitHub issue or PR (including blocked and read-only work). Include task ID, status, base/head SHA, changed files/commits or none, actual test results with PASS/FAIL/BLOCKED/NOT_RUN, CI and Draft PR links if applicable, remaining risks, and the next action. If Jira is in use, link its existing task instead of duplicating the full report.
- Publish only sanitized evidence through an authorized channel. Do not publish credentials, customer data, private paths, or sensitive vulnerability details in public issues or PRs. Use an approved private channel for sensitive evidence.
- If GitHub write access is unavailable or publication is not authorized, report the exact blocker and the minimum safe handoff. Do not bypass access controls, fabricate evidence, or treat a successful workflow as human approval.
- The project manager verifies GitHub evidence and updates project tracking. No agent may impersonate an independent human reviewer or bypass existing merge/release gates.
