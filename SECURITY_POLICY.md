# Security Policy

## Purpose

INVISABLE Guardian is a controlled, lawful, **defensive-only** platform that tests
INVISABLE-owned apps, APIs, repos, staging systems, and user-safety workflows. It exists
to protect vulnerable users and to strengthen INVISABLE systems.

## Scope of authorised testing

Guardian may only act against assets that are:

1. Listed in an approved scope file under `scope/` (see [SCOPE_SCHEMA.yaml](SCOPE_SCHEMA.yaml)).
2. Verified as INVISABLE-owned (DNS / repo ownership check).
3. Targeted using **test accounts only** (`scope/test_accounts.yaml`).

Anything outside an approved scope is out of bounds. See [GUARDRAILS.md](GUARDRAILS.md).

## Reporting a vulnerability

If you discover a vulnerability in an INVISABLE asset:

1. Do **not** disclose publicly.
2. Open a private security issue or email the security team at `security@invisable.co.uk`.
3. Include affected asset, reproduction steps, and impact. Do not include real user data.

Guardian-generated findings are filed automatically as draft issues/PRs with evidence
attached (`reports/`), and routed to the Human Approval Agent.

## Self-healing workflow (no silent production changes)

Guardian may **propose** fixes. It must **never** silently change production.

1. **Detect** weakness
2. **Create issue**
3. **Generate patch branch**
4. **Add regression tests**
5. **Run unit tests**
6. **Run integration tests**
7. **Run security tests**
8. **Run safeguarding tests**
9. **Generate evidence report** (`reports/`)
10. **Open pull request** (draft)
11. **Wait for human review** (Human Approval gate)
12. **Deploy behind a feature flag** only after approval
13. **Monitor**
14. **Roll back automatically** if safety checks fail

This workflow is encoded in `.github/workflows/guardian-ci.yml` and the
Patch Proposal / Test Runner / Evidence Report / Human Approval agents.

## Data handling

- No real user data is read, stored, or exported.
- Test accounts and synthetic data only.
- Evidence reports must be scrubbed of secrets/PII before storage.
- Audit logs are retained as tamper-evident evidence.

## Human approval

High-impact actions (`production_scan`, `high_volume_test`, `account_locking_test`,
`data_export_test`, `admin_permission_test`) and **all** code changes require recorded
human approval before execution/merge. The Human Approval Agent will not auto-approve.
