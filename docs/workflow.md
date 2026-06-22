# Self-Healing Workflow

Guardian may **propose** fixes but must **never** silently change production. The full
loop (also in [SECURITY_POLICY.md](../SECURITY_POLICY.md)):

```
 1. Detect weakness            ── connectors / simulators / runtime monitoring
 2. Create issue               ── draft issue with evidence link
 3. Generate patch branch      ── Patch Proposal agent (never edits production)
 4. Add regression tests       ── one test per finding / per simulator vector
 5. Run unit tests             ┐
 6. Run integration tests      │  Test Runner agent — all gates must pass
 7. Run security tests         │  (CodeQL, Semgrep, Trivy, Gitleaks, ZAP)
 8. Run safeguarding tests     ┘  (Playwright safeguarding journeys + simulators)
 9. Generate evidence report   ── Evidence Report agent → reports/generated/
10. Open pull request (draft)  ── all Guardian PRs open as drafts
11. Wait for human review      ── Human Approval gate (never auto-approves)
12. Deploy behind feature flag ── only after approval; never a silent live change
13. Monitor                    ── Runtime Monitoring agent
14. Roll back automatically    ── if post-deploy safety checks fail
```

## Where it's encoded

- CI: `.github/workflows/guardian-ci.yml` runs steps 5–9 on every Guardian PR and
  enforces that the PR is a draft requiring human review (steps 10–11).
- Security gates: `.github/workflows/{codeql,semgrep,gitleaks,trivy}.yml`.
- Approval: `agents.HumanApprovalAgent` + branch protection (review required, no direct
  pushes to protected branches).
- Evidence: `core.evidence.write_report` → `reports/generated/` (Markdown + JSON, scrubbed).

## Recommended stack per layer

See [self_healing_stack.md](self_healing_stack.md) for the recommended tool/framework per
layer (repair brain, workflow engine, code remediation, GitOps, progressive deploy,
policy-as-code, supply-chain proof, test orchestration, runtime monitoring, safe rollback)
and how each plugs into Guardian.

## Gate summary (must all hold before merge)

| Gate | Enforced by |
|------|-------------|
| All code changes are PRs | branch protection + Patch Proposal agent |
| PR is a draft until reviewed | guardian-ci + repo policy |
| Unit/integration/security/safeguarding tests pass | guardian-ci, Test Runner agent |
| Evidence report attached | Evidence Report agent |
| Human approval recorded | Human Approval agent (no auto-approve) |
| Feature-flag deploy + auto-rollback | `guardian.config.yaml::self_healing.deploy` |
