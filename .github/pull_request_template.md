<!-- Guardian PR template. The Merge Governor and reviewers rely on this. Do not delete sections. -->

## What & why

<!-- One paragraph: the bounded objective and the issue it closes. -->
Closes #

## Risk classification

- [ ] LOW — typo / non-security docs / test-fixture / internal refactor
- [ ] MEDIUM — connector adapter / dependency update / dashboard / telemetry
- [ ] HIGH — authz, ownership, approvals, secrets, crypto, audit/evidence, network policy, isolation, AI tool execution, workflow permissions
- [ ] CRITICAL — signing keys, root of trust, Shadow Guardian, break-glass, evidence deletion/retention, default-deny policy, prod deploy

## Canonical base

- [ ] Base branch is `main`
- [ ] Branch was cut from / rebased onto recent `main`
- [ ] No hidden changes outside the stated objective
- [ ] No overlap with another worker's owned paths (see `docs/governance/path_ownership.yaml`)

## Security-sensitive paths touched

<!-- List any of: core/policy_gate.py, policies/**, ownership/**, identity/**, core/signing.py,
     security/crypto/**, attestation/**, core/evidence/**, isolation/**, core/ai/**,
     .github/workflows/**, deploy/**, docker-compose*.yml — or "none". -->
None

## Tests & gates

- [ ] `pytest -q` green
- [ ] `ruff check .` clean
- [ ] Security scans relevant to the change pass and are **blocking** (no `|| true`, no `continue-on-error`, no bare `except: pass`)
- [ ] New deps: reason recorded, licence reviewed, version/digest pinned, SBOM updated (or N/A)
- [ ] Negative / property tests added for security-sensitive logic (or N/A)

## Reviews required

- [ ] LOW/MEDIUM: 1 independent human review
- [ ] HIGH: 2 independent human reviews + CODEOWNERS + threat-model update + security-impact statement + rollback
- [ ] CRITICAL: HIGH + repository-owner approval + independent security review + staged rollout + recovery test
- [ ] Author is **not** supplying their own required approval

## Capability-claim honesty

- [ ] No documentation claims a capability is `implemented` / `integrated` / `operational` / `production-ready` unless the capability registry and evidence prove it.

## Rollback

<!-- How to revert safely (revert which commit; any data/migration concerns). -->
