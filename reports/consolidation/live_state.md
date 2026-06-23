# Guardian Final Consolidation — Live State (§1)

_Generated 2026-06-23T02:17:47Z from live `git ls-remote --symref`, `git fetch --all`, and the GitHub
repositories API._

## Gate result: ❌ BLOCKED

| Check | Required | Actual |
| --- | --- | --- |
| GitHub default branch | `main` | **`claude/laughing-ptolemy-zfeiiu`** |
| `origin/HEAD` symref | `origin/main` | **`origin/claude/laughing-ptolemy-zfeiiu`** |

Per directive §1, because the default branch is not `main`, the consolidation **stops and
reports this as an owner-controlled blocker**. Everything downstream (final retirement §12,
acceptance §14, definition-of-done §16) is gated on this flip.

## State snapshot

- **`main` tip:** `df4d3e355def7ea27f81b864b11ddb1688f9f835`
- **Legacy/default branch:** `claude/laughing-ptolemy-zfeiiu` @ `8f55815841c13d6dc62883b146d08c0e7d881f36`
- **Remote branches:** 60
- **Open PRs:** 0 (all prior work merged or closed)
- **CODEOWNERS:** present (`.github/CODEOWNERS`)
- **Governor charter:** present (`docs/governance/merge_governor.md`)
- **Retirement manifest:** present (`docs/governance/branch_retirement.yaml`)
- **Branch protection / rulesets / required checks:** not queryable via available tooling — owner to confirm.

## Owner-controlled blockers

1. **Default branch ≠ main (critical).** Flip in **Settings → General → Default branch → `main`**.
   The steward has no tool to change repository settings, and the git proxy denies settings/ref
   mutation, so this cannot be automated.
2. **Ref deletion blocked (high).** The git proxy returns HTTP 403 on branch deletion and no
   MCP delete-branch tool exists; branch retirement (§12) must be run by the owner using the
   command in `docs/governance/branch_retirement.yaml`.

## What is not blocked (steward can proceed on request)

The full branch/PR inventory (§3), the freeze record (§2), security-conflict triage (§6), and
focused forward-port PRs (§7) target `main` directly and do **not** require the default flip.
These can proceed while the owner performs the flip; only final retirement and acceptance are hard-gated.
