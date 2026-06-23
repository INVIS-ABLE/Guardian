# Guardian Final Consolidation — §14 Acceptance Results

_Run 2026-06-23T02:36:00Z · `main` @ `70c9d80f667c32c362af6f1fe919c29ca44abbcc` · default branch verified via GitHub API + `git ls-remote --symref`._

| # | Acceptance item | Result | Evidence |
| --- | --- | --- | --- |
| 1 | GitHub default resolves to `main` | ✅ PASS | API `default_branch=main`; `origin/HEAD -> refs/heads/main` |
| 2 | A wrong-base PR fails | ⚠️ ENFORCED-BY-GOVERNOR | repo-governor flags base≠main; ruleset config not queryable by steward — owner to confirm |
| 3 | Direct push to `main` rejected | ⚠️ OWNER-CONFIRM | requires branch protection/ruleset (not queryable via available tooling) |
| 4 | Required checks block merges | ⚠️ OWNER-CONFIRM | CI checks present; enforcement is a ruleset setting |
| 5 | CODEOWNERS review required | ⚠️ PARTIAL | `.github/CODEOWNERS` present; enforcement is a ruleset setting |
| 6 | Historical capabilities present in `main` | ✅ PASS | inventory: 57 branches 0-unique vs `main`; only 3 security branches hold unique unreviewed work |
| 7 | No obsolete branch holds unreconciled legitimate code | ✅ PASS (w/ 3 flagged) | 3 security-sensitive branches flagged for human review (not obsolete) |
| 8 | All test suites pass | ✅ PASS | full `pytest` suite green |
| 9 | Capability registry matches implementation | ✅ PASS | `core/tools/registry.default_registry` + `core/router.CAPABILITY_MAP`; `test_tool_manifest`, `test_router*` |
| 10 | Planned tools not presented as operational | ✅ PASS | `components.yaml` status present/planned; catalogue marks planned vs operational |
| 11 | One end-to-end safe workflow succeeds | ✅ PASS | `test_router_contract_execution.py`: signed authorization → roots-of-trust → one-use capability → guarded executor → evidence ledger |
| 12 | Failure at any trust boundary refuses execution | ✅ PASS | structured `ToolRefusal` on unknown/forged/disallowed/approval-missing/roots-failed/token-reused; circuit-open refusal (router fabric) |

## Notes
Items 2–5 depend on **repository ruleset / branch-protection settings** that the steward
cannot read or set through available tooling. They are **owner-confirm** items: enable a
ruleset on `main` requiring PR, status checks, and CODEOWNERS review, with direct/force
push blocked. CODEOWNERS and the wrong-base governor are already in the repo.
