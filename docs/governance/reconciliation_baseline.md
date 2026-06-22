# Reconciliation baseline — immutable snapshot

> Evidence timestamp: 2026-06-22T23:01:53Z
> Recorded by the Guardian Merge Governor before modifying branch relationships.
> These SHAs are the rollback anchors. Do not overwrite.

## Canonical and legacy tips

| Ref | SHA | Note |
| --- | --- | --- |
| `origin/main` (canonical) | `acfbf1054af4bdd47ccb84bbeb14ed379af11579` | sole integration/release branch |
| `origin/claude/laughing-ptolemy-zfeiiu` (legacy/default) | `152b321727a15e453fcdc094063d55cf1b28fc81` | reconcile, do not develop |
| merge-base(main, legacy) | `1aa9d6fd280d5c388b957f116d557de6026c8c18` | common ancestor |

## Divergence (cherry-pick aware)

- `main` ahead of legacy by **11** commits.
- legacy ahead of `main` by **3** commits.

### Unique legacy content absent from `main`

```
152b321 Merge pull request #48 from INVIS-ABLE/claude/confident-planck-9t1rfs
7905392 Merge pull request #49 from INVIS-ABLE/claude/area11-uv-lockfile
d51c6ed feat(wave0): repository-truth baseline + machine-readable inventory
```

The substantive unique content is the **Wave 0 repository-truth baseline** (commit
`d51c6ed`, merged via PR #48 into the legacy branch only). It must be ported forward to
`main` — see `branch_reconciliation_plan.md`.

### Recent `main`-only content absent from legacy

```
acfbf10 Merge pull request #53 from INVIS-ABLE/claude/vibrant-gates-8qmfxc
7a458ee adaptive: Level 6 Phase 1 autonomic core (control states, autonomy budget, healing contracts)
dd50179 Merge pull request #51 from INVIS-ABLE/claude/keen-euler-4t9vo7
32eb268 Merge pull request #50 from INVIS-ABLE/claude/exciting-goldberg-udmve1
a890add feat(lineage): data lineage & privacy graph — Wave 1 #3
569dd7c feat(trust): bridge the ownership verifier to the six-roots target root
eedd9c4 Merge pull request #47 from INVIS-ABLE/claude/area11-uv-lockfile
a0ebf24 Merge pull request #46 from INVIS-ABLE/claude/vibrant-gates-8qmfxc
63f61e4 Merge pull request #44 from INVIS-ABLE/claude/keen-euler-4t9vo7
b9cdf0a feat(identity-graph): BloodHound-style identity & permission attack graph — Wave 1 #2
ddb6e3b docs: Mythos Hive Wave 0 inventory, capability/licence matrices & migration plan
```

## Open pull requests at baseline

| PR | Head | Base | Draft | Summary |
| --- | --- | --- | --- | --- |
| #55 | claude/keen-euler-4t9vo7 | main | yes | endpoint intelligence fabric (Wave 1 #4) |
| #52 | claude/twin-ci-gate | main | no | ambient PR blast-radius gate |

Both open PRs correctly target `main`. The only mis-targeted work was Wave 0 (PR #48 →
legacy), which predates this governance baseline.

## Rollback strategy

Every reconciliation lands via a reviewable PR into `main`. To roll back, revert the
merge commit through a follow-up PR; the tips above identify the pre-reconciliation
state. No history is rewritten; no branch is deleted without owner approval and its
final SHA recorded in `branch_retirement.yaml`.
