# ADR-0001: Final Power-Up baseline and repository truth (Wave 0)

- **Status:** accepted
- **Date:** 2026-06-22
- **Deciders:** Guardian maintainers
- **Wave:** 0
- **Roadmap area:** 1 (central authorisation), 22 (documentation/observability of state)

## Context

Guardian is being evolved into a federated autonomous defensive-security and
safeguarding platform per `docs/architecture/final_powerup_map.md` and
`docs/architecture/build_directive.md`. The directive's first required action is
explicit: **do not guess what exists — inspect it**, and produce a truthful baseline
before any feature work. The existing repository already contains substantial,
authoritative machinery (the central `core/policy_gate.py`, the `core/router.py`
capability chokepoint, the 17 ECC agents, signed tool manifests, evidence/audit
subsystems and a passing test suite of 377 tests).

A power-up of this size risks two failure modes: (1) silently replacing working
subsystems with a new scaffold, and (2) the documentation drifting out of sync with
the code so nobody can tell what is actually delivered versus merely planned.

## Decision

We establish a **machine-readable, test-enforced repository inventory** as the single
source of truth for current state, and we adopt ADRs and architecture invariants as
the mechanism for every subsequent wave.

Specifically, Wave 0 delivers:

1. The canonical inputs committed into the repo: `final_powerup_map.md`,
   `build_directive.md`, and `configs/tools/guardian.tool-registry.expanded.yaml`.
2. `core/inventory.py` — introspects the live registries (agents, connectors,
   simulators), the router capability vocabulary and the signed tool-manifest
   registry, and scans the source tree for direct-subprocess and placeholder sites.
3. The generated artefacts `reports/audit/current_state.{json,md}`.
4. Documented inventories: `agent_inventory.md`, `connector_inventory.md`,
   `capability_inventory.md`, plus `invariants.md`.
5. This ADR set and `docs/adr/0000-adr-template.md`.
6. `tests/test_repo_inventory.py`, which fails closed if the report drifts, if a
   registry entry is undocumented, or if a new unsanctioned subprocess site appears.

## Compatibility impact

- No production code paths changed. `core/inventory.py` is additive and read-only.
- All existing public APIs, capability names, configuration and CLI commands are
  untouched.
- The existing 377-test suite must continue to pass unchanged. New tests are additive.

## Consequences

- **Positive:** state can never silently go stale; new subprocess sites and
  undocumented capabilities are caught in CI; future waves start from a verified base.
- **Negative:** contributors must regenerate `reports/audit/current_state.json`
  (`python -m core.inventory --write`) after registry/capability/subprocess changes,
  or the inventory test fails. This is intentional friction in service of truth.

## Alternatives considered

- **Hand-maintained inventory docs only** — rejected: drifts immediately, unverifiable.
- **A new top-level package replacing `core`** — rejected: violates the
  non-negotiable "do not replace the repository with a new scaffold" rule.

## References

- `docs/architecture/final_powerup_map.md` §1–§6, §14 (capability vocabulary).
- `docs/architecture/build_directive.md` Wave 0.
- `docs/architecture/invariants.md`.
- `docs/architecture/components.yaml` (`repo_inventory` component).
