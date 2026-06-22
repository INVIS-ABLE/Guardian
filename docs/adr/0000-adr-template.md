# ADR-NNNN: <short title of the decision>

- **Status:** proposed | accepted | superseded by ADR-MMMM | deprecated
- **Date:** YYYY-MM-DD
- **Deciders:** <names / roles>
- **Wave:** <Final Power-Up wave number, if applicable>
- **Roadmap area:** <area from docs/hardening_roadmap.md, if applicable>

## Context

What is the problem, the forces at play, and the constraints? Reference the relevant
sections of `docs/architecture/final_powerup_map.md` and the existing authority that
must remain intact (`core/policy_gate.py`, `core/router.py`, `core/guardrails.py`,
`core/audit.py`, `core/evidence.py`, `core/memory.py`, OPA).

## Decision

The change being proposed or made. State it in active voice ("We will …").

## Compatibility impact

- Public APIs preserved / changed (with migration path).
- Existing capability names retained?
- Configuration backward compatible?
- Tests that must keep passing.

## Consequences

- Positive outcomes.
- Negative outcomes / costs / risks.
- Follow-up work and the wave that will deliver it.

## Alternatives considered

- Option A — why rejected.
- Option B — why rejected.

## References

- Master map sections.
- Related ADRs.
- Components in `docs/architecture/components.yaml`.
