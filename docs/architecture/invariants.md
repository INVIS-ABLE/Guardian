# Guardian architecture invariants

These invariants are non-negotiable across every Final Power-Up wave. They are derived
from `docs/architecture/build_directive.md` and `final_powerup_map.md §2`. Where an
invariant is mechanically checkable, the enforcing test is named.

## Authority and authorisation

1. `core/policy_gate.py` is the **single** action-authorisation authority. OPA remains
   the final policy decision engine. — _tests: `test_policy_gate.py`, `test_opa_parity.py`._
2. `core/router.py` remains the one capability→tool chokepoint. Every executable action
   enters through the Guardian router fabric. — _tests: `test_router.py`,
   `test_router_contract_execution.py`._
3. `core/guardrails.py` remains the scope and precondition enforcement wrapper
   (default-deny, fail-closed). — _tests: `test_guardrails.py`, `test_scope.py`._
4. Every action receives a policy decision immediately before execution; no path may
   bypass scope, ownership, approval, evidence or audit protocols.

## Evidence and audit

5. `core/audit.py` remains the local tamper-evident audit entry point;
   `core/evidence.py` remains the evidence-normalisation entry point. — _tests:
   `test_audit.py`, `test_evidence_store.py`, `test_signing.py`, `test_attestation.py`._
6. Every execution produces case/job/workflow/trace IDs, tool identity + version,
   input/output hashes, an audit event, an evidence record and start/finish timestamps.

## Model and capability discipline

7. Every model response is **untrusted input** and must pass a typed schema before use.
   — _tests: `test_ai_gateway.py` (output firewall)._
8. Models select Guardian **capabilities**, never arbitrary command strings. Reviewed
   connectors construct executable commands from validated arguments.
9. Every connector requires: manifest, input schema, output schema, parser, health
   check, fixtures, contract tests, evidence mapping, version and provenance. — _tests:
   `test_connector_contract.py`, `test_tool_manifest.py`._

## Execution boundaries

10. Direct host subprocess execution is confined to two sanctioned chokepoints
    (`connectors/base.py`, `core/policy_gate.py`). No new direct-subprocess site may
    appear elsewhere. — _test: `test_repo_inventory.py`._
11. Development adapters are deterministic and clearly separated from production
    adapters; production must not silently fall back to an insecure dev adapter.
12. Production code contains no fake success responses and no silent `pass` branches;
    deployment stubs raise `NotImplementedError` and are inventoried honestly. — _test:
    `test_repo_inventory.py` (placeholder inventory), `test_failclosed.py`._

## Compatibility and truth

13. Do not replace the repository with a new scaffold; extend via compatibility façades
    (`core/brain.py`→`core/brain/`, `core/router.py`→`core/tools/`, etc.).
14. Public APIs stay backward compatible unless a versioned migration is supplied;
    existing capability names are retained through adapters.
15. The machine-readable component manifest (`components.yaml`) is authoritative for
    "present vs planned" and is kept honest. — _test: `test_components_manifest.py`._
16. The repository inventory (`reports/audit/current_state.json`) must never drift from
    reality. — _test: `test_repo_inventory.py`._
17. All public functions, classes and schemas carry type annotations; code targets
    Python 3.12 compatibility and the repo's ruff/mypy conventions.

## Quality gates

18. Existing tests must keep passing on every wave. Tests fail closed when required
    production infrastructure is unavailable rather than reporting false success.
19. Every significant architectural choice is recorded as an ADR (`docs/adr/`).
20. Every subsystem appears in `components.yaml` and is documented.
