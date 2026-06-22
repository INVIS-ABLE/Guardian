# Phase 6 — Detection-as-Code

Blueprint area 19. Portable, version-controlled, **ATT&CK-mapped** detection rules with
**positive/negative tests**, evaluated by an engine that turns telemetry events into
detections — and a **recommended** reversible containment action. Detect → recommend →
(human/policy gate) → contain. The engine never acts; recommendations still pass the
deterministic containment adapter (area 21).

## Rules (`detection/rules/*.yaml`)

Sigma-inspired, data-driven. Each rule carries: `id`, `severity`, **`attack`** (technique
ids, defensive mapping), `confidence`, `detection` conditions (`all`/`any` over event fields
with `equals`/`contains`/`in`/`gte`/`regex`), a **`response`** (a reversible containment action
+ the event field holding the target), and embedded **`tests`** (positive + negative events).

Shipped rules → ATT&CK → response:

| Rule | ATT&CK | Reversible response |
| ---- | ------ | ------------------- |
| web-shell-upload | T1505.003 | isolate_pod (needs approval) |
| credential-token-theft | T1539 | revoke_token (auto) |
| scraper-burst | T1595 | block_indicator_temporarily |
| ransomware-mass-file-change | T1486 | isolate_pod (needs approval) |
| c2-beacon | T1071 | block_indicator_temporarily |

## Engine (`detection/engine.py`)

`DetectionEngine.from_dir().evaluate(event)` returns the `Detection`s that fire (rule id,
ATT&CK, severity, confidence, recommended action + target). `recommend_containment(detection)`
builds a `ContainmentRequest` **only** when the action is a known reversible action and the
target is present — Guardian *recommends*; it does not act.

## Detect → contain wiring (tested)

A detection's recommendation flows into the deterministic containment adapter from area 21,
where the human-approval / policy / parameter gates still apply:

- `credential-token-theft` → `revoke_token` → adapter **issues** (auto, no human approval);
- `ransomware-mass-file-change` → `isolate_pod` → adapter **rejects without a human approval
  token**, accepts with one. Detection cannot bypass the human gate.

Each rule's `confidence` is checked against the recommended action's `min_confidence`, so a
rule can never emit a recommendation its own adapter would reject.

## Tested invariants (10)

- all rules load, each has an ATT&CK mapping and a valid reversible response;
- **every rule's embedded positive events fire it and negative events don't** (one test per
  rule, parametrised);
- rule confidence ≥ the action threshold;
- auto recommendation reaches the adapter and issues;
- high-impact recommendation still requires human approval;
- the loader rejects a rule with no detection conditions.

`ruff` + `bandit -ll` clean.

## Deployment wiring

Rules export to the runtime backends (Wazuh, Loki, SIEM) and consume events from
Falco/Suricata/Zeek/Wazuh/CrowdSec and the Guardian audit stream. Recommendations are
surfaced to the Runtime Monitoring agent and gated by OPA + the containment adapter before any
reversible action runs.
