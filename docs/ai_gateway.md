# Model gateway (`core/ai`)

Every model call in Guardian goes through one gateway. This is build-order step 3 of the
Brain V2 roadmap: before the agents are allowed to reason with models, the *way* they
call models has to be controlled, auditable and fail-closed.

```
ModelRequest(work_class, evidence, tenant/case, prompt_template_version, …)
        │
        ▼
ModelGateway.complete()
  1. context firewall   — refuse forbidden content; compute data classification
  2. routing            — work_class + classification → model CLASS (never for policy)
  3. registry           — resolve class → pinned, allow-listed ModelSpec
  4. privacy boundary   — external model + sensitive content needs explicit permission
  5. budgets            — output-token ceiling (pre) + cost budget (post)
  6. provider           — call backend, bounded retries, NO fallback on failure
  7. output firewall    — screen result for high-risk content
  8. provenance         — emit one immutable ModelCallRecord
        │
        ▼
ModelResponse(text, trust=MODEL_GENERATED, high_risk, firewall_findings, record)
```

## Guarantees

- **A model never decides authority.** `WorkClass.POLICY` routes to no model and raises
  `PolicyRoutingError`. Scope, identity, policy and approval stay deterministic.
- **No private content reaches a model.** Evidence classified `message_plaintext` or
  `decryption_key` raises `PrivacyBoundaryError` before any prompt is built.
- **Sensitive content stays local.** `confidential` / `restricted` / `pii` / `health`
  content is routed to the local/private model unless the caller sets
  `allow_external_processing=True`; an external model handling such content without
  permission is refused.
- **Untrusted evidence is data, never instructions.** The context firewall fences each
  evidence item with its trust level and classification and frames the system prompt so
  the model treats anything inside the fences as data to analyse — the core indirect
  prompt-injection defence.
- **Failure fails closed.** A missing/unavailable provider or a provider exception
  raises `ModelUnavailableError`; the gateway never substitutes a different model.
- **Output is never auto-trusted.** Responses are `MODEL_GENERATED` trust; the output
  firewall flags `high_risk` text (instruction overrides, approval claims, tool/scope/
  policy changes, secret exfiltration) so it must go through verification, not a tool.
- **Everything is recorded.** Each call emits a `ModelCallRecord` with the pinned model
  id, provider, prompt-template version + hash, tool-schema version, input evidence ids,
  output hash, token usage and cost, data classification, tenant/case ids, timeout,
  retry count, external-processing flag, eval version and the routing reason.

## Routing policy

| Work class | Model class | Rationale |
|---|---|---|
| `parsing` | fast | parse / classify / dedupe |
| `sensitive` | local | approved private/local model |
| `reasoning` | strong_reasoning | deep attack-path analysis |
| `patch` | strong_coding | patch generation |
| `review` | judge | independent reviewer (different family) |
| `policy` | none | deterministic — no model |

Independent review uses a deliberately different model **family** (the judge spec is an
OpenAI-family model) so a conclusion is not accepted merely because copies of the same
model agree.

## Providers

`provider_local.py` is an offline, deterministic adapter that performs **no external
processing** — the boundary-respecting destination for sensitive content, and what makes
the gateway testable without network or SDKs. `provider_anthropic.py` and
`provider_openai.py` lazily import their (optional) SDKs and read API keys; without them
they report `available() == False` and the gateway fails closed. A real on-prem model is
wired in behind `provider_local.py`'s interface without changing the gateway.

## Not yet wired

The gateway exists and is fully tested in isolation; connecting it to the agents and the
reasoning graph (so the 17 specialists actually call models through it) is later in the
build order. Today the agents remain thin stubs.
