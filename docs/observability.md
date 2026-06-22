# Observability & Alerting (area 12)

To investigate or audit a single security case, you need its events stitched together and a way
to be told when something is refused. `observability/` provides both, in-process and
dependency-free — no network calls unless a deployment injects real sinks.

## Correlation & trace IDs — `observability/trace.py`

Every case runs under one **correlation id** (the trace id). `Tracer.span(name, **attrs)` opens
a nested span and propagates the active trace/parent through `contextvars`, so a span opened
deep in a call chain inherits the trace automatically — no id threading through every function.

```python
tracer = Tracer()
with tracer.span("case", asset="pwa") as root:
    with tracer.span("policy_decision"):        # same trace_id, parent = root
        with tracer.span("workflow_step"):      # same trace_id, parent = policy_decision
            ...
tracer.spans_for(root.trace_id)   # all three spans, for export/audit
current_correlation_id()          # the active trace id, or None outside a trace
```

- Sibling spans share the trace id but get distinct span ids and the same parent.
- An exception inside a span marks it `status="error"` and still closes it cleanly.
- `Tracer.spans` is a plain list a future OTel exporter can consume; nothing here emits over a
  network.

## Routed, deduplicated alerting — `observability/alerts.py`

`AlertRouter` turns events — especially denials and fail-closed refusals — into severity-routed
alerts. Routing is deterministic and allowlist-based:

- `routes` maps a `Severity` (`INFO < WARNING < HIGH < CRITICAL`) to channel names.
- An alert reaches every channel routed at its severity **or any lower threshold** — a `HIGH`
  route also receives `CRITICAL`.
- `sinks` maps channel names to delivery callables. **There are none by default**, so the
  router never calls out on its own; a deployment wires Slack/PagerDuty/Alertmanager explicitly.

```python
router = AlertRouter(
    routes={Severity.WARNING: ("chat",), Severity.HIGH: ("pager", "chat")},
    sinks={"pager": pagerduty, "chat": slack},
)
router.alert_denial("deploy", source="policy_gate", reason="opa_down")  # -> ["chat", "pager"]
```

Safety properties:
- **Dedup/throttle** — repeats of the same `dedup_key` within `throttle_seconds` are suppressed,
  so one noisy condition can't flood responders.
- **Correlation-linked** — each alert captures the active correlation id, linking it to its
  trace and audit entries.
- **Fault-isolated** — a sink that throws is skipped; other channels still receive the alert.

## Tests

`tests/test_observability.py` — trace propagation (nested/sibling/separate traces, error
status, context cleanup) and alerting (severity allowlist + threshold, dedup/throttle window,
correlation capture, failing-sink isolation).
