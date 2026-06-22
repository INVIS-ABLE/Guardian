"""Trace propagation + routed alerting proofs (area 12 / observability)."""

from __future__ import annotations

import pytest

from observability import AlertRouter, Severity, Tracer
from observability.alerts import Alert
from observability.trace import current_correlation_id


# --- tracing -------------------------------------------------------------------------------

def test_outside_any_span_there_is_no_correlation_id():
    assert current_correlation_id() is None


def test_nested_spans_share_one_trace_and_chain_parents():
    tracer = Tracer()
    with tracer.span("case", asset="pwa") as root:
        assert current_correlation_id() == root.trace_id
        with tracer.span("policy_decision") as child:
            assert child.trace_id == root.trace_id
            assert child.parent_id == root.span_id
            with tracer.span("workflow_step") as grandchild:
                assert grandchild.trace_id == root.trace_id
                assert grandchild.parent_id == child.span_id

    # Context is cleaned up after the trace closes.
    assert current_correlation_id() is None
    assert len(tracer.spans_for(root.trace_id)) == 3
    assert root.duration_ms() is not None and root.duration_ms() >= 0


def test_sibling_spans_share_trace_but_have_distinct_ids():
    tracer = Tracer()
    with tracer.span("case") as root:
        with tracer.span("a") as a:
            pass
        with tracer.span("b") as b:
            pass
    assert a.trace_id == b.trace_id == root.trace_id
    assert a.span_id != b.span_id
    assert a.parent_id == b.parent_id == root.span_id


def test_separate_traces_get_distinct_ids():
    tracer = Tracer()
    with tracer.span("one") as s1:
        pass
    with tracer.span("two") as s2:
        pass
    assert s1.trace_id != s2.trace_id


def test_exception_marks_span_error_and_still_closes():
    tracer = Tracer()
    with pytest.raises(ValueError):
        with tracer.span("boom") as span:
            raise ValueError("x")
    assert span.status == "error"
    assert span.end is not None
    assert current_correlation_id() is None


# --- alerting ------------------------------------------------------------------------------

def _collector():
    received: list[Alert] = []
    return received, lambda alert: received.append(alert)


def test_severity_routing_is_allowlist_and_thresholded():
    pager, pager_sink = _collector()
    chat, chat_sink = _collector()
    router = AlertRouter(
        routes={Severity.WARNING: ("chat",), Severity.HIGH: ("pager", "chat")},
        sinks={"pager": pager_sink, "chat": chat_sink},
    )
    # WARNING goes only to chat; HIGH goes to both (HIGH >= WARNING too).
    assert sorted(router.channels_for(Severity.WARNING)) == ["chat"]
    assert sorted(router.channels_for(Severity.CRITICAL)) == ["chat", "pager"]

    router.emit(Alert("low", Severity.INFO, source="test"))
    assert pager == [] and chat == []  # INFO routed nowhere

    delivered = router.alert_denial("deploy", source="policy_gate", reason="opa_down")
    assert sorted(delivered) == ["chat", "pager"]
    assert pager[0].detail["reason"] == "opa_down"


def test_dedup_throttles_repeat_alerts_then_allows_after_window():
    received, sink = _collector()
    router = AlertRouter(
        routes={Severity.HIGH: ("ops",)}, sinks={"ops": sink}, throttle_seconds=10_000,
    )
    first = router.alert_denial("scan", source="engine", reason="frozen")
    second = router.alert_denial("scan", source="engine", reason="frozen")
    assert first == ["ops"]
    assert second == []  # throttled (same dedup key)
    assert len(received) == 1

    router.throttle_seconds = 0  # window elapsed
    third = router.alert_denial("scan", source="engine", reason="frozen")
    assert third == ["ops"]


def test_alert_carries_active_correlation_id():
    tracer = Tracer()
    received, sink = _collector()
    router = AlertRouter(routes={Severity.HIGH: ("ops",)}, sinks={"ops": sink})
    with tracer.span("case") as root:
        router.alert_denial("contain", source="containment", reason="not_reversible")
    assert received[0].correlation_id == root.trace_id


def test_a_failing_sink_does_not_block_other_channels():
    def broken(_alert):
        raise RuntimeError("sink down")

    ok, ok_sink = _collector()
    router = AlertRouter(
        routes={Severity.CRITICAL: ("broken", "ok")},
        sinks={"broken": broken, "ok": ok_sink},
    )
    delivered = router.emit(Alert("kaboom", Severity.CRITICAL, source="test"))
    assert delivered == ["ok"]  # broken channel skipped, ok still delivered
    assert len(ok) == 1
