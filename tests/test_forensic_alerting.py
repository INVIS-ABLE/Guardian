"""Forensic timeline anomalies must raise real, severity-routed alerts."""

from __future__ import annotations

from forensics import ForensicTimeline, TimelineEvent, raise_forensic_alerts
from forensics.alerting import alerts_from_report, anomaly_to_alert, severity_for
from observability.alerts import AlertRouter, Severity


def _ev(eid, source, action, ts, *, case="c1", outcome="", integrity_ok=True):
    return TimelineEvent(event_id=eid, source=source, action=action, timestamp=ts,
                         case_id=case, outcome=outcome, integrity_ok=integrity_ok)


def _router() -> tuple[AlertRouter, list]:
    captured: list = []
    router = AlertRouter(
        routes={Severity.HIGH: ("secops",)},  # HIGH and CRITICAL route to secops
        sinks={"secops": captured.append},
    )
    return router, captured


def test_severity_mapping_is_fail_loud():
    assert severity_for("unsupported_success:c1:scan:no_evidence") == Severity.CRITICAL
    assert severity_for("integrity_failed:github:i") == Severity.CRITICAL
    assert severity_for("missing_event:c1:post_deploy_health") == Severity.HIGH
    # an unrecognised anomaly kind still alerts rather than being dropped.
    assert severity_for("brand_new_kind:whatever") == Severity.WARNING


def test_unsupported_success_raises_a_real_alert_on_the_channel():
    tl = ForensicTimeline(corroboration={"scan": "evidence"})
    report = tl.build([_ev("s", "connector", "scan", 1.0, outcome="success")])
    assert not report.ok

    router, captured = _router()
    delivered = raise_forensic_alerts(report, router)

    anomaly = "unsupported_success:c1:scan:no_evidence"
    assert delivered[anomaly] == ["secops"]
    assert len(captured) == 1
    alert = captured[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.source == "forensics.timeline"
    assert alert.detail["kind"] == "unsupported_success"
    assert alert.detail["action"] == "scan"
    assert alert.detail["missing_source"] == "evidence"


def test_integrity_failure_parses_source_and_event_id():
    alert = anomaly_to_alert("integrity_failed:github:abc123")
    assert alert.severity == Severity.CRITICAL
    assert alert.detail["event_source"] == "github"
    assert alert.detail["event_id"] == "abc123"


def test_missing_event_is_high_and_parsed():
    tl = ForensicTimeline(expected_sequences={"deploy": ["post_deploy_health"]})
    report = tl.build([_ev("d", "temporal", "deploy", 1.0)])
    alerts = alerts_from_report(report)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].detail["case_id"] == "c1"
    assert alerts[0].detail["missing_action"] == "post_deploy_health"


def test_clean_report_raises_nothing():
    report = ForensicTimeline().build([_ev("a", "s", "x", 1.0)])
    assert report.ok
    router, captured = _router()
    assert raise_forensic_alerts(report, router) == {}
    assert captured == []


def test_repeated_anomaly_is_throttled_not_re_paged():
    tl = ForensicTimeline(corroboration={"scan": "evidence"})
    report = tl.build([_ev("s", "connector", "scan", 1.0, outcome="success")])
    router, captured = _router()

    first = raise_forensic_alerts(report, router)
    second = raise_forensic_alerts(report, router)  # same finding re-derived

    anomaly = "unsupported_success:c1:scan:no_evidence"
    assert first[anomaly] == ["secops"]
    assert second[anomaly] == []  # throttled by the shared dedup key
    assert len(captured) == 1


def test_correlation_id_propagates_to_the_alert():
    tl = ForensicTimeline(corroboration={"scan": "evidence"})
    report = tl.build([_ev("s", "connector", "scan", 1.0, outcome="success")])
    alerts = alerts_from_report(report, correlation_id="trace-xyz")
    assert alerts[0].correlation_id == "trace-xyz"
