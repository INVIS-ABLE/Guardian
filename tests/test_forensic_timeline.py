"""The forensic timeline reconstructs incidents and flags unsupported successes."""

from __future__ import annotations

from forensics import ForensicTimeline, TimelineEvent


def _ev(eid, source, action, ts, *, case="c1", outcome="", integrity_ok=True):
    return TimelineEvent(event_id=eid, source=source, action=action, timestamp=ts,
                         case_id=case, outcome=outcome, integrity_ok=integrity_ok)


def test_clock_skew_correction_orders_across_sources():
    # nodeB's clock runs 100s behind; after correction its event sorts after nodeA's.
    events = [
        _ev("b1", "nodeB", "scan_finish", 50.0),    # corrected -> 150
        _ev("a1", "nodeA", "scan_start", 100.0),     # corrected -> 100
    ]
    tl = ForensicTimeline(clock_offsets={"nodeB": 100.0})
    report = tl.build(events)
    order = [e.event.event_id for e in report.entries]
    assert order == ["a1", "b1"]
    # causal link: b1 preceded by a1 in the same case.
    assert report.entries[1].preceded_by == "a1"


def test_duplicate_delivery_removed():
    events = [_ev("x", "opa", "decision", 1.0), _ev("x", "opa", "decision", 1.0)]
    report = ForensicTimeline().build(events)
    assert report.duplicates_removed == 1
    assert len(report.entries) == 1


def test_missing_expected_event_detected():
    # A patch deploy must be followed by a post-deploy health check; it's absent.
    tl = ForensicTimeline(expected_sequences={"deploy": ["post_deploy_health"]})
    report = tl.build([_ev("d", "temporal", "deploy", 1.0)])
    assert not report.ok
    assert any("missing_event:c1:post_deploy_health" in a for a in report.anomalies)


def test_unsupported_success_flagged_when_evidence_absent():
    # A connector claims a successful scan, but no evidence-ledger event corroborates it.
    tl = ForensicTimeline(corroboration={"scan": "evidence"})
    report = tl.build([_ev("s", "connector", "scan", 1.0, outcome="success")])
    assert not report.ok
    assert any(a.startswith("unsupported_success:c1:scan:no_evidence") for a in report.anomalies)


def test_corroborated_success_is_not_flagged():
    tl = ForensicTimeline(corroboration={"scan": "evidence"})
    report = tl.build([
        _ev("s", "connector", "scan", 1.0, outcome="success"),
        _ev("e", "evidence", "append", 2.0),  # the independent corroboration
    ])
    assert report.ok, report.anomalies


def test_integrity_failure_is_an_anomaly():
    report = ForensicTimeline().build([_ev("i", "github", "audit", 1.0, integrity_ok=False)])
    assert any(a.startswith("integrity_failed:github:i") for a in report.anomalies)


def test_chain_of_custody_export_is_ordered():
    tl = ForensicTimeline()
    report = tl.build([_ev("a", "s", "x", 2.0), _ev("b", "s", "y", 1.0)])
    coc = report.chain_of_custody()
    assert [c["event_id"] for c in coc] == ["b", "a"]
    assert set(coc[0]) >= {"event_id", "source", "action", "corrected_timestamp", "preceded_by"}


def test_correlation_falls_back_to_trace_id():
    e1 = TimelineEvent(event_id="t1", source="a", action="x", timestamp=1.0, trace_id="tr")
    e2 = TimelineEvent(event_id="t2", source="b", action="y", timestamp=2.0, trace_id="tr")
    report = ForensicTimeline().build([e1, e2])
    assert report.entries[1].preceded_by == "t1"  # linked via trace_id when case_id is absent
