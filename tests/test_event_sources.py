"""Event-fabric adapters turn real emitter outputs into TimelineEvents."""

from __future__ import annotations

from core.audit import AuditLog
from core.evidence.store import EvidenceEvent, EvidenceStore, HashChainBackend
from core.policy_gate import PolicyDecision
from forensics import (
    ForensicTimeline,
    events_from_audit_log,
    from_audit_entry,
    from_evidence_receipt,
    from_execution,
    from_policy_decision,
    from_shadow_report,
)
from shadow_guardian.verifier import ShadowFinding, ShadowReport


def test_from_audit_entry_maps_fields():
    entry = {"ts": "2026-06-22T12:00:00+00:00", "actor": "tool_router", "action": "scan",
             "scope": "staging", "decision": "allowed", "detail": {"case_id": "c1"}, "hash": "abc123def456"}
    ev = from_audit_entry(entry)
    assert ev.source == "audit" and ev.action == "scan" and ev.actor == "tool_router"
    assert ev.asset == "staging" and ev.case_id == "c1" and ev.outcome == "allowed"
    assert ev.timestamp > 0


def test_events_from_real_audit_log(tmp_path):
    audit = AuditLog(log_dir=tmp_path)
    audit.record("a1", actor="x", scope="staging", decision="allowed", detail={"case_id": "c1"})
    audit.record("a2", actor="x", scope="staging", decision="refused", detail={"case_id": "c1"})
    events = events_from_audit_log(audit)
    assert [e.action for e in events] == ["a1", "a2"]
    assert all(e.integrity_ok for e in events)


def test_tampered_audit_log_marks_events_integrity_failed(tmp_path):
    audit = AuditLog(log_dir=tmp_path)
    audit.record("a1", actor="x", decision="allowed")
    audit.record("a2", actor="x", decision="allowed")
    # Tamper with the first line; the chain no longer verifies.
    import json
    lines = audit.path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "mallory"
    lines[0] = json.dumps(rec, sort_keys=True)
    audit.path.write_text("\n".join(lines) + "\n")
    events = events_from_audit_log(audit)
    assert events and all(not e.integrity_ok for e in events)


def test_from_policy_decision():
    allow = from_policy_decision(PolicyDecision(allow=True), action="code_review",
                                 actor="a", timestamp=1.0, case_id="c1")
    deny = from_policy_decision(PolicyDecision(allow=False, denies=["blocked_action:hack_back"]),
                               action="hack_back", actor="a", timestamp=2.0, case_id="c1")
    assert allow.source == "opa" and allow.outcome == "success"
    assert deny.outcome == "denied" and "blocked_action:hack_back" in deny.attributes["denies"]


def test_from_evidence_receipt_tracks_verifiable(tmp_path):
    store = EvidenceStore(backend=HashChainBackend(log_dir=tmp_path))
    receipt = store.record(EvidenceEvent(actor="g", command_id="scan", result="completed"))
    ev = from_evidence_receipt(receipt, timestamp=1.0, case_id="c1")
    assert ev.source == "evidence" and ev.integrity_ok and ev.event_id == receipt.event_id


def test_from_shadow_report():
    bad = ShadowReport(ok=False, frozen=True,
                       findings=[ShadowFinding(check="args_hash_matches_observed", ok=False)])
    ev = from_shadow_report(bad, timestamp=1.0, case_id="c1")
    assert ev.source == "shadow" and ev.outcome == "failure" and not ev.integrity_ok
    assert "args_hash_matches_observed" in ev.attributes["failures"]


# --- the payoff: adapters + timeline catch an unsupported success on live signals --------
def test_unsupported_success_detected_from_real_emitters(tmp_path):
    # A connector reports a successful scan (returncode 0), but NO evidence append corroborates
    # it in the same case. The timeline flags the unsupported success.
    class _Result:
        returncode = 0
        output_hash = "deadbeefdeadbeef"

    scan = from_execution(_Result(), action="scan", timestamp=1.0, case_id="c1")
    tl = ForensicTimeline(corroboration={"scan": "evidence"})
    report = tl.build([scan])
    assert any(a.startswith("unsupported_success:c1:scan:no_evidence") for a in report.anomalies)

    # Now add the real evidence receipt for the same case → corroborated, clean.
    store = EvidenceStore(backend=HashChainBackend(log_dir=tmp_path))
    receipt = store.record(EvidenceEvent(actor="g", command_id="scan", result="completed"))
    evidence = from_evidence_receipt(receipt, timestamp=2.0, case_id="c1")
    assert ForensicTimeline(corroboration={"scan": "evidence"}).build([scan, evidence]).ok
