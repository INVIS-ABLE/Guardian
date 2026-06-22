"""Phase 6 — detection-as-code: rules, engine, and detection→containment wiring."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from containment import REVERSIBLE_ACTIONS, ContainmentRejected, DeterministicContainmentAdapter
from core.audit import AuditLog
from detection import DEFAULT_RULES_DIR, DetectionEngine, rule_from_dict

RULE_FILES = sorted(Path(DEFAULT_RULES_DIR).glob("*.yaml"))


def test_rules_load_and_are_well_formed():
    engine = DetectionEngine.from_dir()
    assert len(engine.rules) == len(RULE_FILES) >= 5
    for r in engine.rules:
        assert r.attack, f"{r.id} has no ATT&CK mapping"
        assert 0.0 <= r.confidence <= 1.0
        # Every response action is a known reversible containment action.
        if r.response is not None:
            assert r.response.action in REVERSIBLE_ACTIONS, r.response.action


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.stem)
def test_each_rule_positive_and_negative_cases(rule_file):
    data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
    engine = DetectionEngine.from_dir()
    rid = data["id"]
    for ev in data.get("tests", {}).get("positive", []):
        fired = {d.rule_id for d in engine.evaluate(ev)}
        assert rid in fired, f"{rid} should fire on {ev}"
    for ev in data.get("tests", {}).get("negative", []):
        fired = {d.rule_id for d in engine.evaluate(ev)}
        assert rid not in fired, f"{rid} should NOT fire on {ev}"


def test_confidence_meets_recommended_action_threshold():
    # A rule's confidence must satisfy the containment action's min_confidence, or the
    # adapter would always reject its own recommendation.
    engine = DetectionEngine.from_dir()
    for r in engine.rules:
        if r.response is not None:
            spec = REVERSIBLE_ACTIONS[r.response.action]
            assert r.confidence >= spec.min_confidence, (r.id, r.confidence, spec.min_confidence)


def test_auto_containment_recommendation_flows_to_adapter(tmp_path):
    engine = DetectionEngine.from_dir()
    adapter = DeterministicContainmentAdapter(audit=AuditLog(log_dir=tmp_path))
    # A credential token theft → recommend revoke_token (auto, no human approval) → issue OK.
    [det] = [d for d in engine.evaluate(
        {"event_type": "session_token_export", "token_id": "tok-9"}
    ) if d.rule_id == "credential-token-theft"]
    req = DetectionEngine.recommend_containment(det)
    assert req is not None and req.action == "revoke_token" and req.target == "tok-9"
    order = adapter.issue(req)
    assert order.active


def test_high_impact_recommendation_still_needs_human_approval(tmp_path):
    engine = DetectionEngine.from_dir()
    adapter = DeterministicContainmentAdapter(audit=AuditLog(log_dir=tmp_path))
    [det] = [d for d in engine.evaluate(
        {"event_type": "file_change", "changed_files": 2000, "host": "fileserver-1"}
    ) if d.rule_id == "ransomware-mass-file-change"]
    req = DetectionEngine.recommend_containment(det)  # isolate_pod (requires approval)
    assert req is not None and req.action == "isolate_pod"
    with pytest.raises(ContainmentRejected):
        adapter.issue(req)  # detection recommends, but the human gate from area 21 still applies
    req.approval_token = "appr-1"
    assert adapter.issue(req).active


def test_loader_rejects_rule_without_conditions():
    with pytest.raises(ValueError):
        rule_from_dict({"id": "x", "attack": ["T1"], "detection": {}})
