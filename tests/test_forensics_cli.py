"""The `guardian forensics` CLI reconstructs the timeline and flags anomalies."""

from __future__ import annotations

import json

from click.testing import CliRunner

from core.audit import AuditLog
from core.cli import main


def _populate(tmp_path, *records):
    audit = AuditLog(log_dir=tmp_path)
    for action, detail in records:
        audit.record(action, actor="connector", scope="staging", decision="allowed", detail=detail)
    return audit


def test_clean_timeline_exits_zero(tmp_path):
    _populate(tmp_path, ("scan_start", {"case_id": "c1"}), ("scan_finish", {"case_id": "c1"}))
    result = CliRunner().invoke(main, ["forensics", "--log-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "No anomalies." in result.output
    assert "scan_start" in result.output and "scan_finish" in result.output


def test_missing_expected_event_flagged_and_exits_one(tmp_path):
    _populate(tmp_path, ("deploy", {"case_id": "c1"}))
    rules = tmp_path / "rules.yaml"
    rules.write_text("expected_sequences:\n  deploy:\n    - post_deploy_health\n")
    result = CliRunner().invoke(main, ["forensics", "--log-dir", str(tmp_path),
                                       "--rules", str(rules)])
    assert result.exit_code == 1
    assert "missing_event:c1:post_deploy_health" in result.output


def test_tampered_chain_flags_integrity_and_exits_one(tmp_path):
    audit = _populate(tmp_path, ("a1", {}), ("a2", {}))
    lines = audit.path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "mallory"
    lines[0] = json.dumps(rec, sort_keys=True)
    audit.path.write_text("\n".join(lines) + "\n")
    result = CliRunner().invoke(main, ["forensics", "--log-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "INTEGRITY-FAIL" in result.output


def test_case_filter(tmp_path):
    _populate(tmp_path, ("x", {"case_id": "c1"}), ("y", {"case_id": "c2"}))
    result = CliRunner().invoke(main, ["forensics", "--log-dir", str(tmp_path), "--case", "c1"])
    assert result.exit_code == 0
    assert "x" in result.output and "  y " not in result.output


def test_anomalies_routed_to_jsonl_sink(tmp_path):
    _populate(tmp_path, ("deploy", {"case_id": "c1"}))
    rules = tmp_path / "rules.yaml"
    rules.write_text("expected_sequences:\n  deploy:\n    - post_deploy_health\n")
    alerts = tmp_path / "alerts.jsonl"
    result = CliRunner().invoke(main, ["forensics", "--log-dir", str(tmp_path),
                                       "--rules", str(rules), "--alerts-jsonl", str(alerts)])
    assert result.exit_code == 1
    assert f"Routed 1 alert(s) to {alerts}" in result.output
    lines = alerts.read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["severity"] == "HIGH"
    assert record["source"] == "forensics.timeline"
    assert record["detail"]["missing_action"] == "post_deploy_health"


def test_clean_timeline_writes_no_alerts(tmp_path):
    _populate(tmp_path, ("scan_start", {"case_id": "c1"}), ("scan_finish", {"case_id": "c1"}))
    alerts = tmp_path / "alerts.jsonl"
    result = CliRunner().invoke(main, ["forensics", "--log-dir", str(tmp_path),
                                       "--alerts-jsonl", str(alerts)])
    assert result.exit_code == 0
    assert "Routed 0 alert(s)" in result.output
    assert not alerts.exists()
