"""Citadel transparency invariants (Wave-20 invariant 28).

A missing transparency inclusion proof denies release promotion; logs are cross-checked against an
independent log, and disagreement is a critical event. The execution path records an inclusion
proof before independent Shadow verification.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs" / "citadel"
ARCH = ROOT / "docs" / "architecture"


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def test_inclusion_proof_required_for_promotion():
    t = _load(CONFIGS / "transparency.yaml")["citadel"]["transparency"]
    assert t["inclusion_proof_required_for_promotion"] is True     # invariant 28
    assert t["consistency_proof_required"] is True
    assert t["log_disagreement"] == "critical_event"
    # One authoritative log + one independent cross-check log.
    assert t["primary_log"] != t["independent_log"]


def test_build_foundry_requires_transparency_proof():
    b = _load(CONFIGS / "build-foundry.yaml")["citadel"]["build_foundry"]
    assert b["transparency_proof_required"] is True
    assert "transparency_inclusion" in b["release_candidate_requires"]


def test_execution_path_records_inclusion_before_shadow():
    flows = _load(ARCH / "citadel_data_flows.yaml")["extended_execution_path"]
    order = {s["stage"]: s["step"] for s in flows}
    assert order["transparency_inclusion"] < order["independent_shadow_verification"]
