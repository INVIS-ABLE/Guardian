"""The candidate-repository catalogue is well-formed and honest.

Guards research/repositories/: every candidate has a decision and a category, and
quantitative metadata is explicitly marked pending live discovery (never fabricated).
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CAT_DIR = ROOT / "research" / "repositories"

VALID_DECISIONS = {
    "retain", "adopt", "adapt", "integrate", "federate", "isolate",
    "benchmark", "reference", "defer", "reject", "self",
}


def _load(name: str):
    return yaml.safe_load((CAT_DIR / name).read_text(encoding="utf-8"))


def test_all_catalogue_files_present_and_parse():
    for name in ("catalogue.yaml", "decisions.yaml", "licences.yaml",
                 "security_review.yaml", "data_flows.yaml"):
        assert isinstance(_load(name), dict), name


def test_every_candidate_has_decision_category_and_pending_metadata():
    cat = _load("catalogue.yaml")
    candidates = cat["candidates"]
    assert len(candidates) > 150  # the brief lists ~200
    for c in candidates:
        assert c["provisional_decision"] in VALID_DECISIONS, c["url"]
        assert c["category"], c["url"]
        assert c["url"].startswith("https://github.com/"), c["url"]
        # Honesty: numeric metadata is never fabricated.
        assert c["live_metadata"]["pending_live_discovery"] is True, c["url"]
        assert "discovery_cmd" in c["live_metadata"], c["url"]


def test_guardian_itself_is_marked_self():
    cat = _load("catalogue.yaml")
    guardian = [c for c in cat["candidates"] if c["repo"] == "Guardian"]
    assert guardian and guardian[0]["provisional_decision"] == "self"


def test_offensive_tools_are_not_adopted():
    """Charter: no uncontrolled offensive path. Known offensive tools must never be
    'adopt'/'integrate' — only reject/reference/isolate/defer/benchmark."""
    cat = _load("catalogue.yaml")
    flagged = {"pentagi", "pentestagent", "hexstrike-ai", "Pentest-Swarm-AI",
               "AttackSurfaceManagement", "caldera"}
    for c in cat["candidates"]:
        if c["repo"] in flagged:
            assert c["provisional_decision"] in {"reject", "reference", "isolate", "defer"}, c["repo"]


def test_single_policy_authority_preserved():
    """OPA is retained as the authority; alternative engines must not be 'adopt'."""
    cat = _load("catalogue.yaml")
    by_repo = {c["repo"]: c for c in cat["candidates"]}
    assert by_repo["opa"]["provisional_decision"] == "retain"
    for alt in ("cedar", "cerbos"):
        assert by_repo[alt]["provisional_decision"] in {"reference", "defer", "reject"}
