"""Validate the Brain cognitive-tool catalogue.

Keeps docs/architecture/brain_tools.yaml honest and enforces the cardinal invariant of the
Brain V2 design (docs/brain_v2.md): cognition proposes, authority disposes — so NO cognitive
tool may grant authority. Also enforces one authoritative owner per function and that the
Temporal entry references the same upstream as the infrastructure components manifest.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ARCH = Path(__file__).resolve().parent.parent / "docs" / "architecture"
CATALOGUE = ARCH / "brain_tools.yaml"
COMPONENTS = ARCH / "components.yaml"

REQUIRED = {"id", "tool", "component", "function", "category", "wave", "autonomy", "grants_authority", "status"}
CATEGORIES = {"reasoning", "tooluse", "memory", "code", "assurance"}
AUTONOMY = {"investigate", "conditional", "none"}
STATUSES = {"present", "planned"}


def _catalogue() -> dict:
    return yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))


def _tools() -> list[dict]:
    return _catalogue()["tools"]


def test_catalogue_loads_and_states_the_principle():
    data = _catalogue()
    assert data["tools"], "catalogue must list cognitive tools"
    assert data.get("principle") == "cognition_proposes_authority_disposes"


def test_exactly_twenty_tools():
    # The deliverable is "20 tools to add to the Brain" — keep it exactly 20.
    assert len(_tools()) == 20, f"expected 20 cognitive tools, found {len(_tools())}"


def test_every_tool_has_required_fields_and_valid_values():
    for t in _tools():
        missing = REQUIRED - set(t)
        assert not missing, f"{t.get('id')} missing fields: {missing}"
        assert t["category"] in CATEGORIES, f"{t['id']} bad category {t['category']}"
        assert t["autonomy"] in AUTONOMY, f"{t['id']} bad autonomy {t['autonomy']}"
        assert t["status"] in STATUSES, f"{t['id']} bad status {t['status']}"
        assert 1 <= int(t["wave"]) <= 4, f"{t['id']} wave out of range (1..4)"


def test_ids_and_components_are_unique():
    ids = [t["id"] for t in _tools()]
    assert len(ids) == len(set(ids)), "tool ids must be unique"
    repos = [t["component"] for t in _tools()]
    dupes = {r for r in repos if repos.count(r) > 1}
    assert not dupes, f"duplicate components violate one-owner-per-function: {dupes}"


def test_no_cognitive_tool_grants_authority():
    # The cardinal invariant: a model, graph, solver or scanner never self-authorises.
    offenders = [t["id"] for t in _tools() if t["grants_authority"] is not False]
    assert not offenders, f"cognitive tools must not grant authority: {offenders}"


def test_every_category_is_represented():
    present = {t["category"] for t in _tools()}
    assert present == CATEGORIES, f"missing categories: {CATEGORIES - present}"


def test_temporal_matches_infrastructure_manifest():
    # Temporal is the one tool that lives in BOTH manifests (durable outer workflow); the
    # upstream owner must agree so the two views never drift.
    by_id = {t["id"]: t for t in _tools()}
    temporal = by_id["durable_workflow"]["component"]
    components = yaml.safe_load(COMPONENTS.read_text(encoding="utf-8"))["components"]
    infra = {c["id"]: c for c in components}["durable_orchestration"]["component"]
    assert temporal == infra, f"Temporal owner drift: catalogue={temporal} components={infra}"
