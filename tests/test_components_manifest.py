"""Validate the target-architecture component manifest.

Keeps docs/architecture/components.yaml honest and well-formed, and enforces the
"one authoritative owner per function" principle (no duplicate component owning the stack).
"""

from __future__ import annotations

from pathlib import Path

import yaml

MANIFEST = Path(__file__).resolve().parent.parent / "docs" / "architecture" / "components.yaml"

REQUIRED = {"id", "component", "function", "trust_zone", "roadmap_area", "phase", "status"}
TRUST_ZONES = {"edge", "management", "identity", "execution", "evidence", "detection", "observability"}
STATUSES = {"present", "planned"}


def _manifest() -> dict:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_loads_and_has_components():
    data = _manifest()
    assert data["components"], "manifest must list components"
    assert data.get("principle") == "one_authoritative_owner_per_function"


def test_every_component_has_required_fields():
    for c in _manifest()["components"]:
        missing = REQUIRED - set(c)
        assert not missing, f"{c.get('id')} missing fields: {missing}"
        assert c["trust_zone"] in TRUST_ZONES, f"{c['id']} bad trust_zone {c['trust_zone']}"
        assert c["status"] in STATUSES, f"{c['id']} bad status {c['status']}"
        assert 0 <= int(c["phase"]) <= 6, f"{c['id']} phase out of range"
        assert 1 <= int(c["roadmap_area"]) <= 28, f"{c['id']} roadmap_area out of range"


def test_ids_unique():
    ids = [c["id"] for c in _manifest()["components"]]
    assert len(ids) == len(set(ids)), "component ids must be unique"


def test_one_owner_per_function_no_duplicate_components():
    # The principle: each upstream component appears at most once (single owner per function).
    repos = [c["component"] for c in _manifest()["components"]]
    dupes = {r for r in repos if repos.count(r) > 1}
    assert not dupes, f"duplicate components violate one-owner-per-function: {dupes}"


def test_opa_is_the_present_authority():
    by_id = {c["id"]: c for c in _manifest()["components"]}
    assert by_id["policy_engine"]["component"] == "open-policy-agent/opa"
    assert by_id["policy_engine"]["status"] == "present"
    assert by_id["policy_engine"]["roadmap_area"] == 1
