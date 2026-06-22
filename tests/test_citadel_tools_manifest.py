"""Validate the Crown Citadel tool map (docs/architecture/citadel_tools.yaml).

One authoritative owner per production function; every other tool is an independent verifier,
specialist adapter, laboratory or migration tool — never a second owner. Each category must serve
a real Citadel system id.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "docs" / "architecture" / "citadel_tools.yaml"
CATALOGUE = ROOT / "docs" / "architecture" / "citadel_capabilities.yaml"

PLACEMENTS = {"production", "verifier", "laboratory", "migration", "development"}


def _tools() -> dict:
    return yaml.safe_load(TOOLS.read_text(encoding="utf-8"))


def _categories() -> list[dict]:
    return _tools()["categories"]


def _system_ids() -> set[str]:
    cat = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    return {s["id"] for s in cat["systems"]}


def test_tools_manifest_states_one_owner_principle():
    assert _tools()["principle"] == "one_authoritative_owner_per_function"
    assert _categories(), "tool map must list categories"


def test_each_category_has_exactly_one_owner_and_valid_placement():
    for c in _categories():
        assert isinstance(c["owner"], str) and c["owner"], f"{c['id']} needs exactly one owner"
        assert c["placement"] in PLACEMENTS, f"{c['id']} bad placement {c['placement']}"
        assert c.get("capabilities"), f"{c['id']} must list capabilities"


def test_owner_is_not_listed_among_its_alternatives():
    # The owner is the authority; alternatives are verifiers/specialist/lab tools, not a 2nd owner.
    for c in _categories():
        assert c["owner"] not in c.get("alternatives", []), \
            f"{c['id']} owner duplicated in alternatives"


def test_category_ids_and_owners_are_unique():
    cats = _categories()
    ids = [c["id"] for c in cats]
    assert len(ids) == len(set(ids)), "category ids must be unique"
    owners = [c["owner"] for c in cats]
    dupes = {o for o in owners if owners.count(o) > 1}
    assert not dupes, f"one owner per function: duplicate owners across categories {dupes}"


def test_every_category_serves_a_real_system():
    ids = _system_ids()
    for c in _categories():
        assert c["serves"] in ids, f"{c['id']} serves unknown system {c['serves']}"
