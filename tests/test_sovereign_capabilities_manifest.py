"""Validate the Sovereign Operations Plane capability catalogue.

Enforces the cardinal rule of the Sovereign design (docs/sovereign_ops_plane.md): brokered
power, not root. No capability system grants itself authority; any system that reaches the
approval-bound production level requires human approval; the four powers are real, distinct
modules; and the permanently-prohibited actions are enumerated.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ARCH = Path(__file__).resolve().parent.parent / "docs" / "architecture"
CATALOGUE = ARCH / "sovereign_capabilities.yaml"

REQUIRED = {
    "id", "system", "component", "kind", "function",
    "wave", "max_autonomy_level", "human_approval_required", "grants_authority", "status",
}
KINDS = {"upstream", "guardian_native"}
STATUSES = {"present", "planned"}
POWERS = {"brain", "policy", "broker", "verifier"}


def _catalogue() -> dict:
    return yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))


def _systems() -> list[dict]:
    return _catalogue()["systems"]


def test_catalogue_loads_and_states_the_principle():
    data = _catalogue()
    assert data["systems"], "catalogue must list capability systems"
    assert data.get("principle") == "brokered_power_not_root"


def test_exactly_twenty_systems():
    assert len(_systems()) == 20, f"expected 20 capability systems, found {len(_systems())}"


def test_every_system_has_required_fields_and_valid_values():
    for s in _systems():
        missing = REQUIRED - set(s)
        assert not missing, f"{s.get('id')} missing fields: {missing}"
        assert s["kind"] in KINDS, f"{s['id']} bad kind {s['kind']}"
        assert s["status"] in STATUSES, f"{s['id']} bad status {s['status']}"
        assert 1 <= int(s["wave"]) <= 4, f"{s['id']} wave out of range (1..4)"
        assert 1 <= int(s["max_autonomy_level"]) <= 5, f"{s['id']} autonomy level out of range"
        assert isinstance(s["human_approval_required"], bool)


def test_ids_and_components_are_unique():
    ids = [s["id"] for s in _systems()]
    assert len(ids) == len(set(ids)), "system ids must be unique"
    comps = [s["component"] for s in _systems()]
    dupes = {c for c in comps if comps.count(c) > 1}
    assert not dupes, f"duplicate components violate one-owner-per-function: {dupes}"


def test_no_capability_system_grants_authority():
    # Cardinal rule: brokered power, not root. Nothing here self-authorises.
    offenders = [s["id"] for s in _systems() if s["grants_authority"] is not False]
    assert not offenders, f"capability systems must not grant authority: {offenders}"


def test_approval_bound_production_requires_human_approval():
    # Any system reaching level 5 (approval-bound production) MUST require human approval —
    # nothing touches production autonomously.
    for s in _systems():
        if int(s["max_autonomy_level"]) >= 5:
            assert s["human_approval_required"] is True, f"{s['id']} is level 5 without human approval"


def test_every_wave_is_represented():
    waves = {int(s["wave"]) for s in _systems()}
    assert waves == {1, 2, 3, 4}, f"missing waves: {{1,2,3,4}} - {waves}"


def test_four_powers_are_real_distinct_modules():
    powers = _catalogue()["powers"]
    assert set(powers) == POWERS, f"the four powers must be {POWERS}, found {set(powers)}"
    modules = list(powers.values())
    assert len(modules) == len(set(modules)), "each power must be a distinct module"
    for power, module in powers.items():
        path = Path(__file__).resolve().parent.parent / module
        # core/* powers are real packages/modules; assert they exist on disk.
        if module.startswith("core/"):
            assert path.exists() or path.with_suffix(".py").exists(), f"{power} module missing: {module}"


def test_never_autonomous_list_is_enumerated():
    never = _catalogue()["never_autonomous"]
    assert never, "never_autonomous must enumerate the permanently-prohibited actions"
    for required in ("bypass_approval", "change_its_own_policies", "widen_scope"):
        assert required in never, f"never_autonomous must include {required}"
