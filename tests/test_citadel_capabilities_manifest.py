"""Validate the Crown Citadel capability catalogue (docs/architecture/citadel_capabilities.yaml).

Wave-20 reconciliation invariants: exactly 20 systems (21-40) across the five crowns, one
authoritative owner per function (unique owners), one INDEPENDENT verifier per system (verifier
!= owner), no Citadel subsystem grants authority, attestation services never grant production
authority, and current state is honestly represented (status present|partial|planned). Owners that
name an in-repo module must exist on disk, so the catalogue cannot drift from reality.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "docs" / "architecture" / "citadel_capabilities.yaml"

REQUIRED = {
    "id", "system", "crown", "citadel_wave", "owner", "owner_kind", "verifier",
    "status", "runtime_enforced", "grants_authority", "grants_production_authority",
    "function", "trust_assumptions", "failure_mode", "recovery", "when_unavailable", "evidence",
}
CROWNS = {"I", "II", "III", "IV", "V"}
STATUSES = {"present", "partial", "planned"}
OWNER_KINDS = {"existing_module", "guardian_native", "upstream"}


def _catalogue() -> dict:
    return yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))


def _systems() -> list[dict]:
    return _catalogue()["systems"]


def test_catalogue_loads_and_states_the_principle():
    data = _catalogue()
    assert data["systems"], "catalogue must list capability systems"
    assert data["principle"] == "one_authoritative_owner_plus_one_independent_verifier"
    # Must reference, not duplicate, the existing manifests.
    assert set(data["parent_manifests"]) >= {"components", "brain_tools", "sovereign"}


def test_exactly_twenty_systems_across_five_crowns():
    systems = _systems()
    assert len(systems) == 20, f"expected 20 Citadel systems (21-40), found {len(systems)}"
    by_crown: dict[str, int] = {}
    for s in systems:
        by_crown[s["crown"]] = by_crown.get(s["crown"], 0) + 1
    assert set(by_crown) == CROWNS, f"all five crowns must be present, found {set(by_crown)}"
    assert all(n == 4 for n in by_crown.values()), f"each crown must own 4 systems, got {by_crown}"


def test_every_system_has_required_fields_and_valid_values():
    for s in _systems():
        missing = REQUIRED - set(s)
        assert not missing, f"{s.get('id')} missing fields: {missing}"
        assert s["crown"] in CROWNS, f"{s['id']} bad crown {s['crown']}"
        assert s["status"] in STATUSES, f"{s['id']} bad status {s['status']}"
        assert s["owner_kind"] in OWNER_KINDS, f"{s['id']} bad owner_kind {s['owner_kind']}"
        assert 20 <= int(s["citadel_wave"]) <= 39, f"{s['id']} citadel_wave out of range"
        assert isinstance(s["runtime_enforced"], bool)
        assert s["trust_assumptions"], f"{s['id']} must declare trust assumptions"


def test_ids_unique_and_no_duplicate_authoritative_owner():
    systems = _systems()
    ids = [s["id"] for s in systems]
    assert len(ids) == len(set(ids)), "system ids must be unique"
    owners = [s["owner"] for s in systems]
    dupes = {o for o in owners if owners.count(o) > 1}
    assert not dupes, f"duplicate authoritative owners violate one-owner-per-function: {dupes}"


def test_every_system_has_an_independent_verifier():
    # One authoritative owner + one INDEPENDENTLY implemented verifier — they must differ.
    for s in _systems():
        assert s["verifier"] != s["owner"], f"{s['id']} verifier must differ from its owner"


def test_no_citadel_subsystem_grants_authority():
    offenders = [s["id"] for s in _systems() if s["grants_authority"] is not False]
    assert not offenders, f"no Citadel subsystem may grant authority: {offenders}"


def test_no_subsystem_grants_production_authority():
    offenders = [s["id"] for s in _systems() if s["grants_production_authority"] is not False]
    assert not offenders, f"no Citadel subsystem may grant production authority: {offenders}"


def test_in_repo_owners_and_verifiers_exist_on_disk():
    # Any owner/verifier that names an in-repo path (has a '/' and no ':' and is not an org/repo
    # upstream slug) for a present/partial system must exist — the catalogue can't claim a module
    # is live when it isn't.
    for s in _systems():
        if s["status"] == "planned":
            continue
        for role in ("owner", "verifier"):
            ref = s[role]
            looks_like_repo_path = "/" in ref and (ref.endswith(".py") or ref.endswith(".rego")
                                                    or ref.endswith(".yaml") or ref.endswith(".md")
                                                    or "/" in ref and not ref[0].isupper())
            path = ROOT / ref
            if looks_like_repo_path and (ref.startswith(("core/", "supplychain/", "policies/",
                                                         "isolation/", "recovery/", "containment/",
                                                         "shadow_guardian/", "orchestration/",
                                                         "ownership/", "resilience/", "docs/"))):
                assert path.exists(), f"{s['id']} {role} names a missing in-repo path: {ref}"


def test_status_is_honestly_mixed():
    # Wave 20 rule: current and planned states are honestly represented. There must be BOTH
    # already-real systems and not-yet-built ones — no blanket "all present" inflation.
    statuses = {s["status"] for s in _systems()}
    assert "planned" in statuses or "partial" in statuses, "must honestly flag unbuilt systems"
    assert "present" in statuses, "must credit systems that already exist"


def test_all_thirty_wave20_invariants_enumerated():
    invariants = _catalogue()["invariants"]
    assert len(invariants) >= 30, f"expected the 30 Wave-20 invariants, found {len(invariants)}"
    for key in (
        "no_citadel_subsystem_grants_authority",
        "failed_attestation_denies_capability_issuance",
        "shadow_cannot_assume_operational_control",
        "private_plaintext_never_enters_citadel_systems",
        "recovery_incomplete_until_evidence_and_identity_integrity_pass",
    ):
        assert key in invariants, f"missing required invariant: {key}"


@pytest.mark.xfail(reason="Citadel Waves 21-39 implement runtime enforcement; planned systems are "
                          "catalogued-only today. This test exposes that gap honestly.",
                   strict=False)
def test_every_system_is_runtime_enforced():
    # Honest gap exposure (Wave-20 directive: 'tests that initially expose missing systems').
    not_enforced = [s["id"] for s in _systems() if not s["runtime_enforced"]]
    assert not not_enforced, f"not yet runtime-enforced (future waves): {not_enforced}"
