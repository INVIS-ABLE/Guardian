"""Citadel recovery invariants (Wave-20 invariants 13, 19, 30).

Evidence cannot be deleted by the service that created it; recovery evidence is not written solely
by the system being recovered; recovery is incomplete until evidence integrity AND identity
integrity pass. The vault has a separate identity plane and no normal-runtime write access.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs" / "citadel"
ARCH = ROOT / "docs" / "architecture"


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _vault() -> dict:
    return _load(CONFIGS / "cyber-vault.yaml")["citadel"]["cyber_vault"]


def test_vault_is_isolated_and_immutable():
    v = _vault()
    assert v["immutable"] is True
    assert v["separate_identity"] is True
    assert v["separate_network"] is True
    assert v["no_direct_normal_runtime_write_access"] is True
    assert v["delayed_deletion"] is True
    assert v["recovery_key_separation"] is True


def test_recovery_evidence_independence_and_completeness():
    v = _vault()
    assert v["recovery_evidence_not_written_solely_by_recovered_system"] is True  # invariant 19
    until = v["recovery_incomplete_until"]
    assert "evidence_integrity_pass" in until and "identity_integrity_pass" in until  # invariant 30


def test_continuity_must_not_weaken_core_invariants():
    cont = _load(CONFIGS / "continuity.yaml")["citadel"]["continuity"]
    for guard in ("scope", "ownership", "policy", "evidence", "approval", "privacy",
                  "safeguarding_isolation"):
        assert guard in cont["must_not_weaken"], f"continuity must not weaken {guard}"
    assert cont["reconcile_on_exit"] is True


def test_cyber_vault_owner_and_verifier_are_distinct():
    systems = {s["id"]: s for s in _load(ARCH / "citadel_capabilities.yaml")["systems"]}
    vault = systems["cyber_vault"]
    assert vault["owner"] == "recovery/backup.py"
    assert vault["verifier"] == "recovery/drill.py"
    assert vault["owner"] != vault["verifier"]
