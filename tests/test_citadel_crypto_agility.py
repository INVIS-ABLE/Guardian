"""Citadel cryptographic-agility invariants (Wave-20 invariants 25, 26).

Algorithm migration must support dual-read before cutover; post-quantum migration must not silently
reduce current classical security; retirement is never automatic (it is a quorum decision).
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs" / "citadel"


def _crypto() -> dict:
    return yaml.safe_load((CONFIGS / "crypto-agility.yaml").read_text(encoding="utf-8"))["citadel"]["crypto_agility"]


def test_dual_read_before_cutover_and_no_silent_downgrade():
    c = _crypto()
    assert c["dual_read_required_before_cutover"] is True          # invariant 25
    assert c["pq_must_not_reduce_classical_security"] is True       # invariant 26
    assert c["downgrade_detection"] is True
    assert c["automatic_retirement"] is False                       # retirement is a quorum call


def test_migration_states_order_dual_read_before_new_primary():
    states = _crypto()["migration_states"]
    assert states.index("dual-read") < states.index("new-primary"), \
        "dual-read must precede new-primary in the migration lifecycle"
    assert states.index("hybrid") < states.index("retired")


def test_inventory_and_allowlist_required():
    c = _crypto()
    assert c["inventory_required"] is True
    assert c["algorithm_allowlist_required"] is True
    assert c["unknown_crypto_use"] == "fail_ci"
    assert c["deprecated_algorithm"] == "blocking_finding"
    for field in ("algorithm", "key_size", "migration_state", "deprecation_date"):
        assert field in c["registry_fields"]
