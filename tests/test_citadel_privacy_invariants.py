"""Citadel privacy invariants (Wave-20 invariants 20, 21, 22).

Private-message plaintext NEVER enters Citadel telemetry, evidence, models, memory, formal-
verification input or deception systems. Test/deception credentials can never authenticate to
production, and honeytokens never grant genuine privilege. The forbidden-field set mirrors the one
already enforced in core/verifier.py and core/event_fabric.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ARCH = ROOT / "docs" / "architecture"
CONFIGS = ROOT / "configs" / "citadel"

# Mirrors core/verifier.py::_FORBIDDEN_LEAF_FIELDS — the private-content barrier.
EXPECTED_FORBIDDEN = {"private_key", "plaintext", "message", "conversation_key", "secret", "media"}


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def test_private_plaintext_barrier_covers_every_citadel_sink():
    barrier = _load(ARCH / "citadel_data_flows.yaml")["private_plaintext_barrier"]
    for sink in ("telemetry", "evidence", "models", "memory", "formal_verification_input",
                 "deception_systems"):
        assert sink in barrier["forbidden_in"], f"plaintext barrier must cover {sink}"
    assert set(barrier["forbidden_fields"]) == EXPECTED_FORBIDDEN
    assert set(barrier["classification_denylist"]) == {"MESSAGE_PLAINTEXT", "DECRYPTION_KEY"}


def test_data_protection_excludes_private_content():
    dp = _load(CONFIGS / "data-protection.yaml")["citadel"]["data_protection"]
    assert dp["private_message_plaintext_excluded"] is True       # invariant 20
    assert set(dp["forbidden_fields"]) == EXPECTED_FORBIDDEN
    assert "MESSAGE_PLAINTEXT" in dp["classification_denylist"]


def test_deception_grants_no_real_privilege_and_no_prod_auth():
    dec = _load(CONFIGS / "deception.yaml")["citadel"]["deception"]
    assert dec["real_privilege_prohibited"] is True               # invariant 22
    assert dec["real_user_data_prohibited"] is True
    assert dec["test_or_deception_credentials_authenticate_to_production"] is False  # invariant 21


def test_forbidden_fields_match_runtime_verifier_constant():
    # Ground the barrier in real code: the constant must exist in core/verifier.py and match.
    src = (ROOT / "core" / "verifier.py").read_text(encoding="utf-8")
    for field in EXPECTED_FORBIDDEN:
        assert f'"{field}"' in src, f"core/verifier.py no longer guards {field}; barrier drifted"
