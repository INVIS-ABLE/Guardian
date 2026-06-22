"""Citadel reproducible-build invariants (Wave-20 invariants 9, 10, 29).

A release candidate needs the full chain — source identity + lockfile + hermetic definition +
independent rebuild + matching digest + SBOM + provenance + signature + transparency inclusion. A
signature alone is insufficient, and a non-reproducible critical build cannot promote.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs" / "citadel"

REQUIRED_CHAIN = {
    "source_identity", "lockfile", "hermetic_build_definition", "independent_rebuild",
    "matching_digest", "sbom", "provenance", "signature", "transparency_inclusion",
}


def _foundry() -> dict:
    return yaml.safe_load((CONFIGS / "build-foundry.yaml").read_text(encoding="utf-8"))["citadel"]["build_foundry"]


def test_release_candidate_requires_full_provenance_chain():
    f = _foundry()
    assert set(f["release_candidate_requires"]) == REQUIRED_CHAIN   # invariants 9, 10


def test_signature_alone_is_insufficient():
    f = _foundry()
    assert f["signature_alone_insufficient"] is True                # invariant 10


def test_non_reproducible_critical_build_cannot_promote():
    f = _foundry()
    assert f["non_reproducible_critical_build"] == "block_promotion"  # invariant 29
    assert f["digest_match_required"] is True
    assert f["independent_rebuilders"] >= 2
    assert f["reproducible_critical_builds"] is True


def test_critical_build_classes_enumerated():
    f = _foundry()
    for cls in ("container_images", "policy_bundles", "worker_images", "pwa_releases"):
        assert cls in f["build_classes"], f"build foundry must cover {cls}"
