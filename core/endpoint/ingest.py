"""Endpoint-fabric ingestion seam — build a fabric from reviewed packs, signatures, or Fleet.

Three entry points, matching how packs reach the fabric:

  * :func:`load_reviewed_packs` — read reviewed pack *content* (no signatures) from a YAML.
    This is the committed, reviewable artifact: the queries a human approved. Signatures are
    produced separately by a reviewer (they never live in the repo as plaintext secrets).
  * :func:`build_from_spec` — build and **admit** packs from a spec that already carries each
    pack's reviewer signature (the production shape: content + detached signature + trusted
    keys). Admission verifies every signature.
  * :func:`seal_and_admit` — a convenience for demos/CLI: generate a one-off reviewer key,
    sign the reviewed packs with it, and admit them into a fabric that trusts only that key —
    so the full sign → verify → admit → vet flow can be shown end to end without provisioning
    real reviewer keys.

In production the fabric is populated from **Fleet**, which distributes the signed packs and
collects osquery results. :func:`from_fleet` is that seam and fails closed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from core.signing import generate_keypair, sign

from .fabric import EndpointFabric
from .models import PackSignature, QueryPack


def load_reviewed_packs(path: str | Path) -> list[QueryPack]:
    """Load reviewed pack content (a list of :class:`QueryPack`) from a YAML spec.

    Spec shape::

        packs:
          - {id: "...", name: "...", author: "...", reviewed_by: "...", queries: [...]}
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"endpoint pack spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return [QueryPack(**pk) for pk in data.get("packs", [])]


def sign_pack(pack: QueryPack, private_hex: str, key_id: str) -> PackSignature:
    """Produce a reviewer's detached signature over a pack's canonical bytes."""
    return PackSignature(key_id=key_id, signature=sign(private_hex, pack.canonical_bytes()))


def build_from_spec(spec: dict[str, Any]) -> EndpointFabric:
    """Build a fabric from a spec of ``{trusted_reviewers, packs:[{pack, signature}]}`` and admit.

    ``trusted_reviewers`` maps key_id → public hex; each pack entry carries its detached
    ``signature``. Admission verifies every signature, so a bad/absent signature raises.
    """
    fabric = EndpointFabric(dict(spec.get("trusted_reviewers", {})))
    for entry in spec.get("packs", []):
        pack = QueryPack(**entry["pack"])
        signature = PackSignature(**entry["signature"])
        fabric.admit(pack, signature)
    return fabric


def seal_and_admit(packs: list[QueryPack], *, key_id: str = "rev-demo") -> EndpointFabric:
    """Demo/CLI helper: sign reviewed packs with a fresh key and admit them under that trust.

    Mirrors a reviewer signing offline: a one-off keypair is generated, each pack is signed,
    and a fabric trusting only that key admits them. The trust is structural — the fabric
    accepts only this key — so the sign → verify → admit → vet flow is exercised for real.
    """
    kp = generate_keypair()
    fabric = EndpointFabric({key_id: kp.public})
    for pack in packs:
        fabric.admit(pack, sign_pack(pack, kp.private, key_id))
    return fabric


def from_fleet(_config: Any | None = None) -> EndpointFabric:
    """Populate the fabric from the production source (Fleet: signed packs + osquery results).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    fabric: an empty approved set would let nothing run, but more importantly the trusted
    reviewer keys must come from a provisioned source, not a default. Until then, callers must
    supply reviewed packs explicitly and admit them with verified signatures.
    """
    raise NotImplementedError(
        "Fleet ingestion is not wired yet; load reviewed packs (load_reviewed_packs) and admit "
        "them with verified reviewer signatures (build_from_spec / seal_and_admit). Set "
        "GUARDIAN_ENV=development to use spec-based fabrics."
    )


def production_source_required() -> bool:
    """Whether a real endpoint source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
