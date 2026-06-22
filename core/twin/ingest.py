"""Twin ingestion seam — build a :class:`DigitalTwin` from a typed spec, or from Cartography.

For development/CI and for declaring a known sub-graph, the twin is built from a plain spec
(dict or YAML). In production the same twin is populated from Cartography/CloudQuery and
persisted in PostgreSQL — that wiring lands at :func:`from_cartography`, which fails closed
(raises) until the source is provisioned rather than returning a silently-empty twin.

Spec shape::

    assets:
      - {id: "repo:guardian", kind: repository, name: Guardian, owner: secops}
      - {id: "img:guardian",  kind: container_image, name: guardian:1.0}
    relationships:
      - {src: "repo:guardian", dst: "img:guardian", kind: produces}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .graph import DigitalTwin
from .models import AssetNode, Relationship


def build_from_spec(spec: dict[str, Any]) -> DigitalTwin:
    """Construct a twin from a ``{assets: [...], relationships: [...]}`` mapping.

    Pydantic validates every node/edge (including the privacy boundary on node
    classification); structural errors (unknown asset ids) raise ``TwinError``.
    """
    assets = [AssetNode(**a) for a in spec.get("assets", [])]
    relationships = [Relationship(**r) for r in spec.get("relationships", [])]
    twin = DigitalTwin()
    twin.extend(assets, relationships)
    return twin


def load_twin(path: str | Path) -> DigitalTwin:
    """Load a twin from a YAML spec file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"twin spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_cartography(_config: Any | None = None) -> DigitalTwin:
    """Populate the twin from the production relationship source (Cartography/CloudQuery).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    twin: an empty blast radius would falsely imply "nothing is affected". Until the source
    is provisioned, callers must supply an explicit spec via :func:`build_from_spec`.
    """
    raise NotImplementedError(
        "Cartography/CloudQuery ingestion is not wired yet; build the twin from an explicit "
        "spec (build_from_spec/load_twin). Set GUARDIAN_ENV=development to use spec-based twins."
    )


def production_source_required() -> bool:
    """Whether a real twin source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
