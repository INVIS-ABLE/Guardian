"""Fuzzing ingestion — build a report from a spec, or from ClusterFuzzLite.

For development/CI the report is built from a plain spec of targets + crash observations. In
production the same observations come from **ClusterFuzzLite** running AFL++ / Atheris / Jazzer;
that wiring lands at :func:`from_clusterfuzz`, which fails closed.

Spec shape::

    campaign: "nightly crypto-parser fuzz"
    targets:
      - {id: "fuzz:crypto-envelope", name: "Crypto envelope parser", surface: crypto_envelope}
    crashes:
      - {target_id: "fuzz:crypto-envelope", signature: "abc123", kind: crash,
         input_hash: "sha256:...", severity: high}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .farm import FuzzFarm
from .models import CrashObservation, FuzzReport, FuzzTarget


def build_from_spec(spec: dict[str, Any]) -> FuzzReport:
    """Construct a fuzz report from a ``{campaign, targets, crashes}`` mapping."""
    farm = FuzzFarm(FuzzTarget(**t) for t in spec.get("targets", []))
    crashes = [CrashObservation(**c) for c in spec.get("crashes", [])]
    return farm.report(spec.get("campaign", "unnamed campaign"), crashes)


def load_campaign(path: str | Path) -> FuzzReport:
    """Load and adjudicate a fuzzing campaign from a YAML spec."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"fuzz campaign spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_clusterfuzz(_config: Any | None = None) -> FuzzReport:
    """Populate a report from the production fuzzing source (ClusterFuzzLite).

    Not yet wired. Fails closed so a caller never reads an empty report as "no crashes found":
    a silent empty result is the worst false negative for a fuzzing farm. Until wired, build
    reports from explicit specs.
    """
    raise NotImplementedError(
        "ClusterFuzzLite ingestion is not wired yet; build the report from an explicit campaign "
        "spec (build_from_spec/load_campaign). Set GUARDIAN_ENV=development for spec-based runs."
    )


def production_source_required() -> bool:
    """Whether a real fuzzing source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
