"""Emulation ingestion — build a report from a spec, or from CALDERA.

For development/CI and for declaring a known operation, the emulation report is built from a
plain spec (dict or YAML) of lab-observed results. In production the same results come from
**CALDERA** (with Atomic Red Team / Stratus Red Team techniques); that wiring lands at
:func:`from_caldera`, which fails closed (raises) until the range is provisioned.

Spec shape::

    operation: "INVISABLE quarterly ATT&CK emulation"
    environment: range            # must be a disposable lab — never production
    results:
      - technique: {id: T1059.004, name: "Unix Shell", tactic: execution}
        prevented: false
        detected_by: falco        # omit / null when not detected
        evidence_preserved: true
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .lab import AdversaryLab
from .models import EmulationReport, Technique, TechniqueResult


def build_from_spec(spec: dict[str, Any]) -> EmulationReport:
    """Construct an emulation report from a ``{operation, environment, results}`` mapping.

    The :class:`AdversaryLab` enforces lab-only on ``environment``; a production target raises
    ``LabOnlyViolation`` before any result is processed.
    """
    lab = AdversaryLab(environment=spec.get("environment", "range"))
    results = []
    for raw in spec.get("results", []):
        data = dict(raw)
        technique = Technique(**data.pop("technique"))
        results.append(TechniqueResult(technique=technique, **data))
    return lab.report(spec.get("operation", "unnamed operation"), results)


def load_operation(path: str | Path) -> EmulationReport:
    """Load and assemble an emulation report from a YAML operation spec."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"emulation operation spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_caldera(_config: Any | None = None) -> EmulationReport:
    """Populate a report from the production range (CALDERA + Atomic/Stratus Red Team).

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty
    operation: an empty report would falsely imply "no techniques bypassed our controls" — the
    most dangerous false negative for a defensive lab. Until the range is provisioned, build
    reports from explicit specs (:func:`build_from_spec` / :func:`load_operation`).
    """
    raise NotImplementedError(
        "CALDERA range ingestion is not wired yet; build the report from an explicit operation "
        "spec (build_from_spec/load_operation). Set GUARDIAN_ENV=development to use spec-based runs."
    )


def production_source_required() -> bool:
    """Whether a real range source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
