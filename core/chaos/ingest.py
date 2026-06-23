"""Chaos ingestion — build a report from a spec, or from the chaos platform.

For development/CI the report is built from a spec of scenarios + observed results against a
cloned twin. In production the results come from a chaos platform driving failures against the
cloned twin / shadow stack; that wiring lands at :func:`from_chaos_platform`, which fails closed.

Spec shape::

    run: "quarterly resilience game-day"
    clone_of: "twin:invisable-clone-2026Q2"     # MUST be a clone, never production
    results:
      - scenario: {id: s1, mode: policy_engine_down, target: "svc:messaging-relay",
                   predicted_impact: ["svc:messaging-relay"]}
        actual_impact: ["svc:messaging-relay", "db:mailbox"]
        recovered: true
        rto_seconds: 95
        rto_objective_seconds: 120
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .models import ChaosReport, ChaosResult, FailureScenario
from .simulator import ChaosSimulator


def build_from_spec(spec: dict[str, Any]) -> ChaosReport:
    """Construct a chaos report from a ``{run, clone_of, results}`` mapping.

    :class:`ChaosSimulator` enforces clone-only on ``clone_of`` — a production reference raises
    ``ProductionTargetRefused`` before any result is processed.
    """
    sim = ChaosSimulator(clone_of=spec.get("clone_of", ""))
    results = []
    for raw in spec.get("results", []):
        data = dict(raw)
        scenario = FailureScenario(**data.pop("scenario"))
        results.append(ChaosResult(scenario=scenario, **data))
    return sim.report(spec.get("run", "unnamed run"), results)


def load_run(path: str | Path) -> ChaosReport:
    """Load and adjudicate a chaos run from a YAML spec."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"chaos run spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_chaos_platform(_config: Any | None = None) -> ChaosReport:
    """Populate a report from the production chaos platform (against the cloned twin).

    Not yet wired. Fails closed so a caller never reads an empty report as "the model is perfectly
    accurate" — an absent game-day is not a passed one. Until wired, build reports from explicit
    specs.
    """
    raise NotImplementedError(
        "chaos-platform ingestion is not wired yet; build the report from an explicit spec "
        "(build_from_spec/load_run). Set GUARDIAN_ENV=development for spec-based runs."
    )


def production_source_required() -> bool:
    """Whether a real chaos source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
