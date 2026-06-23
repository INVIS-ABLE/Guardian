"""Crypto-proof ingestion — build a report from a spec, or from the symbolic provers.

For development/CI the report is built from a spec of protocols + proof results. In production
the results come from **Tamarin / Verifpal / ProVerif** runs in CI; that wiring lands at
:func:`from_provers`, which fails closed.

Spec shape::

    protocols:
      - {id: "proto:device-enrolment", name: "Device enrolment", prover: tamarin}
    results:
      - {protocol_id: "proto:device-enrolment", status: proved,
         property: {kind: authentication, description: "enrolling device is authenticated"}}
      - {protocol_id: "proto:account-recovery", status: falsified,
         property: {kind: recovery_soundness, description: "recovery cannot impersonate"},
         attack_trace: ["attacker triggers recovery", "race binds attacker device"]}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .lab import CryptoProofLab
from .models import ProofReport, ProofResult, Protocol, SecurityProperty


def build_from_spec(spec: dict[str, Any]) -> ProofReport:
    """Construct a proof report from a ``{protocols, results}`` mapping."""
    lab = CryptoProofLab(Protocol(**p) for p in spec.get("protocols", []))
    results = []
    for raw in spec.get("results", []):
        data = dict(raw)
        prop = SecurityProperty(**data.pop("property"))
        results.append(ProofResult(property=prop, **data))
    return lab.report(results)


def load_proofs(path: str | Path) -> ProofReport:
    """Load and adjudicate a crypto-proof run from a YAML spec."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"crypto-proof spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_from_spec(data)


def from_provers(_config: Any | None = None) -> ProofReport:
    """Populate a report from the production provers (Tamarin / Verifpal / ProVerif).

    Not yet wired. Fails closed so a caller never reads an empty report as "all properties hold":
    an absent proof is not a passed proof. Until wired, build reports from explicit specs.
    """
    raise NotImplementedError(
        "symbolic-prover ingestion is not wired yet; build the report from an explicit spec "
        "(build_from_spec/load_proofs). Set GUARDIAN_ENV=development for spec-based runs."
    )


def production_source_required() -> bool:
    """Whether a real prover source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
