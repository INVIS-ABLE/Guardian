"""Guardian digital-twin chaos & recovery simulator (Sovereign plane, Wave 3, system #17).

Failure simulations run against a **clone** of the digital twin (#1), never production: kill a
region / IdP / OPA / secrets store / CA / key rotation / queue / DB / audit log / network, then
compare the model's predicted blast radius against the actual impact. Every mismatch is a
*surprise* to learn from — a map gap to fix, or resilience to bank (docs/sovereign_ops_plane.md).

Clone-only by construction: the simulator refuses any reference not marked as a clone, so it can
never inject failures into the production twin.
"""

from __future__ import annotations

from .ingest import (
    build_from_spec,
    from_chaos_platform,
    load_run,
    production_source_required,
)
from .models import (
    ChaosReport,
    ChaosResult,
    FailureMode,
    FailureScenario,
    Surprise,
    SurpriseKind,
)
from .simulator import ChaosError, ChaosSimulator, ProductionTargetRefused

__all__ = [
    "ChaosSimulator",
    "ChaosError",
    "ProductionTargetRefused",
    "FailureMode",
    "SurpriseKind",
    "FailureScenario",
    "Surprise",
    "ChaosResult",
    "ChaosReport",
    "build_from_spec",
    "load_run",
    "from_chaos_platform",
    "production_source_required",
]
