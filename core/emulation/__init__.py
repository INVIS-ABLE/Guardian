"""Guardian continuous adversary-emulation lab (Sovereign plane, Wave 3, system #13).

The first Wave-3 (Proof) system. It emulates MITRE ATT&CK techniques **in the disposable lab
only** and scores each on the three questions that matter — was it prevented? detected by an
independent sensor? was evidence preserved? — turning **every bypass into a regression test** so
a control gap can never silently reappear (docs/sovereign_ops_plane.md; upstream: CALDERA).

Lab-only and metadata-only by construction: the harness refuses any non-range environment and
records *that* a technique was or wasn't caught, never production data.
"""

from __future__ import annotations

from .ingest import (
    build_from_spec,
    from_caldera,
    load_operation,
    production_source_required,
)
from .lab import (
    LAB_ENVIRONMENTS,
    AdversaryLab,
    EmulationError,
    LabOnlyViolation,
)
from .models import (
    EmulationReport,
    RegressionReason,
    RegressionTest,
    Tactic,
    Technique,
    TechniqueResult,
    Verdict,
)

__all__ = [
    "AdversaryLab",
    "EmulationError",
    "LabOnlyViolation",
    "LAB_ENVIRONMENTS",
    "Tactic",
    "Technique",
    "TechniqueResult",
    "Verdict",
    "RegressionReason",
    "RegressionTest",
    "EmulationReport",
    "build_from_spec",
    "load_operation",
    "from_caldera",
    "production_source_required",
]
