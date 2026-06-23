"""Guardian Wave 2 reasoning — deeper intelligence over the Wave 1 awareness graphs.

Three composing engines that turn a rich map into investigated, calibrated conclusions
(docs/sovereign_ops_plane.md, Wave 2):

  * #7  evidence & competing-hypothesis engine  — :mod:`core.reasoning.hypothesis`
        + ACH matrix / diagnosticity overlay      — :mod:`core.reasoning.ach`
  * #8  causal root-cause engine                — :mod:`core.reasoning.causal`
  * #9  multi-model reasoning council           — :mod:`core.reasoning.council`
  * #10 confidence calibration & abstention      — :mod:`core.reasoning.calibration`
  * #11 autonomous threat-hunting engine         — :mod:`core.reasoning.hunting`

Case ingestion (spec → evidence + hypotheses) lives in :mod:`core.reasoning.cases`.

All read-only and metadata-only: they reason over the typed evidence contracts
(:mod:`core.evidence.models`) and the digital twin (:mod:`core.twin`), and add no authority —
cognition proposes, authority disposes.
"""

from __future__ import annotations

from .ach import (
    ACHView,
    Cell,
    Consistency,
    DiagnosticEvidence,
    MatrixRow,
    ach_matrix,
    analyze,
    diagnostic_split,
)
from .calibration import Bin, Calibrator
from .cases import build_case_from_spec, from_case_store, load_case
from .causal import CausalReport, Counterfactual, root_cause
from .council import Case, CouncilVerdict, convene
from .hunting import HuntResult, run_hunts
from .incident import IncidentVerdict, investigate
from .hypothesis import (
    CaseVerdict,
    HypothesisVerdict,
    adjudicate,
    adjudicate_hypothesis,
)

__all__ = [
    "Calibrator",
    "Bin",
    "HypothesisVerdict",
    "CaseVerdict",
    "adjudicate",
    "adjudicate_hypothesis",
    "CausalReport",
    "Counterfactual",
    "root_cause",
    "Case",
    "CouncilVerdict",
    "convene",
    "HuntResult",
    "run_hunts",
    "IncidentVerdict",
    "investigate",
    # ACH overlay + case ingestion (Wave 2 #7, complementary view)
    "ACHView",
    "MatrixRow",
    "Cell",
    "Consistency",
    "DiagnosticEvidence",
    "ach_matrix",
    "diagnostic_split",
    "analyze",
    "build_case_from_spec",
    "load_case",
    "from_case_store",
]
