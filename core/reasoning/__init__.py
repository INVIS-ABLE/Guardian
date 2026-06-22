"""Guardian Wave 2 reasoning — deeper intelligence over the Wave 1 awareness graphs.

Three composing engines that turn a rich map into investigated, calibrated conclusions
(docs/sovereign_ops_plane.md, Wave 2):

  * #7  evidence & competing-hypothesis engine  — :mod:`core.reasoning.hypothesis`
  * #8  causal root-cause engine                — :mod:`core.reasoning.causal`
  * #10 confidence calibration & abstention      — :mod:`core.reasoning.calibration`

All read-only and metadata-only: they reason over the typed evidence contracts
(:mod:`core.evidence.models`) and the digital twin (:mod:`core.twin`), and add no authority —
cognition proposes, authority disposes.
"""

from __future__ import annotations

from .calibration import Bin, Calibrator
from .causal import CausalReport, Counterfactual, root_cause
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
]
