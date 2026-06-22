"""Bounded specialist agents (target architecture §6).

The four priority specialists, each with a typed task/result contract, an approved
evidence view, a model-routing class, abstention rules and a deterministic verifier —
and none able to approve or execute its own recommendations:

* :class:`ScopeController` — deterministic scope/identity/ownership (no model).
* :class:`CodeArchitectureAnalyst` — static analysis via the tool gateway, interpreted
  via the model gateway, grounded in evidence.
* :class:`EvidenceAdjudicator` — evidence-led verdict, never majority vote.
* :class:`PatchReviewer` — independent patch verification (different model family).
"""

from __future__ import annotations

from .base import Specialist, SpecialistResult, SpecialistTask, Verdict
from .code_architecture import CodeArchitectureAnalyst
from .evidence_adjudicator import EvidenceAdjudicator
from .patch_reviewer import PatchReviewer
from .scope_controller import ScopeController

__all__ = [
    "Specialist",
    "SpecialistTask",
    "SpecialistResult",
    "Verdict",
    "ScopeController",
    "CodeArchitectureAnalyst",
    "EvidenceAdjudicator",
    "PatchReviewer",
]
