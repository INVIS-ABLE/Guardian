"""Shadow Guardian — an independent verifier of high-risk Guardian transitions.

Deliberately a *separate* package from ``core`` (target architecture §35): the Shadow
Guardian re-checks the things the primary Guardian issues — capability tokens and their
signed tool manifests — using its **own** re-derivation, holds **no** execution
credentials, and can **freeze** capability issuance when it sees an unexplained
divergence. Loss of the Shadow Guardian (or any divergence) freezes high-risk actions.

In production this runs as a separate codebase, account and key set. Here it is a
clearly-isolated package that does not import the primary's hashing/signing helpers — it
recomputes them independently so a bug or compromise on the primary side cannot make the
Shadow agree by construction.
"""

from __future__ import annotations

from .verifier import (
    CapabilityFrozen,
    FreezeLatch,
    ObservedCall,
    ShadowFinding,
    ShadowGate,
    ShadowGuardian,
    ShadowReport,
)

__all__ = [
    "ShadowGuardian",
    "ShadowReport",
    "ShadowFinding",
    "ObservedCall",
    "FreezeLatch",
    "ShadowGate",
    "CapabilityFrozen",
]
