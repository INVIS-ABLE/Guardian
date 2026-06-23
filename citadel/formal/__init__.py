"""Citadel Systems 25 + 26 — Formal State-Machine + Protocol Verification (Waves 25-26).

Formal models (TLA+ / Tamarin) for the capability lifecycle and attestation-bound secret release,
each linked to the runtime code it abstracts and the test that exercises the same invariant. The
provers run in a laboratory toolchain; the consistency verifier here keeps models present + linked.
"""

from __future__ import annotations

from .spec import REGISTRY, FormalModel, Prover, models
from .verifier import import_counterexample, model_issues, verify_all

__all__ = [
    "REGISTRY", "FormalModel", "Prover", "models",
    "import_counterexample", "model_issues", "verify_all",
]
