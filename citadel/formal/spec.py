"""Formal-model registry (Citadel Systems 25 + 26, Waves 25-26).

Each entry links a formal model (TLA+ for state machines, Tamarin for protocols) to (a) the runtime
code it models and (b) the executable test that exercises the same invariant — so a model and its
implementation cannot silently diverge. The provers (TLC/Apalache, Tamarin) run in a laboratory
toolchain; this registry + the consistency verifier keep the models present, declared and linked.

Status: PARTIAL — models authored and linked; prover execution is a laboratory step (not run here).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parent / "models"


class Prover(str, Enum):
    TLC = "tlc"            # TLA+ model checker
    APALACHE = "apalache"
    TAMARIN = "tamarin"
    PROVERIF = "proverif"


@dataclass(frozen=True)
class FormalModel:
    model_id: str
    model_file: str          # relative to models/
    prover: Prover
    properties: tuple[str, ...]
    models_code: str         # the runtime module this abstracts
    proving_test: str        # the executable test exercising the same invariant

    @property
    def path(self) -> Path:
        return MODELS_DIR / self.model_file


REGISTRY: tuple[FormalModel, ...] = (
    FormalModel(
        model_id="capability_lifecycle",
        model_file="capability.tla",
        prover=Prover.TLC,
        properties=("NoReplay", "NoExpiredUse", "ApprovalBound"),
        models_code="core/tools/capability.py",
        proving_test="tests/test_citadel_quorum.py",   # approval/threshold invariants exercised here
    ),
    FormalModel(
        model_id="attestation_secret_release",
        model_file="attestation_secret_release.spthy",
        prover=Prover.TAMARIN,
        properties=("secrecy", "no_release_without_attestation"),
        models_code="citadel/confidential/secret_release.py",
        proving_test="tests/test_citadel_confidential.py",
    ),
)


def models() -> tuple[FormalModel, ...]:
    return REGISTRY


__all__ = ["Prover", "FormalModel", "REGISTRY", "MODELS_DIR", "models"]
