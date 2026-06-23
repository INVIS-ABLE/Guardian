"""Data classification + exfiltration detection (Citadel System 31, Wave 31).

Classify content (PII / secrets), and decide egress: protected data moving to an untrusted
destination is an exfiltration finding. The private-message-plaintext barrier is STRUCTURAL — the
forbidden fields/classifications (mirrors core.verifier) can never enter a model/browser/evidence
pipeline. Every model/browser I/O check produces a traceable decision. Owner: Presidio (production);
independent verifier: isolation/egress.py (existing egress control).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

# Mirrors core/verifier.py::_FORBIDDEN_LEAF_FIELDS — the private-content barrier.
FORBIDDEN_FIELDS = frozenset(
    {"private_key", "plaintext", "message", "conversation_key", "secret", "media"}
)
CLASSIFICATION_DENYLIST = frozenset({"MESSAGE_PLAINTEXT", "DECRYPTION_KEY"})

_PATTERNS = {
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PII = "pii"
    SECRET = "secret"


@dataclass(frozen=True)
class Classification:
    sensitivity: Sensitivity
    detectors: tuple[str, ...]

    @property
    def protected(self) -> bool:
        return self.sensitivity in (Sensitivity.PII, Sensitivity.SECRET)


def classify(text: str) -> Classification:
    hits = [name for name, pat in _PATTERNS.items() if pat.search(text)]
    if any(h in ("aws_key", "private_key_block") for h in hits):
        return Classification(Sensitivity.SECRET, tuple(hits))
    if any(h in ("email", "credit_card") for h in hits):
        return Classification(Sensitivity.PII, tuple(hits))
    return Classification(Sensitivity.INTERNAL, ())


@dataclass(frozen=True)
class EgressDecision:
    allow: bool
    sensitivity: str
    destination_trusted: bool
    reasons: tuple[str, ...]


def egress_decision(text: str, *, destination_trusted: bool) -> EgressDecision:
    """Protected data to an untrusted destination is blocked (an exfiltration finding)."""
    c = classify(text)
    reasons: list[str] = []
    if c.protected and not destination_trusted:
        reasons.append(f"protected_{c.sensitivity.value}_to_untrusted_destination")
    return EgressDecision(allow=not reasons, sensitivity=c.sensitivity.value,
                          destination_trusted=destination_trusted, reasons=tuple(reasons))


def barrier_violation(payload: dict) -> list[str]:
    """Structural check: forbidden fields / denylisted classifications must never enter a pipeline."""
    violations = [f"forbidden_field:{k}" for k in payload if k in FORBIDDEN_FIELDS]
    classification = str(payload.get("classification", ""))
    if classification in CLASSIFICATION_DENYLIST:
        violations.append(f"denylisted_classification:{classification}")
    return violations


@dataclass(frozen=True)
class IoDecision:
    direction: str          # "model_input" | "model_output" | "browser_output"
    allow: bool
    sensitivity: str
    reasons: tuple[str, ...]


def model_io_check(text: str, *, direction: str, destination_trusted: bool = False) -> IoDecision:
    """Scan model/browser I/O and return a traceable allow/deny decision."""
    d = egress_decision(text, destination_trusted=destination_trusted)
    return IoDecision(direction=direction, allow=d.allow, sensitivity=d.sensitivity,
                      reasons=d.reasons)


__all__ = [
    "FORBIDDEN_FIELDS", "CLASSIFICATION_DENYLIST", "Sensitivity", "Classification", "classify",
    "EgressDecision", "egress_decision", "barrier_violation", "IoDecision", "model_io_check",
]
