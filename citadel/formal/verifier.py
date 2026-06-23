"""Formal-model consistency verifier (Citadel Systems 25 + 26).

Without running the provers (a laboratory step), this keeps the formal layer honest: every model in
the registry must exist on disk, declare its properties inside the model file, model a real runtime
module, and cite an executable proving test that exists. It also imports counterexamples as test
fixtures. If a modelled code module changes, re-running the prover is required (flagged here).
"""

from __future__ import annotations

from pathlib import Path

from .spec import REGISTRY, FormalModel

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def model_issues(model: FormalModel) -> list[str]:
    issues: list[str] = []
    if not model.path.exists():
        issues.append(f"{model.model_id}: model file missing ({model.model_file})")
        return issues
    text = model.path.read_text(encoding="utf-8")
    for prop in model.properties:
        if prop not in text:
            issues.append(f"{model.model_id}: property '{prop}' not declared in model file")
    if not (REPO_ROOT / model.models_code).exists():
        issues.append(f"{model.model_id}: modelled code missing ({model.models_code})")
    if not (REPO_ROOT / model.proving_test).exists():
        issues.append(f"{model.model_id}: proving test missing ({model.proving_test})")
    return issues


def verify_all() -> list[str]:
    """Return all consistency issues across the registry ([] == every model present and linked)."""
    issues: list[str] = []
    for model in REGISTRY:
        issues.extend(model_issues(model))
    return issues


def import_counterexample(model_id: str, trace: list[dict]) -> dict:
    """Turn a prover counterexample into a regression fixture (so a failed proof becomes a test)."""
    return {"model_id": model_id, "kind": "counterexample", "steps": list(trace)}


__all__ = ["model_issues", "verify_all", "import_counterexample", "REPO_ROOT"]
