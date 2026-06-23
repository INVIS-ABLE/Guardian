"""Case ingestion for the Wave-2 reasoning engines (Sovereign plane, systems #7–#11).

Builds the reasoning :class:`~core.reasoning.council.Case` — a bundle of evidence and the
competing hypotheses about it — from a human-authored spec, so the same loaded case can be fed
to the adjudicator (:mod:`core.reasoning.hypothesis`), the ACH overlay (:mod:`core.reasoning.ach`)
*and* the council (:mod:`core.reasoning.council`). Evidence is referenced by a short stable
**key** in the spec (``E1``, ``falco-shell``); the loader mints a UUID per evidence item and
rewrites each hypothesis's ``consistent`` / ``inconsistent`` key lists into the model's
UUID-keyed ``supporting_evidence_ids`` / ``contradicting_evidence_ids``.

Spec shape::

    evidence:
      - { key: E1, kind: log_line, summary: "...", trust_level: verified_evidence,
          validation_state: validated, provenance: {tool: falco} }
    hypotheses:
      - { statement: "...", consistent: [E1], inconsistent: [E2], status: unverified,
          falsification_tests: [{description: "...", expected_if_true: "...", expected_if_false: "..."}] }
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import yaml

from core.evidence.models import EvidenceItem, Hypothesis, Provenance, TestProposal

from .council import Case


def build_case_from_spec(spec: dict[str, Any]) -> Case:
    """Construct a reasoning :class:`Case` from a ``{evidence: [...], hypotheses: [...]}`` mapping."""
    key_to_id: dict[str, UUID] = {}
    evidence: list[EvidenceItem] = []
    for raw in spec.get("evidence", []):
        data = dict(raw)
        key = data.pop("key", None)
        if key is None:
            raise ValueError("each evidence item needs a 'key' to be referenced by hypotheses")
        prov = data.pop("provenance", {"tool": "unknown"})
        item = EvidenceItem(id=uuid4(), provenance=Provenance(**prov), **data)
        key_to_id[key] = item.id
        evidence.append(item)

    def _ids(keys: list[str]) -> tuple[UUID, ...]:
        missing = [k for k in keys if k not in key_to_id]
        if missing:
            raise ValueError(f"hypothesis references unknown evidence keys: {missing}")
        return tuple(key_to_id[k] for k in keys)

    hypotheses: list[Hypothesis] = []
    for raw in spec.get("hypotheses", []):
        data = dict(raw)
        consistent = data.pop("consistent", [])
        inconsistent = data.pop("inconsistent", [])
        tests = tuple(TestProposal(**t) for t in data.pop("falsification_tests", []))
        hypotheses.append(Hypothesis(
            supporting_evidence_ids=_ids(consistent),
            contradicting_evidence_ids=_ids(inconsistent),
            falsification_tests=tests, **data,
        ))
    return Case(evidence=tuple(evidence), hypotheses=tuple(hypotheses))


def load_case(path: str | Path) -> Case:
    """Load a reasoning case from a YAML spec file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"case spec not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return build_case_from_spec(data)


def from_case_store(_config: Any | None = None) -> Case:
    """Populate a case from the production evidence store / case manager.

    Not yet wired. Fails closed so a production caller never reasons over a silently-empty case:
    an empty ACH matrix would falsely imply "no competing explanations" and let one favoured
    theory stand unchallenged. Until the store is wired, build cases from explicit specs.
    """
    raise NotImplementedError(
        "case-store ingestion is not wired yet; build the case from an explicit spec "
        "(build_case_from_spec/load_case). Set GUARDIAN_ENV=development to use spec-based cases."
    )


def production_source_required() -> bool:
    """Whether a real case source is required (staging/production), mirroring the policy gate."""
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}
