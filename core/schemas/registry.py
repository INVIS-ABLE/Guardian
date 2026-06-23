"""Canonical schema registry + JSON Schema export (Wave 1).

Guardian's typed contracts are authoritative but were scattered across packages
(``core.evidence.models``, ``core.brain.state``, ``core.tools.manifest``,
``core.ai.schemas``) plus the new event envelope. This registry gives them ONE
canonical name space and exports a versioned JSON Schema for each, so external
consumers (the PWA, other services) and contract tests have a single source of truth.

It deliberately *re-exports* the existing authoritative models rather than redefining
them — there is one owner per schema, never two competing definitions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from core.ai.schemas import ModelRequest, ModelResponse, ModelSpec
from core.brain.state import GuardianCaseState
from core.evidence.models import (
    AssetRef,
    EvidenceItem,
    Finding,
    Hypothesis,
    PolicyDecisionRecord,
    ProposedAction,
    Provenance,
    TestProposal,
    VerificationResult,
)
from core.tools.manifest import SignedManifest, ToolManifest

from .approvals import Approval
from .bundles import EvidenceBundle
from .decisions import GuardianDecision
from .events import CaseEvent
from .execution import ArtifactRef, ExecutionJob
from .remediation import CodeChange, RemediationOption

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

#: Canonical name -> authoritative Pydantic model. One owner per schema.
CANONICAL_SCHEMAS: dict[str, type[BaseModel]] = {
    # Case / reasoning
    "guardian_case_state": GuardianCaseState,
    "case_event": CaseEvent,
    "hypothesis": Hypothesis,
    "proposed_action": ProposedAction,
    "policy_decision_record": PolicyDecisionRecord,
    "verification_result": VerificationResult,
    # Evidence / findings
    "asset_ref": AssetRef,
    "provenance": Provenance,
    "evidence_item": EvidenceItem,
    "finding": Finding,
    "test_proposal": TestProposal,
    # Tools / execution
    "tool_manifest": ToolManifest,
    "signed_manifest": SignedManifest,
    "execution_job": ExecutionJob,
    "artifact_ref": ArtifactRef,
    # Model decisions
    "model_spec": ModelSpec,
    "model_request": ModelRequest,
    "model_response": ModelResponse,
    "guardian_decision": GuardianDecision,
    # Approvals / remediation / evidence bundles
    "approval": Approval,
    "remediation_option": RemediationOption,
    "code_change": CodeChange,
    "evidence_bundle": EvidenceBundle,
}


def schema_names() -> list[str]:
    """Sorted canonical schema names."""
    return sorted(CANONICAL_SCHEMAS)


def get_model(name: str) -> type[BaseModel]:
    """Resolve a canonical name to its authoritative model (raises KeyError if unknown)."""
    return CANONICAL_SCHEMAS[name]


def json_schema(name: str) -> dict[str, Any]:
    """Return the JSON Schema for one canonical model."""
    return CANONICAL_SCHEMAS[name].model_json_schema()


def all_json_schemas() -> dict[str, dict[str, Any]]:
    """Return JSON Schemas for every canonical model, keyed by canonical name."""
    return {name: model.model_json_schema() for name, model in CANONICAL_SCHEMAS.items()}


def export_json_schemas(out_dir: Path | None = None) -> list[Path]:
    """Write ``schemas/<name>-v1.json`` for every canonical model. Returns paths."""
    import json

    target = out_dir or (REPO_ROOT / "schemas")
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in sorted(all_json_schemas().items()):
        path = target / f"{name}-v1.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


__all__ = [
    "CANONICAL_SCHEMAS",
    "schema_names",
    "get_model",
    "json_schema",
    "all_json_schemas",
    "export_json_schemas",
    "REPO_ROOT",
]
