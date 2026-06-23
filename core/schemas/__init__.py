"""Guardian canonical schemas (Wave 1 — typed contracts).

One import surface for Guardian's typed contracts. The authoritative models keep living
in their owning packages (``core.evidence.models``, ``core.brain.state``,
``core.tools.manifest``, ``core.ai.schemas``); this package re-exports them under a
single canonical registry, adds the missing :class:`CaseEvent` envelope, exports JSON
Schema for each, and provides backward-compatibility adapters for the legacy
``RouteResult`` / ``ConnectorResult`` shapes.

There is one owner per schema — this package never redefines a model that already
exists elsewhere.
"""

from __future__ import annotations

from .adapters import connector_result_to_event, route_result_to_event
from .approvals import Approval
from .bundles import EvidenceBundle, merkle_root
from .decisions import GuardianDecision
from .events import SCHEMA_VERSION, CaseEvent, canonical_payload_hash
from .execution import ArtifactRef, ExecutionJob
from .registry import (
    CANONICAL_SCHEMAS,
    all_json_schemas,
    export_json_schemas,
    get_model,
    json_schema,
    schema_names,
)
from .remediation import CodeChange, RemediationOption

__all__ = [
    "CaseEvent",
    "SCHEMA_VERSION",
    "canonical_payload_hash",
    "ExecutionJob",
    "ArtifactRef",
    "GuardianDecision",
    "RemediationOption",
    "CodeChange",
    "Approval",
    "EvidenceBundle",
    "merkle_root",
    "CANONICAL_SCHEMAS",
    "schema_names",
    "get_model",
    "json_schema",
    "all_json_schemas",
    "export_json_schemas",
    "route_result_to_event",
    "connector_result_to_event",
]
