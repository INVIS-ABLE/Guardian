"""Guardian canonical schemas (Wave 1 — typed contracts).

One import surface for Guardian's typed contracts. The authoritative models keep living
in their owning packages (``core.evidence.models``, ``core.brain.state``,
``core.tools.manifest``, ``core.ai.schemas``); this package re-exports them under a
single canonical registry, adds the missing :class:`CaseEvent` envelope, exports JSON
Schema for each, and provides backward-compatibility adapters for the legacy
``RouteResult`` / ``ConnectorResult`` shapes.

There is one owner per schema — this package never redefines a model that already
exists elsewhere.

Import discipline: the leaf modules (``events``, ``adapters`` and the new model
modules) are imported eagerly because they depend only on pydantic. The ``registry``
module is imported **lazily** via :pep:`562` ``__getattr__`` because it pulls in
``core.brain.state`` — eager-importing it here would create an import cycle with
``core.router`` (which imports this package to emit ``CaseEvent``s). Accessing any
registry symbol (e.g. ``core.schemas.export_json_schemas``) loads it on first use.
"""

from __future__ import annotations

from typing import Any

from .adapters import connector_result_to_event, route_result_to_event
from .approvals import Approval
from .bundles import EvidenceBundle, merkle_root
from .decisions import GuardianDecision
from .events import SCHEMA_VERSION, CaseEvent, canonical_payload_hash
from .execution import ArtifactRef, ExecutionJob
from .remediation import CodeChange, RemediationOption

# Registry symbols (CANONICAL_SCHEMAS, export_json_schemas, ...) are resolved lazily via
# __getattr__ below to avoid an import cycle: registry -> core.brain.state -> core.brain
# -> orchestrator -> core.router -> core.schemas. No static path from this package reaches
# the registry module, so the cycle cannot form at import time.
_REGISTRY_EXPORTS = frozenset(
    {
        "CANONICAL_SCHEMAS",
        "schema_names",
        "get_model",
        "json_schema",
        "all_json_schemas",
        "export_json_schemas",
    }
)


def __getattr__(name: str) -> Any:
    if name in _REGISTRY_EXPORTS:
        from . import registry

        return getattr(registry, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
