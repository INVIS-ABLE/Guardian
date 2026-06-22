"""Backward-compatibility adapters (Wave 1).

The Final Power-Up adds a typed event mesh, but existing code already returns
``RouteResult`` (``core.router``) and ``ConnectorResult`` (``connectors.base``), and
records evidence via ``core.evidence``. These adapters lift those legacy shapes into the
canonical :class:`~core.schemas.events.CaseEvent` envelope **without changing the legacy
types** — so old callers keep working while new consumers get a uniform, hashed event.

Adapters duck-type on ``.to_dict()`` to avoid import cycles with the connector layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from .events import CaseEvent

if TYPE_CHECKING:  # pragma: no cover - typing only
    from connectors.base import ConnectorResult
    from core.router import RouteResult


class _HasToDict(Protocol):
    def to_dict(self) -> dict: ...


def route_result_to_event(
    result: RouteResult | _HasToDict,
    *,
    case_id: UUID | None = None,
    trace_id: str = "",
    workflow_id: str = "",
) -> CaseEvent:
    """Lift a legacy ``RouteResult`` into a canonical ``CaseEvent``.

    ``allowed`` maps to ``guardian.tool.completed``; a refusal maps to
    ``guardian.tool.refused``. The full legacy dict is preserved as the payload.
    """
    payload = result.to_dict()
    allowed = bool(payload.get("allowed"))
    event_type = "guardian.tool.completed" if allowed else "guardian.tool.refused"
    tool = payload.get("tool")
    return CaseEvent.create(
        event_type=event_type,
        actor="tool-router",
        payload=payload,
        case_id=case_id,
        trace_id=trace_id,
        workflow_id=workflow_id,
        asset_refs=(f"tool:{tool}",) if tool else (),
    )


def connector_result_to_event(
    result: ConnectorResult | _HasToDict,
    *,
    case_id: UUID | None = None,
    trace_id: str = "",
    workflow_id: str = "",
) -> CaseEvent:
    """Lift a legacy ``ConnectorResult`` into a canonical ``CaseEvent``."""
    payload = result.to_dict()
    tool = payload.get("tool")
    return CaseEvent.create(
        event_type="guardian.tool.connector",
        actor=f"connector:{tool}" if tool else "connector",
        payload=payload,
        case_id=case_id,
        trace_id=trace_id,
        workflow_id=workflow_id,
        asset_refs=(f"tool:{tool}",) if tool else (),
    )


__all__ = ["route_result_to_event", "connector_result_to_event"]
