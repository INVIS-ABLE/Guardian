"""Guardian model gateway (target architecture §2).

Every model call goes through :class:`core.ai.gateway.ModelGateway`. It enforces the
routing policy, the context/output firewalls, per-call budgets and the privacy
boundary, and records one immutable :class:`ModelCallRecord` per call. Provider SDKs
are optional and lazily imported; without them the gateway fails closed rather than
substituting a different model.
"""

from __future__ import annotations

from .budgets import CallBudget
from .context_firewall import max_classification, render_prompt
from .gateway import ModelGateway, default_gateway
from .output_firewall import screen_output
from .provenance import ModelCallRecord, hash_text
from .registry import ModelRegistry, default_registry
from .routing import RoutingDecision, route
from .schemas import (
    BudgetExceededError,
    GatewayError,
    ModelClass,
    ModelRequest,
    ModelResponse,
    ModelSpec,
    ModelUnavailableError,
    PolicyRoutingError,
    PrivacyBoundaryError,
    WorkClass,
)

__all__ = [
    "ModelGateway",
    "default_gateway",
    "ModelRegistry",
    "default_registry",
    "ModelRequest",
    "ModelResponse",
    "ModelSpec",
    "ModelClass",
    "WorkClass",
    "RoutingDecision",
    "route",
    "CallBudget",
    "ModelCallRecord",
    "hash_text",
    "max_classification",
    "render_prompt",
    "screen_output",
    "GatewayError",
    "PolicyRoutingError",
    "PrivacyBoundaryError",
    "ModelUnavailableError",
    "BudgetExceededError",
]
