"""Tool router — the Guardian Brain's single, guarded path to action.

Agents *decide*; the router *acts*. Every connector and simulator invocation goes
through one chokepoint so that:

  * a high-level **capability** (e.g. ``"static_code"``, ``"secrets"``,
    ``"privacy_simulation"``) is resolved to a concrete tool,
  * the guardrails are evaluated *before* dispatch (default-deny, fail-closed),
  * dry-run is honoured,
  * the call and its outcome are written to the tamper-evident audit log,
  * results come back in one uniform shape regardless of the underlying tool.

Because all execution funnels through :class:`ToolRouter`, the boundaries in
GUARDRAILS.md are enforced uniformly and cannot be bypassed by an individual agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from connectors import REGISTRY as CONNECTOR_REGISTRY
from connectors.base import BaseConnector, ConnectorResult
from simulators import REGISTRY as SIMULATOR_REGISTRY
from simulators.base import BaseSimulator

from .audit import AuditLog
from .evidence import SimulatorResult
from .guardrails import GuardrailViolation, Guardrails
from .scope import Scope

# Capability → (kind, tool-name). Capabilities are the stable vocabulary the Brain
# and agents speak; the concrete tool behind each can change without touching agents.
CAPABILITY_MAP: dict[str, tuple[str, str]] = {
    # static / code
    "static_code": ("connector", "semgrep"),
    "codeql": ("connector", "codeql"),
    "secrets": ("connector", "gitleaks"),
    # supply chain / containers
    "dependency": ("connector", "trivy"),
    "container": ("connector", "trivy"),
    # dynamic
    "dast": ("connector", "zap"),
    "api_security": ("connector", "zap"),
    # credential resilience (approval-gated; owned staging + test accounts only)
    "password_strength": ("connector", "hashcat"),
    "login_resilience": ("connector", "hydra"),
    # defensive simulators
    "privacy_simulation": ("simulator", "privacy_leak"),
    "banned_user_simulation": ("simulator", "banned_user_return"),
    "moderator_abuse_simulation": ("simulator", "moderator_abuse"),
}


@dataclass
class RouteResult:
    """Uniform router outcome — same shape for connectors and simulators."""

    capability: str
    kind: str            # "connector" | "simulator"
    tool: str
    allowed: bool
    dry_run: bool
    output: dict[str, Any] = field(default_factory=dict)
    refusal_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "kind": self.kind,
            "tool": self.tool,
            "allowed": self.allowed,
            "dry_run": self.dry_run,
            "output": self.output,
            "refusal_reason": self.refusal_reason,
        }


class UnknownCapability(KeyError):
    """Raised when a capability has no registered tool."""


class ToolRouter:
    """Routes capabilities to guarded tool executions for one scope."""

    def __init__(
        self,
        scope: Scope,
        *,
        guardrails: Guardrails | None = None,
        dry_run: bool = True,
    ) -> None:
        self.scope = scope
        self.guardrails = guardrails or Guardrails(scope=scope)
        self.dry_run = dry_run
        self.audit = AuditLog()

    # --- discovery -------------------------------------------------------------
    @staticmethod
    def capabilities() -> list[str]:
        return sorted(CAPABILITY_MAP)

    def resolve(self, capability: str) -> tuple[str, str]:
        if capability not in CAPABILITY_MAP:
            raise UnknownCapability(
                f"No tool registered for capability '{capability}'. "
                f"Known: {', '.join(self.capabilities())}"
            )
        return CAPABILITY_MAP[capability]

    # --- dispatch --------------------------------------------------------------
    def route(self, capability: str, **kwargs: Any) -> RouteResult:
        """Resolve, authorise, and execute a capability. Refusals are returned,
        not raised — the Brain records and continues, fail-closed for that step."""
        kind, tool = self.resolve(capability)
        result = RouteResult(
            capability=capability, kind=kind, tool=tool, allowed=False, dry_run=self.dry_run
        )
        try:
            # Pre-authorise on the tool's declared mode/action so the guardrail
            # decision (and its clear refusal message) happens before any tool work.
            self._preauthorize(kind, tool)
            if kind == "connector":
                result.output = self._run_connector(tool, **kwargs).to_dict()
            elif kind == "simulator":
                result.output = self._run_simulator(tool).to_dict()
            else:  # pragma: no cover - guarded by CAPABILITY_MAP
                raise UnknownCapability(f"Unknown tool kind '{kind}'")
            result.allowed = True
        except (GuardrailViolation, PermissionError) as exc:
            result.refusal_reason = str(exc)
            self.audit.record(
                f"router:{capability}:refused",
                actor="tool_router",
                scope=self.scope.asset,
                decision="refused",
                detail={"tool": tool, "reason": str(exc)},
            )
        return result

    # --- internals -------------------------------------------------------------
    def _preauthorize(self, kind: str, tool: str) -> None:
        """Gate on the tool's declared mode/action before dispatch (fail-closed)."""
        registry = CONNECTOR_REGISTRY if kind == "connector" else SIMULATOR_REGISTRY
        cls = registry.get(tool)
        if cls is None:
            raise UnknownCapability(f"{kind} '{tool}' is not registered.")
        self.guardrails.assert_mode_allowed(cls.mode)
        self.guardrails.assert_not_blocked(cls.action)
        self.guardrails.assert_approved(cls.action)

    def _run_connector(self, tool: str, **kwargs: Any) -> ConnectorResult:
        cls: type[BaseConnector] | None = CONNECTOR_REGISTRY.get(tool)
        if cls is None:
            raise UnknownCapability(f"Connector '{tool}' is not registered.")
        connector = cls(self.scope, dry_run=self.dry_run, guardrails=self.guardrails)
        self.audit.record(
            f"router:{tool}:dispatch",
            actor="tool_router",
            scope=self.scope.asset,
            decision="allowed",
            detail={"kind": "connector", "dry_run": self.dry_run},
        )
        # Connector.run() applies the guardrails again at the point of execution.
        return connector.run(
            repo=kwargs.get("repo"), target=kwargs.get("target"),
            **{k: v for k, v in kwargs.items() if k not in {"repo", "target"}},
        )

    def _run_simulator(self, tool: str) -> SimulatorResult:
        cls: type[BaseSimulator] | None = SIMULATOR_REGISTRY.get(tool)
        if cls is None:
            raise UnknownCapability(f"Simulator '{tool}' is not registered.")
        simulator = cls(self.scope, dry_run=self.dry_run, guardrails=self.guardrails)
        self.audit.record(
            f"router:{tool}:dispatch",
            actor="tool_router",
            scope=self.scope.asset,
            decision="allowed",
            detail={"kind": "simulator", "dry_run": self.dry_run},
        )
        # Simulator.run() authorises via guardrails before doing anything.
        return simulator.run()
