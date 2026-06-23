"""Health-aware capability resolver (Wave 2 — router fabric).

The :class:`~core.tools.registry.ToolRegistry` answers "which signed, environment-
permitted tool serves this capability?" — one manifest per capability. The resolver adds
the fabric layer on top: a capability may have **several** candidate tools, and the
resolver ranks them by current health, selects the best *available* one, and returns a
structured decision (or a structured refusal) — never an exception.

It composes the registry's existing verification (signature + environment, fail-closed)
with the :class:`~core.tools.health.ToolHealthTracker` circuit breaker, so a capability
degrades gracefully to a healthy alternative instead of repeatedly dispatching to a
broken tool. With a single candidate (today's default registry) behaviour is unchanged
except that a tripped circuit yields a refusal rather than a doomed call.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .health import HealthState, ToolHealth, ToolHealthTracker
from .manifest import SignedManifest, ToolManifest, require_signed_manifests
from .registry import RefusalReason, ToolRefusal, ToolRegistry


class Candidate(BaseModel):
    """One scored, verified candidate tool for a capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    score: float = Field(ge=0.0, le=1.0)
    state: HealthState
    available: bool


class ResolverDecision(BaseModel):
    """The resolver's structured choice among candidates."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    environment: str
    selected_tool: str
    manifest: ToolManifest
    candidates: tuple[Candidate, ...]

    @property
    def had_alternatives(self) -> bool:
        return len(self.candidates) > 1


class CapabilityResolver:
    """Ranks verified candidate tools for a capability by health and selects the best."""

    def __init__(self, *, health: ToolHealthTracker | None = None) -> None:
        self._candidates: dict[str, list[SignedManifest]] = {}
        self.health = health or ToolHealthTracker()

    # --- registration ----------------------------------------------------------
    def register(self, signed: SignedManifest) -> None:
        """Add a candidate tool for its capability (multiple candidates allowed)."""
        self._candidates.setdefault(signed.manifest.capability, []).append(signed)

    @classmethod
    def from_registry(
        cls, registry: ToolRegistry, *, health: ToolHealthTracker | None = None
    ) -> CapabilityResolver:
        """Seed a resolver from an existing single-candidate ToolRegistry."""
        resolver = cls(health=health)
        for signed in registry._by_capability.values():  # noqa: SLF001 - intentional bridge
            resolver.register(signed)
        return resolver

    def candidates_for(self, capability: str) -> tuple[str, ...]:
        return tuple(s.manifest.tool for s in self._candidates.get(capability, []))

    # --- resolution ------------------------------------------------------------
    def record_outcome(
        self, tool: str, *, ok: bool, latency_ms: float | None = None, error: str = ""
    ) -> None:
        """Feed an execution outcome back into tool health."""
        if ok:
            self.health.record_success(tool, latency_ms=latency_ms)
        else:
            self.health.record_failure(tool, error=error)

    def resolve(self, capability: str, *, environment: str) -> ResolverDecision | ToolRefusal:
        """Pick the healthiest verified, environment-permitted tool for the capability.

        Fail-closed: an unknown capability, no validly-signed candidate, none permitted in
        the environment, or every candidate's circuit open each yields a typed refusal.
        """
        signed_list = self._candidates.get(capability)
        if not signed_list:
            return ToolRefusal(
                capability=capability, reason=RefusalReason.UNKNOWN_CAPABILITY,
                detail="no candidate tool registered for this capability",
            )

        verified: list[SignedManifest] = []
        saw_signature_failure = False
        saw_environment_block = False
        for signed in signed_list:
            if not signed.verify() and require_signed_manifests():
                saw_signature_failure = True
                continue
            if not signed.manifest.allows_environment(environment):
                saw_environment_block = True
                continue
            verified.append(signed)

        if not verified:
            if saw_environment_block and not saw_signature_failure:
                return ToolRefusal(
                    capability=capability, reason=RefusalReason.ENVIRONMENT_NOT_ALLOWED,
                    detail=f"no candidate permitted in environment '{environment}'",
                )
            return ToolRefusal(
                capability=capability, reason=RefusalReason.SIGNATURE_INVALID,
                detail="no candidate manifest signature verified",
            )

        # Score each verified candidate by current health; rank best-first, then deterministic.
        scored: list[tuple[ToolHealth, SignedManifest]] = [
            (self.health.health(s.manifest.tool), s) for s in verified
        ]
        scored.sort(key=lambda hs: (hs[0].available, hs[0].score, hs[1].manifest.tool), reverse=True)
        candidates = tuple(
            Candidate(tool=h.tool, score=h.score, state=h.state, available=h.available)
            for h, _ in scored
        )

        best_health, best_signed = scored[0]
        if not best_health.available:
            return ToolRefusal(
                capability=capability, reason=RefusalReason.TOKEN_REJECTED,
                detail="all candidate tools are unavailable (circuit open)",
            )
        return ResolverDecision(
            capability=capability,
            environment=environment,
            selected_tool=best_signed.manifest.tool,
            manifest=best_signed.manifest,
            candidates=candidates,
        )


__all__ = ["Candidate", "ResolverDecision", "CapabilityResolver"]
