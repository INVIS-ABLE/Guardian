"""Wave 2 — router fabric: tool-health service + health-aware candidate resolver.

Acceptance: a capability resolves to the healthiest verified, environment-permitted
candidate; the circuit breaker takes a repeatedly-failing tool out of rotation and
restores it after cooldown; resolution always returns a typed decision or refusal,
never an exception.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.tools.health import HealthState, ToolHealthTracker
from core.tools.manifest import (
    NetworkMode,
    ResourceLimits,
    ToolManifest,
    sign_manifest,
)
from core.tools.registry import RefusalReason, ToolRefusal, default_registry
from core.tools.resolver import CapabilityResolver, ResolverDecision

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _signed(capability: str, tool: str, *, envs=("staging",)):
    m = ToolManifest(
        capability=capability, tool=tool, image_digest=f"sha256:{'0' * 64}",
        input_schema=f"schemas/{capability}-input-v1.json",
        output_schema=f"schemas/{capability}-output-v1.json",
        allowed_environments=envs, requires_approval=False,
        network=NetworkMode.DENY_ALL, limits=ResourceLimits(),
    )
    return sign_manifest(m)


# --- health tracker --------------------------------------------------------------------

def test_new_tool_starts_healthy():
    h = ToolHealthTracker()
    assert h.health("semgrep").state is HealthState.HEALTHY
    assert h.is_available("semgrep")
    assert h.health("semgrep").score == 1.0


def test_failures_open_circuit_then_cooldown_half_opens():
    h = ToolHealthTracker(failure_threshold=3, cooldown_seconds=60)
    for _ in range(3):
        h.record_failure("zap", error="timeout", now=NOW)
    # circuit open -> unavailable during cooldown
    assert h.health("zap", now=NOW).state is HealthState.UNAVAILABLE
    assert not h.is_available("zap", now=NOW)
    # after cooldown -> half-open (degraded, but usable for a trial)
    later = NOW + timedelta(seconds=61)
    assert h.health("zap", now=later).state is HealthState.DEGRADED
    assert h.is_available("zap", now=later)


def test_success_closes_circuit_and_recovers_score():
    h = ToolHealthTracker(failure_threshold=2, cooldown_seconds=10)
    h.record_failure("trivy", now=NOW)
    h.record_failure("trivy", now=NOW)
    assert h.health("trivy", now=NOW).state is HealthState.UNAVAILABLE
    h.record_success("trivy", latency_ms=12.0)
    snap = h.health("trivy", now=NOW)
    assert snap.state is HealthState.HEALTHY
    assert snap.consecutive_failures == 0
    assert snap.last_latency_ms == 12.0


def test_snapshot_lists_all_tracked_tools():
    h = ToolHealthTracker()
    h.record_success("a")
    h.record_failure("b")
    assert set(h.snapshot()) == {"a", "b"}


# --- resolver --------------------------------------------------------------------------

def test_resolve_single_candidate_unchanged():
    r = CapabilityResolver.from_registry(default_registry())
    d = r.resolve("static_code_scan", environment="staging")
    assert isinstance(d, ResolverDecision)
    assert d.selected_tool == "semgrep"
    assert d.had_alternatives is False


def test_unknown_capability_refuses():
    r = CapabilityResolver()
    d = r.resolve("nope", environment="staging")
    assert isinstance(d, ToolRefusal)
    assert d.reason is RefusalReason.UNKNOWN_CAPABILITY


def test_environment_block_refuses():
    r = CapabilityResolver()
    r.register(_signed("dast", "zap", envs=("staging",)))
    d = r.resolve("dast", environment="production")
    assert isinstance(d, ToolRefusal)
    assert d.reason is RefusalReason.ENVIRONMENT_NOT_ALLOWED


def test_prefers_healthier_candidate():
    h = ToolHealthTracker(failure_threshold=10)  # keep both available; compare by score
    r = CapabilityResolver(health=h)
    r.register(_signed("scan", "alpha"))
    r.register(_signed("scan", "beta"))
    # degrade alpha's score with failures (not enough to open the circuit)
    for _ in range(3):
        r.record_outcome("alpha", ok=False, error="x")
    r.record_outcome("beta", ok=True, latency_ms=5.0)
    d = r.resolve("scan", environment="staging")
    assert isinstance(d, ResolverDecision)
    assert d.selected_tool == "beta"
    assert d.had_alternatives is True
    # candidates are ranked best-first
    assert d.candidates[0].tool == "beta"


def test_falls_back_when_primary_circuit_open():
    h = ToolHealthTracker(failure_threshold=3, cooldown_seconds=60)
    r = CapabilityResolver(health=h)
    r.register(_signed("scan", "primary"))
    r.register(_signed("scan", "backup"))
    for _ in range(3):
        r.record_outcome("primary", ok=False, error="down")
    d = r.resolve("scan", environment="staging")
    assert isinstance(d, ResolverDecision)
    assert d.selected_tool == "backup"  # primary's circuit is open


def test_all_unavailable_refuses():
    h = ToolHealthTracker(failure_threshold=2, cooldown_seconds=60)
    r = CapabilityResolver(health=h)
    r.register(_signed("scan", "only"))
    r.record_outcome("only", ok=False)
    r.record_outcome("only", ok=False)
    d = r.resolve("scan", environment="staging")
    assert isinstance(d, ToolRefusal)
    assert d.reason is RefusalReason.TOKEN_REJECTED


def test_resolution_never_raises_on_bad_input():
    r = CapabilityResolver.from_registry(default_registry())
    for cap in ("", "static_code_scan", "definitely-unknown"):
        for env in ("development", "staging", "production"):
            out = r.resolve(cap, environment=env)
            assert isinstance(out, (ResolverDecision, ToolRefusal))


# --- executor <-> health integration ---------------------------------------------------

def test_executor_records_success_into_health():
    from uuid import uuid4

    from core.tools.executor import ToolExecutor

    health = ToolHealthTracker()
    ex = ToolExecutor(default_registry(), health=health)
    out = ex.execute("static_code_scan", case_id=uuid4(), args={"x": 1}, environment="staging")
    # dry-run execution still succeeds structurally and feeds health
    assert not isinstance(out, ToolRefusal)
    h = health.health("semgrep")
    assert h.successes == 1
    assert h.state is HealthState.HEALTHY


def test_executor_records_failure_when_runner_raises():
    from uuid import uuid4

    from core.tools.executor import ToolExecutor

    class _Boom:
        def run(self, manifest, token, args):
            raise RuntimeError("sandbox exploded")

    health = ToolHealthTracker(failure_threshold=1)
    ex = ToolExecutor(default_registry(), runner=_Boom(), health=health)
    try:
        ex.execute("static_code_scan", case_id=uuid4(), args={"x": 1}, environment="staging")
    except RuntimeError:
        pass
    else:  # pragma: no cover - the runner must propagate
        raise AssertionError("runner error should propagate")
    h = health.health("semgrep")
    assert h.failures == 1
    assert h.state is HealthState.UNAVAILABLE  # threshold=1 opens the circuit
