"""Flink stateful-correlation job manifests (directive §11).

Flink is Guardian's stateful nervous system: it correlates events, tracks sequences and
builds baselines. Every job is versioned, signed, declares its input/output topics and
state schema, has a checkpoint policy, a privacy classification, tenant isolation, resource
limits and passing replay tests. **Flink never grants authority — it generates evidence and
signals.** Typed manifest + fail-closed validator (acceptance #35).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FlinkResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_slots: int = Field(gt=0)
    memory_mb: int = Field(gt=0)


class FlinkJobManifest(BaseModel):
    """A signed, replayable, tenant-isolated correlation job (§11)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")  # signed artifact
    input_topics: tuple[str, ...]
    output_topics: tuple[str, ...]
    state_schema_version: int = Field(ge=0)
    checkpoint_interval_seconds: int = Field(gt=0)  # state recovers from checkpoints (#35)
    privacy_classification: str = "internal"
    tenant_isolated: bool = True
    resource_limits: FlinkResourceLimits
    replay_tests_passed: bool = False
    grants_authority: bool = False  # invariant — never True


class FlinkJobError(RuntimeError):
    """Raised when a Flink job manifest violates an invariant. Fail closed."""


def assert_flink_job_valid(job: FlinkJobManifest) -> None:
    """A job is deployable only if signed, isolated, checkpointed and replay-tested (§11)."""
    if job.grants_authority:
        raise FlinkJobError(f"Flink job {job.name!r} must not grant authority (§11)")
    if not job.input_topics or not job.output_topics:
        raise FlinkJobError(f"Flink job {job.name!r} must declare input and output topics")
    if not job.tenant_isolated:
        raise FlinkJobError(f"Flink job {job.name!r} must be tenant-isolated")
    if not job.replay_tests_passed:
        raise FlinkJobError(f"Flink job {job.name!r} has not passed replay tests (§11)")


__all__ = [
    "FlinkResourceLimits",
    "FlinkJobManifest",
    "FlinkJobError",
    "assert_flink_job_valid",
]
