"""Execution job + artifact reference schemas (Final Power-Up §19).

A sealed ``ExecutionJob`` is the unit the router hands to the execution service: it names
the tool, the resolved capability, validated arguments, the input artifacts, the
isolation profile, the credentials to broker, the targets, a timeout and a trace id.
It carries no secrets — only references — so it is safe to log and to checkpoint.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


class ArtifactRef(BaseModel):
    """A content-addressable reference to an input/output artifact (never inline bytes)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(min_length=1)
    media_type: str = "application/octet-stream"
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, default=0)
    storage_uri: str = ""


class ExecutionJob(BaseModel):
    """A sealed, secret-free description of one tool execution (master map §19)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    job_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    tool_id: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    input_artifacts: tuple[ArtifactRef, ...] = ()
    execution_profile: str = "scanner-standard"
    credential_refs: tuple[str, ...] = ()
    target_refs: tuple[str, ...] = ()
    timeout_seconds: int = Field(ge=1, le=86_400, default=900)
    trace_id: str = ""


__all__ = ["ExecutionJob", "ArtifactRef", "SCHEMA_VERSION"]
