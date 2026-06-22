"""Guardian workload isolation & egress control (Phase 3 / blueprint areas 6, 7, 8).

Scanners and repository processing run heavily sandboxed (non-root, read-only root, all caps
dropped, no host namespaces, no Docker socket, resource + runtime limits, gVisor for high-risk
jobs) behind a default-deny egress policy. These in-process checks gate a workload before it
starts; Cilium/Tetragon/gVisor enforce the same posture at the kernel/network layer in
deployment.
"""

from __future__ import annotations

from .egress import EgressDecision, EgressPolicy, METADATA_IPS
from .sandbox import (
    Mount,
    RunSpec,
    SandboxProfile,
    assert_sandboxed,
    validate_runspec,
)
from .security_context import (
    GVISOR_RUNTIME_CLASS,
    docker_run_args,
    gvisor_pod_overlay,
    restricted_security_context,
)

__all__ = [
    "SandboxProfile",
    "RunSpec",
    "Mount",
    "validate_runspec",
    "assert_sandboxed",
    "EgressPolicy",
    "EgressDecision",
    "METADATA_IPS",
    "restricted_security_context",
    "docker_run_args",
    "gvisor_pod_overlay",
    "GVISOR_RUNTIME_CLASS",
]
