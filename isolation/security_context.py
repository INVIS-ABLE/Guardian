"""Hardened security-context generators (Phase 3).

Produces a Kubernetes "restricted" Pod Security context and equivalent `docker run` args, plus
the gVisor runtime class for high-risk jobs. These emit the posture that `validate_runspec`
checks, so the generator and the validator agree.
"""

from __future__ import annotations

from typing import Any

GVISOR_RUNTIME_CLASS = "gvisor"  # RuntimeClass mapped to runsc
NOBODY_UID = 65534


def restricted_security_context(uid: int = NOBODY_UID) -> dict[str, Any]:
    """Kubernetes container securityContext meeting the 'restricted' Pod Security Standard."""
    return {
        "runAsNonRoot": True,
        "runAsUser": uid,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "privileged": False,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def docker_run_args(
    image: str,
    *,
    memory_mb: int = 2048,
    pids_limit: int = 256,
    cpus: float = 1.0,
    network: str = "none",
    uid: int = NOBODY_UID,
) -> list[str]:
    """A hardened `docker run` argument list (read-only, no caps, no new privs, tmpfs)."""
    return [
        "run", "--rm",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", f"{uid}:{uid}",
        "--network", network,                 # "none" or a controlled egress network
        "--pids-limit", str(pids_limit),
        "--memory", f"{memory_mb}m",
        "--cpus", str(cpus),
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
        "--mount", "type=bind,source=/workspace/input,target=/input,readonly",
        "--mount", "type=tmpfs,target=/output",
        image,
    ]


def gvisor_pod_overlay() -> dict[str, Any]:
    """Pod spec fragment selecting the gVisor runtime for high-risk workloads."""
    return {"runtimeClassName": GVISOR_RUNTIME_CLASS}
