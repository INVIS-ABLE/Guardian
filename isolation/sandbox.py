"""Workload sandbox profile + run-spec validation (Phase 3 / blueprint areas 6, 8).

Every scanner / repository-processing job must run heavily isolated. This module defines the
required `SandboxProfile` and validates a `RunSpec` against it BEFORE the workload is started,
so a misconfigured job (privileged, host namespaces, the Docker socket, a writable root
filesystem, running as root, missing limits, …) is refused. gVisor (`runsc`) is the runtime
for high-risk jobs; Cilium/Tetragon enforce networking at runtime in deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DOCKER_SOCKET_MARKERS = ("/var/run/docker.sock", "/run/docker.sock", "docker.sock")


@dataclass(frozen=True)
class SandboxProfile:
    """The required isolation posture. Defaults are the strict baseline; high-risk jobs add gVisor."""

    require_non_root: bool = True
    require_read_only_root: bool = True
    require_drop_all_caps: bool = True
    require_no_new_privileges: bool = True
    require_seccomp: bool = True
    forbid_privileged: bool = True
    forbid_host_namespaces: bool = True  # host PID/IPC/network
    forbid_host_path_mounts: bool = True
    forbid_docker_socket: bool = True
    require_resource_limits: bool = True  # cpu + memory + pids
    require_max_runtime: bool = True
    require_egress_policy: bool = True  # default-deny egress must be attached
    require_read_only_input: bool = True
    require_gvisor: bool = False  # set True for untrusted/high-risk repo processing


@dataclass
class Mount:
    source: str
    target: str
    read_only: bool = False
    host_path: bool = False  # True if the source is a host path (vs a managed volume/tmpfs)

    def is_docker_socket(self) -> bool:
        s = (self.source or "").lower()
        t = (self.target or "").lower()
        return any(m in s or m in t for m in DOCKER_SOCKET_MARKERS)


@dataclass
class RunSpec:
    """A proposed workload. Validated against a SandboxProfile before it may run."""

    image: str
    run_as_non_root: bool = False
    read_only_root_fs: bool = False
    dropped_capabilities: list[str] = field(default_factory=list)  # e.g. ["ALL"]
    added_capabilities: list[str] = field(default_factory=list)
    no_new_privileges: bool = False
    seccomp_profile: str | None = None  # e.g. "RuntimeDefault" or a path
    privileged: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    host_network: bool = False
    mounts: list[Mount] = field(default_factory=list)
    cpu_limit: float | None = None
    memory_limit_mb: int | None = None
    pids_limit: int | None = None
    max_runtime_seconds: int | None = None
    runtime_class: str | None = None  # "gvisor"/"runsc" for high-risk
    has_egress_policy: bool = False


def validate_runspec(spec: RunSpec, profile: SandboxProfile | None = None) -> list[str]:
    """Return a list of violations ([] means the spec satisfies the profile)."""
    p = profile or SandboxProfile()
    v: list[str] = []

    if p.forbid_privileged and spec.privileged:
        v.append("privileged containers are forbidden")
    if p.forbid_host_namespaces and (spec.host_pid or spec.host_ipc or spec.host_network):
        v.append("host PID/IPC/network namespaces are forbidden")
    if p.require_non_root and not spec.run_as_non_root:
        v.append("must run as a non-root user")
    if p.require_read_only_root and not spec.read_only_root_fs:
        v.append("root filesystem must be read-only")
    if p.require_no_new_privileges and not spec.no_new_privileges:
        v.append("no_new_privileges must be set")
    if p.require_seccomp and not spec.seccomp_profile:
        v.append("a seccomp profile is required")
    if p.require_drop_all_caps and "ALL" not in {c.upper() for c in spec.dropped_capabilities}:
        v.append("all Linux capabilities must be dropped (drop: ALL)")
    if spec.added_capabilities:
        v.append(f"no capabilities may be added (got {spec.added_capabilities})")
    if p.forbid_docker_socket and any(m.is_docker_socket() for m in spec.mounts):
        v.append("the Docker socket must never be mounted")
    if p.forbid_host_path_mounts and any(m.host_path for m in spec.mounts):
        v.append("host-path mounts are forbidden (use managed volumes/tmpfs)")
    if p.require_read_only_input and any(
        not m.read_only for m in spec.mounts if "/input" in (m.target or "")
    ):
        v.append("input mounts must be read-only")
    if p.require_resource_limits and not (
        spec.cpu_limit and spec.memory_limit_mb and spec.pids_limit
    ):
        v.append("cpu, memory and pids limits are required")
    if p.require_max_runtime and not spec.max_runtime_seconds:
        v.append("a maximum runtime must be set")
    if p.require_egress_policy and not spec.has_egress_policy:
        v.append("a default-deny egress policy must be attached")
    if p.require_gvisor and (spec.runtime_class or "").lower() not in ("gvisor", "runsc"):
        v.append("high-risk workloads must use the gVisor (runsc) runtime")
    return v


def assert_sandboxed(spec: RunSpec, profile: SandboxProfile | None = None) -> None:
    """Raise PermissionError if the spec is not adequately isolated (fail closed)."""
    violations = validate_runspec(spec, profile)
    if violations:
        raise PermissionError("workload not adequately isolated: " + "; ".join(violations))
