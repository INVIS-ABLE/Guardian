"""Phase 3 — workload isolation + default-deny egress."""

from __future__ import annotations

import pytest

from isolation import (
    EgressPolicy,
    Mount,
    RunSpec,
    SandboxProfile,
    assert_sandboxed,
    docker_run_args,
    restricted_security_context,
    validate_runspec,
)


def _hardened_spec(**over) -> RunSpec:
    base = dict(
        image="scanner@sha256:abc",
        run_as_non_root=True,
        read_only_root_fs=True,
        dropped_capabilities=["ALL"],
        no_new_privileges=True,
        seccomp_profile="RuntimeDefault",
        cpu_limit=1.0,
        memory_limit_mb=2048,
        pids_limit=256,
        max_runtime_seconds=900,
        has_egress_policy=True,
        mounts=[Mount(source="vol-in", target="/input", read_only=True)],
    )
    base.update(over)
    return RunSpec(**base)


def test_hardened_spec_passes():
    assert validate_runspec(_hardened_spec()) == []
    assert_sandboxed(_hardened_spec())  # does not raise


@pytest.mark.parametrize(
    "override,needle",
    [
        ({"privileged": True}, "privileged"),
        ({"host_network": True}, "host PID/IPC/network"),
        ({"run_as_non_root": False}, "non-root"),
        ({"read_only_root_fs": False}, "read-only"),
        ({"no_new_privileges": False}, "no_new_privileges"),
        ({"seccomp_profile": None}, "seccomp"),
        ({"dropped_capabilities": []}, "capabilities must be dropped"),
        ({"added_capabilities": ["NET_ADMIN"]}, "no capabilities may be added"),
        ({"cpu_limit": None}, "limits are required"),
        ({"max_runtime_seconds": None}, "maximum runtime"),
        ({"has_egress_policy": False}, "egress"),
    ],
)
def test_each_violation_detected(override, needle):
    violations = validate_runspec(_hardened_spec(**override))
    assert any(needle in v for v in violations), violations


def test_docker_socket_mount_forbidden():
    spec = _hardened_spec(
        mounts=[Mount(source="/var/run/docker.sock", target="/var/run/docker.sock")]
    )
    assert any("Docker socket" in v for v in validate_runspec(spec))


def test_host_path_mount_forbidden():
    spec = _hardened_spec(mounts=[Mount(source="/etc", target="/host-etc", host_path=True)])
    assert any("host-path" in v for v in validate_runspec(spec))


def test_gvisor_required_for_high_risk():
    profile = SandboxProfile(require_gvisor=True)
    assert any("gVisor" in v for v in validate_runspec(_hardened_spec(), profile))
    ok = _hardened_spec(runtime_class="gvisor")
    assert validate_runspec(ok, profile) == []


def test_assert_sandboxed_raises_on_bad_spec():
    with pytest.raises(PermissionError):
        assert_sandboxed(_hardened_spec(privileged=True))


# ----------------------------------------------------------------------------- egress
def test_egress_default_deny():
    pol = EgressPolicy()
    assert pol.allows("evil.example.com") is False
    assert pol.allows("8.8.8.8") is False


def test_egress_blocks_metadata_and_private_and_loopback():
    pol = EgressPolicy(allow_private=False)
    assert pol.decide("169.254.169.254").reason.startswith("blocked")
    assert pol.decide("10.0.0.5").reason.startswith("blocked")
    assert pol.decide("127.0.0.1").reason.startswith("blocked")
    assert pol.decide("169.254.10.10").reason.startswith("blocked")  # link-local


def test_egress_allowlist_host_and_cidr():
    pol = EgressPolicy(allowed_hosts={"api.github.com"}, allowed_cidrs=["140.82.112.0/20"])
    assert pol.allows("api.github.com") is True
    assert pol.allows("140.82.112.3") is True
    assert pol.allows("1.2.3.4") is False


def test_security_context_is_restricted():
    ctx = restricted_security_context()
    assert ctx["runAsNonRoot"] and ctx["readOnlyRootFilesystem"]
    assert ctx["allowPrivilegeEscalation"] is False
    assert ctx["capabilities"]["drop"] == ["ALL"]
    args = docker_run_args("scanner@sha256:abc")
    assert "--read-only" in args and "--cap-drop" in args and "no-new-privileges" in args
