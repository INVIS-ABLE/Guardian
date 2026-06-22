# Phase 3 — Workload Isolation & Egress Control

Blueprint areas 6 (workload isolation), 7 (outbound control), 8 (sandbox). A scanner or
repository-processing job runs heavily isolated behind a default-deny egress policy, and a
proposed workload is **validated before it starts**. gVisor/Cilium/Tetragon enforce the same
posture at the kernel/network layer in deployment; `isolation/` is the in-process gate.

## Sandbox profile (`isolation/sandbox.py`)

`validate_runspec(spec, profile)` refuses a workload unless it is:

- **non-root**, **read-only root filesystem**, **all Linux capabilities dropped**, **no added
  caps**, **`no_new_privileges`**, **seccomp** profile set;
- **not privileged**, **no host PID/IPC/network** namespaces;
- **no Docker socket** mount, **no host-path** mounts, **input mounts read-only**;
- bounded by **CPU + memory + PID limits** and a **maximum runtime**;
- attached to a **default-deny egress policy**;
- on the **gVisor (runsc)** runtime for high-risk jobs.

`assert_sandboxed()` fails closed (raises) on any violation. Tested: a hardened spec passes;
each individual weakening (privileged, host network, root, writable root, missing seccomp,
added caps, Docker socket, host path, missing limits/runtime/egress, missing gVisor) is caught.

## Default-deny egress (`isolation/egress.py`)

`EgressPolicy` is **default-deny** with an explicit host/CIDR allowlist and **always blocks**:

- the cloud **metadata** endpoint (`169.254.169.254` / `fd00:ec2::254`),
- **loopback**, **link-local**, **multicast**, **reserved**, and **private** ranges (unless a
  job legitimately needs an internal endpoint, `allow_private=True`).

Destinations are checked as resolved IPs, so DNS-rebinding cannot smuggle a blocked address
past the allowlist (resolve immediately before connect, check the IP). This is the control
that stops *"instructions in a malicious document → outbound exfiltration request."*

## Hardened security contexts (`isolation/security_context.py`)

`restricted_security_context()` emits a Kubernetes "restricted" Pod Security context;
`docker_run_args()` emits the equivalent `docker run` flags (`--read-only --cap-drop ALL
--security-opt no-new-privileges --user 65534 --network none --pids-limit --memory --tmpfs`,
read-only input bind, tmpfs output); `gvisor_pod_overlay()` selects the gVisor runtime. The
generator and the validator agree, so generated specs pass `validate_runspec`.

## Maps to the bulletproof tests

- **#2 a compromised connector cannot reach an unapproved destination** — default-deny egress
  + metadata/private blocking (foundation; Cilium gateway enforces at the network layer).
- **Isolation acceptance row** — scanners sandboxed, rootless, read-only input, ephemeral
  output, explicit egress allowlist, destroyed after each job.

## Deployment wiring

gVisor `RuntimeClass`, Cilium network policies, Tetragon runtime enforcement, and the
authenticated egress gateway are added per `docs/architecture/components.yaml`
(`execution_isolation`, `network_policy`, `runtime_enforcement`). The validator runs in CI/the
Brain to reject any workload spec that drifts from this posture.
