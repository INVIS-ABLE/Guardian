"""Enarx specialist adapter (Citadel System 22).

Enarx runs WebAssembly workloads inside a TEE (SGX or SEV) with attestation. Like Gramine, it is a
*specialist adapter* — an alternative to the authoritative Confidential Containers owner — for
WASM-packaged confidential workloads. Deterministic stand-in; the contract matches
``ConfidentialRuntime``.
"""

from __future__ import annotations

from .confidential_containers import DestructionReceipt, WorkerHandle
from .profiles import WorkerClass


class EnarxKeep:
    """Enarx 'Keep' confidential runtime stand-in (specialist adapter, not the primary owner)."""

    runtime_name = "enarx/enarx"

    def __init__(self) -> None:
        self._live: dict[str, WorkerHandle] = {}
        self._counter = 0

    def launch(self, image_digest: str, worker_class: WorkerClass, *, at: float) -> WorkerHandle:
        self._counter += 1
        handle = WorkerHandle(
            worker_id=f"kp-{self._counter}", worker_class=worker_class,
            image_digest=image_digest, launched_at=at,
        )
        self._live[handle.worker_id] = handle
        return handle

    def is_live(self, worker_id: str) -> bool:
        return worker_id in self._live

    def destroy(self, worker_id: str, *, at: float) -> DestructionReceipt:
        self._live.pop(worker_id, None)
        return DestructionReceipt(
            worker_id=worker_id, destroyed_at=at,
            ephemeral_storage_wiped=True, identity_revoked=True,
        )


__all__ = ["EnarxKeep"]
