"""Confidential Containers (CoCo) + Kata runtime seam (Citadel System 22).

Confidential Containers is the authoritative production runtime for confidential workers; it runs
each worker in a Kata VM with hardware-backed memory encryption and remote attestation. This is the
thin runtime boundary Guardian drives. ``KataConfidentialContainers`` is a deterministic stand-in
that tracks live workers and issues destruction receipts so the verifier path is exercised offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .profiles import WorkerClass


@dataclass(frozen=True)
class WorkerHandle:
    worker_id: str
    worker_class: WorkerClass
    image_digest: str
    launched_at: float


@dataclass(frozen=True)
class DestructionReceipt:
    """Proof a worker was destroyed after its job — ephemeral identity + storage are gone."""

    worker_id: str
    destroyed_at: float
    ephemeral_storage_wiped: bool
    identity_revoked: bool

    @property
    def complete(self) -> bool:
        return self.ephemeral_storage_wiped and self.identity_revoked


class ConfidentialRuntime(Protocol):
    """Launch, attest and destroy confidential workers. Production: CoCo/Kata; tests: the stand-in."""

    def launch(self, image_digest: str, worker_class: WorkerClass, *, at: float) -> WorkerHandle:
        """Launch a confidential worker for the given signed image + class."""

    def is_live(self, worker_id: str) -> bool:
        """Whether the worker is still running."""

    def destroy(self, worker_id: str, *, at: float) -> DestructionReceipt:
        """Tear down the worker and return proof its ephemeral identity + storage are gone."""


class KataConfidentialContainers:
    """Deterministic CoCo/Kata stand-in. Ephemeral by construction: destroy wipes the worker."""

    runtime_name = "confidential-containers/kata"

    def __init__(self) -> None:
        self._live: dict[str, WorkerHandle] = {}
        self._counter = 0

    def launch(self, image_digest: str, worker_class: WorkerClass, *, at: float) -> WorkerHandle:
        self._counter += 1
        handle = WorkerHandle(
            worker_id=f"cw-{self._counter}", worker_class=worker_class,
            image_digest=image_digest, launched_at=at,
        )
        self._live[handle.worker_id] = handle
        return handle

    def is_live(self, worker_id: str) -> bool:
        return worker_id in self._live

    def destroy(self, worker_id: str, *, at: float) -> DestructionReceipt:
        self._live.pop(worker_id, None)   # ephemeral: the worker and its storage are gone
        return DestructionReceipt(
            worker_id=worker_id, destroyed_at=at,
            ephemeral_storage_wiped=True, identity_revoked=True,
        )


__all__ = ["WorkerHandle", "DestructionReceipt", "ConfidentialRuntime", "KataConfidentialContainers"]
