"""Transparency log — append-only Merkle log with inclusion + consistency proofs (Citadel System 29).

A release artefact is promotable only when it has a verifiable **inclusion proof** in the
transparency log, and the log's growth is checked with **consistency proofs** so history cannot be
rewritten. A second, independent log is gossiped for cross-checking; disagreement is a critical
event (Wave-20 invariant 28: a missing inclusion proof denies promotion).

RFC 6962-style hashing (domain-separated leaf/node hashes). Pure-Python and deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def _leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])   # odd node promoted
        level = nxt
    return level[0]


@dataclass(frozen=True)
class InclusionProof:
    index: int
    size: int
    leaf_hash: str
    audit_path: tuple[str, ...]


@dataclass(frozen=True)
class Checkpoint:
    size: int
    root: str


@dataclass
class TransparencyLog:
    """Append-only Merkle log. Entries are opaque bytes (e.g. an artefact digest + provenance)."""

    name: str = "rekor"
    _leaves: list[bytes] = field(default_factory=list)

    def append(self, entry: bytes) -> int:
        self._leaves.append(_leaf_hash(entry))
        return len(self._leaves) - 1

    @property
    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> str:
        return _merkle_root(self._leaves).hex()

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(size=self.size, root=self.root())

    def inclusion_proof(self, index: int) -> InclusionProof:
        if not 0 <= index < self.size:
            raise IndexError(index)
        path: list[str] = []
        level = list(self._leaves)
        idx = index
        while len(level) > 1:
            nxt: list[bytes] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    if i == idx or i + 1 == idx:
                        sibling = level[i + 1] if i == idx else level[i]
                        path.append(sibling.hex())
                    nxt.append(_node_hash(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])
            idx //= 2
            level = nxt
        return InclusionProof(index=index, size=self.size,
                              leaf_hash=self._leaves[index].hex(), audit_path=tuple(path))


def verify_inclusion(proof: InclusionProof, root: str) -> bool:
    """Recompute the root from the leaf + audit path; it must equal the claimed root."""
    h = bytes.fromhex(proof.leaf_hash)
    idx, size = proof.index, proof.size
    for sib_hex in proof.audit_path:
        sib = bytes.fromhex(sib_hex)
        if idx % 2 == 0 and idx + 1 < size:
            h = _node_hash(h, sib)
        else:
            h = _node_hash(sib, h)
        idx //= 2
        size = (size + 1) // 2
    return h.hex() == root


def consistent(old: Checkpoint, new: Checkpoint, log: TransparencyLog) -> bool:
    """Append-only check: the old root must reappear as the root over the first ``old.size`` leaves
    of the current log. (Simplified consistency proof over the same log instance.)"""
    if new.size < old.size or new.root != log.root() or new.size != log.size:
        return False
    prefix_root = _merkle_root(log._leaves[: old.size]).hex()
    return prefix_root == old.root


__all__ = [
    "InclusionProof", "Checkpoint", "TransparencyLog", "verify_inclusion", "consistent",
]
