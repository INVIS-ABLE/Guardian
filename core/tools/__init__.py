"""Versioned, signed tool-manifest gateway (target architecture §13).

Replaces the hard-coded capability→tool-name map (``core.router.CAPABILITY_MAP``) with
signed, pinned manifests, one-use capability tokens, and a bounded executor that refuses
unknown capabilities with a structured result instead of an exception.
"""

from __future__ import annotations

from .capability import CapabilityToken, TokenStore, hash_args, issue_token
from .executor import DryRunRunner, RunOutput, ToolExecution, ToolExecutor, ToolRunner
from .manifest import (
    FilesystemPolicy,
    FsAccess,
    NetworkMode,
    ResourceLimits,
    SignedManifest,
    ToolManifest,
    require_signed_manifests,
    sign_manifest,
)
from .registry import RefusalReason, ToolRefusal, ToolRegistry, default_registry

__all__ = [
    "ToolManifest",
    "SignedManifest",
    "sign_manifest",
    "require_signed_manifests",
    "NetworkMode",
    "FsAccess",
    "FilesystemPolicy",
    "ResourceLimits",
    "CapabilityToken",
    "issue_token",
    "TokenStore",
    "hash_args",
    "ToolRegistry",
    "default_registry",
    "ToolRefusal",
    "RefusalReason",
    "ToolExecutor",
    "ToolExecution",
    "ToolRunner",
    "DryRunRunner",
    "RunOutput",
]
