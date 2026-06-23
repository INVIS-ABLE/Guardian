"""WebAssembly extension-plane manifests (directive §28).

Small deterministic extensions (evidence transforms, redactors, validators, scorers) run
under Wasmtime with **explicit capabilities and limits**: a signed digest, declared imports,
no network and no filesystem by default, and memory/fuel/timeout/output ceilings. Wasm must
never be the *only* security boundary for high-risk scanners — those use gVisor/disposable
VMs — so a manifest cannot mark itself high-risk-isolation.

Typed manifest + fail-closed validator (acceptance #34).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class WasmModuleManifest(BaseModel):
    """A signed, capability-limited Wasm extension (§28)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")  # signed digest
    declared_imports: tuple[str, ...] = ()
    allow_network: bool = False     # no network by default
    allow_filesystem: bool = False  # no filesystem by default
    memory_limit_bytes: int = Field(gt=0)
    fuel_limit: int = Field(gt=0)
    timeout_ms: int = Field(gt=0)
    output_limit_bytes: int = Field(gt=0)
    input_schema_ref: str = Field(min_length=1)
    output_schema_ref: str = Field(min_length=1)
    high_risk_scanner: bool = False  # must be False — Wasm is not that boundary


# Imports a deterministic extension is allowed to declare. Anything else is refused.
_ALLOWED_IMPORTS: frozenset[str] = frozenset(
    {"log", "clock", "random_seed", "schema_validate", "redact", "score"}
)


class WasmExtensionError(RuntimeError):
    """Raised when a Wasm manifest exceeds the extension plane's limits. Fail closed."""


def assert_wasm_safe(module: WasmModuleManifest) -> None:
    """A module is loadable only within explicit capabilities and limits (§28)."""
    if module.high_risk_scanner:
        raise WasmExtensionError(
            f"module {module.name!r} marked high-risk-scanner — use gVisor/VM, not Wasm (§28)"
        )
    unknown = sorted(set(module.declared_imports) - _ALLOWED_IMPORTS)
    if unknown:
        raise WasmExtensionError(f"module {module.name!r} declares unknown imports: {unknown}")
    if module.allow_network:
        raise WasmExtensionError(
            f"module {module.name!r} requests network — extensions have no network by default (§28)"
        )
    if module.allow_filesystem:
        raise WasmExtensionError(
            f"module {module.name!r} requests filesystem — extensions have none by default (§28)"
        )


__all__ = [
    "WasmModuleManifest",
    "WasmExtensionError",
    "assert_wasm_safe",
]
