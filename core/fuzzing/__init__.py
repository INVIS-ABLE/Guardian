"""Guardian continuous fuzzing farm (Sovereign plane, Wave 3, system #14).

CI fuzzing of the security-critical parsers (crypto envelopes, attachments, tokens, evidence
formats) so Guardian finds the crash in the lab before an attacker finds it in production. The
``FuzzFarm`` dedupes crashes by signature and mints a regression seed for every unique one, so a
bug can never silently return (docs/sovereign_ops_plane.md; upstream: ClusterFuzzLite).

Metadata-only: crash inputs are referenced by hash, never inlined, so a malicious corpus entry
never becomes content the model ingests.
"""

from __future__ import annotations

from .farm import FuzzError, FuzzFarm
from .ingest import (
    build_from_spec,
    from_clusterfuzz,
    load_campaign,
    production_source_required,
)
from .models import (
    CrashKind,
    CrashObservation,
    FuzzReport,
    FuzzTarget,
    RegressionSeed,
    Severity,
    UniqueCrash,
)

__all__ = [
    "FuzzFarm",
    "FuzzError",
    "CrashKind",
    "Severity",
    "FuzzTarget",
    "CrashObservation",
    "UniqueCrash",
    "RegressionSeed",
    "FuzzReport",
    "build_from_spec",
    "load_campaign",
    "from_clusterfuzz",
    "production_source_required",
]
