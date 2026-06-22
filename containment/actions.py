"""Reversible containment action catalogue (blueprint area 21 / Phase 6).

Automatic containment is restricted to a fixed allowlist of **pre-approved, reversible**
operations. Each action carries the controls the blueprint requires: a confidence threshold,
a maximum blast radius, a default TTL (containment auto-expires), whether a human must approve,
and a documented rollback procedure. An action not in this catalogue can never be executed —
there is no free-form / AI-generated containment command path.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ContainmentAction:
    name: str
    reversible: bool
    default_ttl_seconds: int  # containment auto-expires; this is the cap
    max_blast_radius: int  # max distinct entities one order may affect
    min_confidence: float  # 0..1 detection confidence required to act
    requires_human_approval: bool
    rollback_procedure: str


# The pre-approved, reversible operations (blueprint area 21). High-blast-radius actions
# (isolating a pod, freezing a deployment) require human approval even when automated.
REVERSIBLE_ACTIONS: dict[str, ContainmentAction] = {
    a.name: a
    for a in (
        ContainmentAction("revoke_token", True, 0, 1, 0.6, False,
                          "re-issue a fresh short-lived token after re-verification"),
        ContainmentAction("disable_service_account", True, 3600, 1, 0.75, False,
                          "re-enable the service account once cleared"),
        ContainmentAction("isolate_pod", True, 1800, 1, 0.8, True,
                          "remove the network isolation label to rejoin the mesh"),
        ContainmentAction("remove_workload_from_service", True, 1800, 1, 0.75, False,
                          "re-add the workload to the service endpoints"),
        ContainmentAction("block_indicator_temporarily", True, 3600, 1, 0.7, False,
                          "remove the indicator from the temporary blocklist on expiry"),
        ContainmentAction("disable_feature_flag", True, 3600, 1, 0.6, False,
                          "re-enable the feature flag"),
        ContainmentAction("pause_workflow", True, 3600, 1, 0.6, False,
                          "resume the paused workflow"),
        ContainmentAction("quarantine_image_digest", True, 86400, 1, 0.8, False,
                          "release the image digest from quarantine after re-scan"),
        ContainmentAction("freeze_deployment", True, 3600, 1, 0.85, True,
                          "unfreeze the deployment pipeline"),
        ContainmentAction("force_reauthentication", True, 0, 100, 0.5, False,
                          "no rollback needed; users simply re-authenticate"),
    )
}


def is_reversible_action(name: str) -> bool:
    return name in REVERSIBLE_ACTIONS
