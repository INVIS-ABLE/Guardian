# Guardian authorization policy (Open Policy Agent / Rego).
#
# This is the *declarative* twin of core/guardrails.py. The same gates from
# GUARDRAILS.md are expressed here so they can be evaluated by OPA in CI, in a
# sidecar, or at an API boundary — independently of the Python process. The Python
# guardrails remain the in-process enforcement; this policy is defence-in-depth.
#
# Decision contract:
#   input  = {
#     "action": "...",            # e.g. "code_review", "production_scan"
#     "mode": "...",              # scope mode being requested
#     "scope": {                  # the active scope file (subset)
#        "environment": "staging",
#        "allowed_modes": [...],
#        "blocked_actions": [...],
#        "approval_required": [...]
#     },
#     "approvals": ["production_scan", ...],   # recorded human approvals
#     "target": {"kind": "domain"|"repo", "in_scope": true|false, "owned": true|false}
#   }
#   output = data.guardian.authz.decision  -> {"allow": bool, "deny": [reasons]}
#
# Evaluate:
#   opa eval -d policies/opa -I 'data.guardian.authz.decision' < input.json
package guardian.authz

import future.keywords.in

# Actions that are ALWAYS blocked — mirrors core.guardrails.BLOCKED_ACTIONS.
blocked_actions := {
	"third_party_scan",
	"real_user_data_access",
	"credential_theft",
	"stealth",
	"persistence",
	"exploit_deployment",
	"hack_back",
	"destructive_testing",
}

# Actions that ALWAYS require a recorded human approval —
# mirrors core.guardrails.GLOBAL_APPROVAL_REQUIRED.
global_approval_required := {
	"production_scan",
	"high_volume_test",
	"account_locking_test",
	"data_export_test",
	"admin_permission_test",
	"credential_audit",
}

default allow := false

allow if {
	count(deny) == 0
}

# --- denials (each adds a human-readable reason) ------------------------------

# Globally blocked, or blocked by the scope file.
deny contains msg if {
	input.action in blocked_actions
	msg := sprintf("action '%v' is globally blocked", [input.action])
}

deny contains msg if {
	some a in input.scope.blocked_actions
	a == input.action
	msg := sprintf("action '%v' is blocked by this scope", [input.action])
}

# Mode must be explicitly allowed by the scope (default-deny).
deny contains msg if {
	not mode_allowed
	msg := sprintf("mode '%v' is not in scope.allowed_modes", [input.mode])
}

mode_allowed if {
	some m in input.scope.allowed_modes
	m == input.mode
}

# Production requires an approved production_scan.
deny contains msg if {
	input.scope.environment == "production"
	not "production_scan" in approvals_set
	msg := "production scope requires a recorded 'production_scan' approval"
}

# Approval-gated actions need a recorded approval.
deny contains msg if {
	needs_approval
	not input.action in approvals_set
	msg := sprintf("action '%v' requires a recorded human approval", [input.action])
}

needs_approval if {
	input.action in global_approval_required
}

needs_approval if {
	some a in input.scope.approval_required
	a == input.action
}

approvals_set contains a if {
	some a in input.approvals
}

# Targets must be in-scope AND ownership-verified.
deny contains msg if {
	input.target
	not input.target.in_scope
	msg := sprintf("target %v is not in scope", [input.target])
}

deny contains msg if {
	input.target
	input.target.in_scope
	not input.target.owned
	msg := sprintf("ownership of target %v could not be verified", [input.target])
}

decision := {"allow": allow, "deny": deny}
