# Guardian central authorization policy.
#
# This is the external authority (OPA / conftest) and mirrors core/policy_gate.py exactly.
# Default deny. There is NO allow_production flag — production needs two distinct, unexpired
# reviewers who approved production_scan.
package guardian.authz

import future.keywords.in

blocked_actions := {
	"third_party_scan", "real_user_data_access", "credential_theft", "stealth",
	"persistence", "exploit_deployment", "hack_back", "destructive_testing",
}

global_approval_required := {
	"production_scan", "high_volume_test", "account_locking_test",
	"data_export_test", "admin_permission_test", "credential_audit",
}

production_min_reviewers := 2

# ---- valid (unexpired) approvals ------------------------------------------------
valid_approval(a) if {
	a.expires_at == null
}

valid_approval(a) if {
	a.expires_at != null
	input.now < a.expires_at
}

valid_approvals_for(action) := {a |
	some a in input.approvals
	a.action == action
	valid_approval(a)
}

# ---- deny rules (mirror of the embedded evaluator) ------------------------------
deny contains msg if {
	input.action in blocked_actions
	msg := sprintf("blocked_action:%s", [input.action])
}

deny contains msg if {
	input.action in {x | some x in input.blocked_actions}
	msg := sprintf("blocked_action:%s", [input.action])
}

deny contains msg if {
	not input.mode in {m | some m in input.allowed_modes}
	msg := sprintf("mode_not_allowed:%s", [input.mode])
}

deny contains "ownership_unverified" if {
	has_target
	not input.ownership_verified
}

has_target if input.domain != null
has_target if input.repo != null

deny contains msg if {
	input.test_account != null
	not input.test_account in {t | some t in input.allowed_test_accounts}
	msg := sprintf("non_test_account:%s", [input.test_account])
}

deny contains msg if {
	gated
	count(valid_approvals_for(input.action)) == 0
	msg := sprintf("missing_approval:%s", [input.action])
}

gated if input.action in global_approval_required
gated if input.action in {x | some x in input.approval_required}

deny contains msg if {
	input.environment == "production"
	approvers := {a.approver | some a in valid_approvals_for("production_scan")}
	count(approvers) < production_min_reviewers
	msg := sprintf("insufficient_production_approvals:%d/%d", [count(approvers), production_min_reviewers])
}

# ---- decision -------------------------------------------------------------------
default allow := false

allow if count(deny) == 0

decision := {"allow": allow, "denies": [m | some m in deny]}
