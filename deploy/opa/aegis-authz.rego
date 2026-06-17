# Aegis role-gate authorization policy (OPA / Rego).
#
# This replicates the built-in StaticPolicyEngine role-rank table so that
# running Aegis with AEGIS_POLICY_ENGINE=opa is a behaviour-identical
# drop-in. The OPAPolicyEngine POSTs {"input": {...}} to
#   /v1/data/aegis/authz
# and reads `result.allow` (bool) plus optional `result.reason`.
#
# Load it locally with:
#   opa run -s deploy/opa/
# then point Aegis at it:
#   export AEGIS_POLICY_ENGINE=opa
#   export AEGIS_OPA_URL=http://localhost:8181
#   export AEGIS_OPA_PATH=/v1/data/aegis/authz   # default
#
# The query input document looks like:
#   {
#     "input": {
#       "subject": {
#         "sub": "...", "email": "...", "is_system": false,
#         "project_memberships": {"<project_id>": "<role>"}
#       },
#       "action": "fix.apply",
#       "resource": {"project_id": "<project_id>"},
#       "context": {}
#     }
#   }

package aegis.authz

import rego.v1

# Lower-to-higher privilege ranks (mirror aegis.api.policy._ROLE_RANK).
role_rank := {
	"scanner": 1,
	"remediator": 2,
	"approver": 3,
	"admin": 4,
}

# Minimum role per action (mirror aegis.api.policy._ACTION_MIN_ROLE).
action_min_role := {
	"scan.start": "scanner",
	"agent.run": "remediator",
	"agent.execute": "approver",
	"fix.generate": "remediator",
	"fix.apply": "approver",
	"verify.replay": "remediator",
	"target.manage": "admin",
	"audit.verify": "admin",
	"run.cancel": "remediator",
	"tool.invoke": "remediator",
}

default allow := false

# System principals (worker service accounts) bypass the role gate.
allow if {
	input.subject.is_system == true
}

# A member whose role rank meets the action's minimum is allowed.
allow if {
	not input.subject.is_system
	role := input.subject.project_memberships[input.resource.project_id]
	required := action_min_role[input.action]
	role_rank[role] >= role_rank[required]
}

# --- reason (human-readable deny explanation) ------------------------------

# No reason on an allow.
reason := "" if allow

# No membership on the project at all.
reason := sprintf("user %s has no membership on project %s", [
	input.subject.email,
	input.resource.project_id,
]) if {
	not allow
	not input.subject.project_memberships[input.resource.project_id]
}

# Has a membership, but the role rank is too low for the action.
reason := sprintf("role '%s' cannot perform '%s' on project %s", [
	role,
	input.action,
	input.resource.project_id,
]) if {
	not allow
	role := input.subject.project_memberships[input.resource.project_id]
}
