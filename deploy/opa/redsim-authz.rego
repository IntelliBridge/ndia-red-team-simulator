# Redsim role-gate authorization policy (OPA / Rego).
#
# This replicates the built-in StaticPolicyEngine role-rank table so that
# running Redsim with REDSIM_POLICY_ENGINE=opa is a behaviour-identical
# drop-in. The OPAPolicyEngine POSTs {"input": {...}} to
#   /v1/data/redsim/authz
# and reads `result.allow` (bool) plus optional `result.reason`.
#
# Load it locally with:
#   opa run -s deploy/opa/
# then point Redsim at it:
#   export REDSIM_POLICY_ENGINE=opa
#   export REDSIM_OPA_URL=http://localhost:8181
#   export REDSIM_OPA_PATH=/v1/data/redsim/authz   # default
#
# The query input document looks like:
#   {
#     "input": {
#       "subject": {
#         "sub": "...", "email": "...", "is_system": false,
#         "project_memberships": {"<project_id>": "<role>"}
#       },
#       "action": "attack.run",
#       "resource": {"project_id": "<project_id>"},
#       "context": {}
#     }
#   }

package redsim.authz

import rego.v1

# Lower-to-higher privilege ranks (mirror redsim.api.policy._ROLE_RANK).
# viewer ranks 0: read-only membership, fails every gated action.
role_rank := {
	"viewer": 0,
	"scanner": 1,
	"remediator": 2,
	"approver": 3,
	"admin": 4,
}

# Minimum role per action (mirror redsim.api.policy._ACTION_MIN_ROLE).
action_min_role := {
	"scan.start": "scanner",
	"verify.replay": "remediator",
	"target.manage": "admin",
	"auth_profile.manage": "admin",
	"audit.verify": "admin",
	"run.cancel": "remediator",
	"model.register": "remediator",
	"attack.run": "scanner",
	"explain.run": "scanner",
	"harden.recommend": "remediator",
	"finding.review": "approver",
	"finding.annotate": "remediator",
	"report.export": "scanner",
	# Phase B (spec 7.4 addendum, 2026-09-09).
	"llm.probe.run": "remediator",
	"dataset.register": "remediator",
	"dataset.export": "scanner",
	"integration.push": "admin",
	"batch.run": "scanner",
	"report.render": "scanner",
	"finding.author": "remediator",
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
