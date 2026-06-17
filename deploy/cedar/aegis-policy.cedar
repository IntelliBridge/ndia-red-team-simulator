// Aegis role-gate authorization policy (Cedar).
//
// Replicates the built-in StaticPolicyEngine role-rank table so running
// Aegis with AEGIS_POLICY_ENGINE=cedar is a behaviour-identical drop-in.
//
// The CedarPolicyEngine POSTs an authorization query to
//   {AEGIS_CEDAR_URL}/v1/is_authorized
// shaped as { principal, action, resource, context } and reads back a
// `decision` of "Allow" / "Deny" (plus an optional `reason`).
//
// Cedar evaluates permit/forbid policies over typed entities; the
// equivalent of the role-rank comparison is expressed as one permit per
// (action, sufficient-role) pair. The caller's role for the project must
// be attached to the principal as `principal.role` for the request's
// project (the cedar-agent host resolves this from
// subject.project_memberships[resource.project_id] before evaluation —
// see aegis-entities.md).
//
// Role ranks: scanner(1) < remediator(2) < approver(3) < admin(4).
// A principal satisfies an action when its role rank >= the action's
// minimum, so each action lists every role at or above its bar.

// --- scan.start : minimum scanner -----------------------------------------
permit (
  principal,
  action == Action::"scan.start",
  resource
) when {
  principal.role == "scanner" || principal.role == "remediator" ||
  principal.role == "approver" || principal.role == "admin"
};

// --- remediator-min actions: agent.run, fix.generate, verify.replay,
//     run.cancel, tool.invoke --------------------------------------------
permit (
  principal,
  action in [
    Action::"agent.run", Action::"fix.generate", Action::"verify.replay",
    Action::"run.cancel", Action::"tool.invoke"
  ],
  resource
) when {
  principal.role == "remediator" || principal.role == "approver" ||
  principal.role == "admin"
};

// --- approver-min actions: agent.execute, fix.apply -----------------------
permit (
  principal,
  action in [Action::"agent.execute", Action::"fix.apply"],
  resource
) when {
  principal.role == "approver" || principal.role == "admin"
};

// --- admin-only actions: target.manage, audit.verify ----------------------
permit (
  principal,
  action in [Action::"target.manage", Action::"audit.verify"],
  resource
) when {
  principal.role == "admin"
};

// --- system principals bypass the role gate -------------------------------
// Worker service accounts authenticate as is_system=true; grant them all
// actions regardless of project membership.
permit (
  principal,
  action,
  resource
) when {
  principal.is_system == true
};
