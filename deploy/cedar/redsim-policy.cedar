// Redsim role-gate authorization policy (Cedar).
//
// Replicates the built-in StaticPolicyEngine role-rank table so running
// Redsim with REDSIM_POLICY_ENGINE=cedar is a behaviour-identical drop-in.
//
// The CedarPolicyEngine POSTs an authorization query to
//   {REDSIM_CEDAR_URL}/v1/is_authorized
// shaped as { principal, action, resource, context } and reads back a
// `decision` of "Allow" / "Deny" (plus an optional `reason`).
//
// Cedar evaluates permit/forbid policies over typed entities; the
// equivalent of the role-rank comparison is expressed as one permit per
// (action, sufficient-role) pair. The caller's role for the project must
// be attached to the principal as `principal.role` for the request's
// project (the cedar-agent host resolves this from
// subject.project_memberships[resource.project_id] before evaluation —
// see redsim-entities.md).
//
// Role ranks: viewer(0) < scanner(1) < remediator(2) < approver(3) < admin(4).
// viewer is read-only membership: it appears in no permit below.
// A principal satisfies an action when its role rank >= the action's
// minimum, so each action lists every role at or above its bar.

// --- scanner-min actions: scan.start, attack.run, explain.run,
//     report.export; Phase B (spec 7.4 addendum, 2026-09-09):
//     batch.run, report.render -------------------------------------------
permit (
  principal,
  action in [
    Action::"scan.start", Action::"attack.run", Action::"explain.run",
    Action::"report.export",
    Action::"batch.run", Action::"report.render"
  ],
  resource
) when {
  principal.role == "scanner" || principal.role == "remediator" ||
  principal.role == "approver" || principal.role == "admin"
};

// --- remediator-min actions: verify.replay, run.cancel, model.register,
//     harden.recommend, finding.annotate; Phase B (spec 7.4 addendum,
//     2026-09-09): llm.probe.run, dataset.register, dataset.export
//     (spec 17.4 and 27.4: an export writes a slice other teams read),
//     finding.author -----------------------------------------------------
permit (
  principal,
  action in [
    Action::"verify.replay", Action::"run.cancel", Action::"model.register",
    Action::"harden.recommend", Action::"finding.annotate",
    Action::"llm.probe.run", Action::"dataset.register", Action::"dataset.export",
    Action::"finding.author"
  ],
  resource
) when {
  principal.role == "remediator" || principal.role == "approver" ||
  principal.role == "admin"
};

// --- approver-min actions: finding.review ---------------------------------
// The independence check (reviewer != campaign creator) lives in the
// service layer, not here (spec section 7.7).
permit (
  principal,
  action == Action::"finding.review",
  resource
) when {
  principal.role == "approver" || principal.role == "admin"
};

// --- admin-only actions: target.manage, auth_profile.manage, audit.verify;
//     Phase B (spec 7.4 addendum, 2026-09-09): integration.push, because a
//     push sends data outside the deployment boundary ---------------------
permit (
  principal,
  action in [
    Action::"target.manage", Action::"auth_profile.manage", Action::"audit.verify",
    Action::"integration.push"
  ],
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
