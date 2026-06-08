"""`aegis fix` — thin CLI shell over ``services.fixes.generate_fix``."""

from __future__ import annotations

import sys

from aegis.cli import _console, _runstate
from aegis.schema import AegisFinding


def _cmd_fix_api(args, _config):
    from aegis.cli import api_client

    client = api_client.build_client()
    try:
        result = client.fix(
            finding_id=args.finding_id,
            strategy=("deps" if args.deps else "live" if args.live else "patch"),
            apply=bool(getattr(args, "apply", False)),
            open_pr=bool(getattr(args, "open_pr", False)),
            repo=getattr(args, "repo", None),
        )
    except api_client.ApiError as exc:
        _console._err(f"fix rejected by API: {exc}")
        sys.exit(1)
    _console._info(f"Job ID: {result.get('job_id')}")
    if result.get("run_id"):
        _console._info(f"Run ID: {result['run_id']}")


def cmd_fix(args, config) -> None:
    """Remediate a finding — thin CLI shell over ``services.fixes.generate_fix``.

    The CLI parses options, resolves the run + finding, and prints the
    structured outcome the service returns. All authorize / patch / commit
    / PR logic lives in the service. The ``--rollback`` short-circuit and
    the ``--deps`` Trivy re-scan are local conveniences that still belong
    at this layer (they don't produce audit events of their own).

    F4: when ``--api`` / ``AEGIS_MODE=api`` is set, dispatches to the API
    instead. ``--rollback`` stays local because it's a repo-side operation.
    """
    from aegis.cli import api_client

    if api_client.is_api_mode(args) and not args.rollback:
        return _cmd_fix_api(args, config)

    from aegis.remediate.patch_workflow import rollback
    from aegis.services.fixes import generate_fix

    finding_id = args.finding_id
    state = _runstate._resolve_run_state(config, args.run)
    findings = _runstate._load_findings_objects(state)

    target_finding = next((f for f in findings if f.id == finding_id), None)
    if target_finding is None:
        _console._err(f"Finding '{finding_id}' not found in run {state.run_id}.")
        sys.exit(1)

    _console._info(f"Finding: {target_finding.id} — {target_finding.title}")
    _console._info(f"Severity: {_console._colored_severity(target_finding.severity)}")

    if args.rollback:
        ref_before = getattr(args, "ref_before", None)
        if not ref_before:
            _console._err("--rollback requires --ref-before <commit-hash>")
            sys.exit(1)
        if not args.repo:
            _console._err("--rollback requires --repo")
            sys.exit(1)
        ok = rollback(args.repo, ref_before)
        _console._info("Rollback complete." if ok else "Rollback failed.")
        sys.exit(0 if ok else 1)

    if not args.patch and not args.live and not args.deps:
        print()
        print("Specify a fix strategy:")
        print(f"  aegis fix {finding_id} --patch   Generate a code patch via CAI CodeAgent")
        print(f"  aegis fix {finding_id} --live    Harden the target via CAI BlueteamAgent")
        print(f"  aegis fix {finding_id} --deps    Bump vulnerable dependencies (M7)")
        return

    state.update_finding_status(finding_id, "fixing")
    outcomes: list = []

    if args.patch:
        if args.use_golden_patch:
            _console._info(f"Using golden patch fixture for {finding_id}")
        else:
            _console._info(f"Invoking CAI CodeAgent to generate patch for {finding_id}")
        outcomes.append(generate_fix(
            run_state=state, finding=target_finding, strategy="patch",
            repo=args.repo, apply=args.apply, open_pr=args.open_pr,
            branch=args.branch, allow_dirty=args.allow_dirty,
            push=args.push, use_golden_patch=args.use_golden_patch,
            actor="cli:fix", config=config,
        ))

    if args.live:
        _console._info(f"Invoking CAI BlueteamAgent to harden target for {finding_id}")
        outcomes.append(generate_fix(
            run_state=state, finding=target_finding, strategy="live",
            repo=args.repo, apply=False, open_pr=False, branch=None,
            allow_dirty=False, push=False, use_golden_patch=False,
            actor="cli:fix", config=config,
            override_authorized=getattr(args, "override_authorized", False),
        ))

    if args.deps:
        if not args.repo:
            _console._err("--deps requires --repo")
            sys.exit(1)
        dep_finding = _refresh_deps_findings(args, state, finding_id)
        if dep_finding is None:
            sys.exit(1)
        outcomes.append(generate_fix(
            run_state=state, finding=dep_finding, strategy="deps",
            repo=args.repo, apply=args.apply, open_pr=args.open_pr,
            branch=args.branch, allow_dirty=args.allow_dirty,
            push=args.push, use_golden_patch=False,
            actor="cli:fix", config=config,
        ))

    _report_fix_outcomes(state, finding_id, outcomes, args.deps)


def _refresh_deps_findings(args, state, finding_id):
    """Re-run Trivy fs to refresh deps findings then return the requested one.

    Trivy execution is a deterministic local scan; staying at the CLI layer
    keeps the dep-bump service signature single-purpose (one finding in,
    one outcome out).
    """
    from aegis.runners.trivy_runner import run_trivy

    _console._info(f"Running Trivy fs scan on {args.repo}")
    trivy_result = run_trivy(
        args.repo, run_id=state.run_id,
        output_dir=state.run_path / "trivy",
    )
    if not trivy_result.success:
        _console._warn(f"Trivy run failed: {trivy_result.error}")
    else:
        existing = [AegisFinding.from_dict(f) for f in state.load_findings()]
        by_id = {f.id: f for f in existing}
        for tf in trivy_result.findings:
            by_id[tf.id] = tf
        state.save_findings(list(by_id.values()))
        _console._info(f"Trivy: {len(trivy_result.findings)} dependency finding(s); "
                    f"run now has {len(by_id)} total")

    all_findings = [AegisFinding.from_dict(f) for f in state.load_findings()]
    dep_finding = next((f for f in all_findings if f.id == finding_id), None)
    if dep_finding is None or dep_finding.finding_type != "dependency":
        _console._err(f"--deps requires a dependency finding id; "
                   f"'{finding_id}' is missing or wrong type")
        return None
    return dep_finding


def _report_fix_outcomes(state, finding_id, outcomes, ran_deps: bool) -> None:
    """Print a structured summary for each service outcome + persist status."""
    candidates: list[str] = []
    for outcome in outcomes:
        if outcome.strategy == "deps":
            # The deps service may operate on a different finding id; persist
            # status on the deps finding itself.
            state.update_finding_status(outcome.finding_id, outcome.status)
            if outcome.diff_path:
                _console._info(f"Bump diff written to {outcome.diff_path}")
            if outcome.commit_hash:
                _console._info(f"Bump committed on branch {outcome.branch} ({outcome.commit_hash})")
            if outcome.pr_url:
                _console._info(f"PR: {outcome.pr_url}")
            if not outcome.success and outcome.error:
                _console._warn(f"deps: {outcome.error}")
            continue

        if outcome.diff_path:
            _console._info(f"Patch written to {outcome.diff_path}")
        if outcome.commit_hash:
            _console._info(f"Committed on branch {outcome.branch} ({outcome.commit_hash})")
        if outcome.pr_url:
            _console._info(f"PR opened: {outcome.pr_url}")
        if outcome.status == "pending_apply" and not outcome.commit_hash:
            _console._info("Dry-run OK — patch applies cleanly. Pass --apply to commit.")
        if not outcome.success and outcome.error:
            _console._warn(f"{outcome.strategy}: {outcome.error}")
        candidates.append(outcome.status)

    if candidates:
        if "failed" in candidates:
            final = "failed"
        elif "pending_apply" in candidates and "fixed" not in candidates:
            final = "pending_apply"
        else:
            final = "fixed"
        state.update_finding_status(finding_id, final)
    elif not ran_deps:
        # No strategy contributed a status — restore the finding from "fixing".
        state.update_finding_status(finding_id, "open")
