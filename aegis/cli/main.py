"""Aegis security platform — main CLI entry point.

Usage:
    python -m aegis.cli <command> [options]
    python aegis/cli.py <command> [options]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.schema import AegisFinding

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
_RED = "\033[31m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_GREEN = "\033[32m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_SEVERITY_COLOR = {
    "critical": _RED,
    "high": _YELLOW,
    "medium": _BLUE,
    "low": "",
}


def _colored_severity(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev.lower(), "")
    if color:
        return f"{color}{sev.upper()}{_RESET}"
    return sev.upper()


def _info(msg: str) -> None:
    print(f"{_GREEN}[*]{_RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"{_YELLOW}[!]{_RESET} {msg}")


def _err(msg: str) -> None:
    print(f"{_RED}[!]{_RESET} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_run_state(config, run_id: str | None = None):
    """Return a RunState for the given (or latest) run, or exit with error."""
    from aegis.state import RunState

    if run_id:
        return RunState(config.output_dir, run_id)

    state = RunState.latest_run(config.output_dir)
    if state is None:
        _err("No runs found. Run 'aegis scan' first.")
        sys.exit(1)
    return state


def _load_findings_objects(state):
    """Load findings from state and convert to AegisFinding objects."""
    from aegis.schema import AegisFinding

    raw = state.load_findings()
    if not raw:
        _warn("No findings in this run.")
        return []
    return [AegisFinding.from_dict(f) for f in raw]


# ---------------------------------------------------------------------------
# API dispatch helpers (used when ``--api`` / ``AEGIS_MODE=api``)
# ---------------------------------------------------------------------------

def _cmd_scan_api(args, _config):
    from aegis.cli import api_client

    client = api_client.build_client()
    try:
        result = client.start_scan(
            target=args.target_url,
            project_id=getattr(args, "project_id", None) or "default",
            scanner=getattr(args, "scanner", None) or "strix",
            instruction=getattr(args, "instruction", None),
            override_authorized=getattr(args, "override_authorized", False),
        )
    except api_client.ApiError as exc:
        _err(f"scan rejected by API: {exc}")
        sys.exit(1)
    _info(f"Run ID: {result.get('run_id')}")
    _info(f"Job ID: {result.get('job_id')}")
    if result.get("status_url"):
        _info(f"Status: {result['status_url']}")


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
        _err(f"fix rejected by API: {exc}")
        sys.exit(1)
    _info(f"Job ID: {result.get('job_id')}")
    if result.get("run_id"):
        _info(f"Run ID: {result['run_id']}")


def _cmd_verify_api(args, _config):
    from aegis.cli import api_client

    client = api_client.build_client()
    try:
        result = client.verify(finding_id=args.finding_id)
    except api_client.ApiError as exc:
        _err(f"verify rejected by API: {exc}")
        sys.exit(1)
    _info(f"Job ID: {result.get('job_id')}")


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_doctor(args, config):
    """Validate the Aegis development environment."""
    from aegis.doctor import run_doctor

    ok = run_doctor(config, api_mode=getattr(args, "api_mode", False))
    sys.exit(0 if ok else 1)


def cmd_init(_args, _config):
    """Create a default aegis.yaml in the current directory."""
    target = Path("aegis.yaml")
    if target.exists():
        _warn("aegis.yaml already exists — skipping.")
        return

    import dataclasses

    from aegis.config import AegisConfig

    defaults = AegisConfig()
    lines = ["# Aegis configuration\n"]
    for f in dataclasses.fields(defaults):
        val = getattr(defaults, f.name)
        if isinstance(val, list):
            lines.append(f"{f.name}:")
            for item in val:
                lines.append(f"  - \"{item}\"")
        elif isinstance(val, str):
            lines.append(f"{f.name}: \"{val}\"")
        else:
            lines.append(f"{f.name}: {val}")
    lines.append("")

    target.write_text("\n".join(lines))
    _info(f"Created {target.resolve()}")


def cmd_scan(args, config):
    """Scan a target — thin CLI shell over ``services.scans.start_scan``.

    Local-only conveniences (loading pre-existing Strix events.jsonl,
    bundled demo fixture) stay at this layer; everything that needs an
    audit event lives behind the service boundary.

    F4: when ``--api`` / ``AEGIS_MODE=api`` is set, dispatches the scan
    via ``aegis.cli.api_client`` and returns the run handle.
    """
    from aegis.adapters.strix_adapter import convert_strix_findings, load_strix_events
    from aegis.cli import api_client
    from aegis.services.scans import start_scan
    from aegis.state import RunState

    if api_client.is_api_mode(args):
        return _cmd_scan_api(args, config)

    target_url = args.target_url
    repo_path = args.repo

    state = RunState(config.output_dir)
    _info(f"Run ID: {state.run_id}")
    _info(f"Target: {target_url}")

    findings = []

    if getattr(args, "use_strix", False):
        _info("Launching Strix as a subprocess (this may take a while)")
        outcome = start_scan(
            run_state=state, target=target_url, scanner="strix",
            instruction=getattr(args, "instruction", None),
            timeout=getattr(args, "timeout", 1800),
            actor="cli:scan",
            config=config,
            override_authorized=getattr(args, "override_authorized", False),
            use_strix=True,
        )
        findings = outcome.findings
        if outcome.success:
            _info(f"Strix completed: {len(findings)} finding(s)")
        elif outcome.partial_success:
            _warn(f"Strix exited rc={outcome.return_code} but emitted "
                  f"{len(findings)} finding(s) — partial success")
        else:
            _err(f"Strix failed: {outcome.error or 'unknown error'}")

    # Try to load Strix events.jsonl from an explicit path or the repo path.
    events_path = Path(args.events) if getattr(args, "events", None) else None
    if events_path is None and repo_path and not findings:
        events_path = Path(repo_path) / "events.jsonl"

    if not findings and events_path is not None:
        if events_path.exists():
            _info(f"Loading Strix events from {events_path}")
            findings = load_strix_events(str(events_path), state.run_id)
        else:
            _warn(f"Strix events file not found: {events_path}")

    # Demo mode: load fixture only when explicitly requested.
    if not findings and getattr(args, "demo", False):
        fixture = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "strix_finding.json"
        if fixture.exists():
            _info(f"Loading demo fixture from {fixture}")
            with open(fixture) as fh:
                raw = json.load(fh)
            raw_list = raw if isinstance(raw, list) else [raw]
            findings = convert_strix_findings(raw_list, state.run_id)
        else:
            _warn("Demo fixture not found. No findings to process.")
    elif not findings:
        _warn("No Strix findings loaded. Provide --events, --repo with events.jsonl, or --demo.")

    state.save_findings(findings)
    _info(f"Saved {len(findings)} finding(s) to {state.findings_path}")

    # Summary
    if findings:
        print()
        print(f"{_BOLD}Scan Summary{_RESET}")
        print(f"  Findings: {len(findings)}")
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        for sev in ("critical", "high", "medium", "low"):
            count = sev_counts.get(sev, 0)
            if count:
                print(f"  {_colored_severity(sev)}: {count}")


def cmd_findings(args, config):
    """Display findings as a table."""
    state = _resolve_run_state(config, args.run)
    findings = state.load_findings()

    if not findings:
        _warn("No findings in this run.")
        return

    _info(f"Run: {state.run_id}  ({len(findings)} finding(s))")
    print()

    # Table header
    hdr_fmt = "{:<14}  {:<10}  {:<45}  {:<12}  {:<14}"

    print(hdr_fmt.format("ID", "Severity", "Title", "Type", "Status"))
    print("-" * 100)

    for f in findings:
        sev_raw = f.get("severity", "unknown")
        # For colored severity we need to account for ANSI escape width
        sev_display = _colored_severity(sev_raw)
        title = f.get("title", "")
        if len(title) > 45:
            title = title[:42] + "..."
        # Print with manual padding since ANSI codes mess up format widths
        fid = f.get("id", "?")
        ftype = f.get("finding_type", "?")
        status = f.get("status", "?")
        print(f"{fid:<14}  {sev_display}{' ' * max(0, 10 - len(sev_raw.upper()) )}"
              f"  {title:<45}  {ftype:<12}  {status:<14}")


def cmd_export(args, config):
    """Export findings to vulnerability-fixer format."""
    if args.format != "vulnfixer":
        _err(f"Unsupported export format: {args.format}")
        sys.exit(1)

    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)

    if not findings:
        return

    from aegis.adapters.vulnfixer_adapter import export_findings

    output_path = state.run_path / "vulnfixer-export.json"
    summary = export_findings(findings, output_path)

    _info(f"Exported to {output_path}")
    print()
    print(f"{_BOLD}Export Summary{_RESET}")
    print(f"  Total findings:          {summary['total']}")
    print(f"  Routable to vulnfixer:   {summary['routable_to_vulnfixer']}")
    print(f"  Requires code fix (CAI): {summary['requires_code_fix']}")


def cmd_fix(args, config):
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
    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)

    target_finding = next((f for f in findings if f.id == finding_id), None)
    if target_finding is None:
        _err(f"Finding '{finding_id}' not found in run {state.run_id}.")
        sys.exit(1)

    _info(f"Finding: {target_finding.id} — {target_finding.title}")
    _info(f"Severity: {_colored_severity(target_finding.severity)}")

    if args.rollback:
        ref_before = getattr(args, "ref_before", None)
        if not ref_before:
            _err("--rollback requires --ref-before <commit-hash>")
            sys.exit(1)
        if not args.repo:
            _err("--rollback requires --repo")
            sys.exit(1)
        ok = rollback(args.repo, ref_before)
        _info("Rollback complete." if ok else "Rollback failed.")
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
            _info(f"Using golden patch fixture for {finding_id}")
        else:
            _info(f"Invoking CAI CodeAgent to generate patch for {finding_id}")
        outcomes.append(generate_fix(
            run_state=state, finding=target_finding, strategy="patch",
            repo=args.repo, apply=args.apply, open_pr=args.open_pr,
            branch=args.branch, allow_dirty=args.allow_dirty,
            push=args.push, use_golden_patch=args.use_golden_patch,
            actor="cli:fix", config=config,
        ))

    if args.live:
        _info(f"Invoking CAI BlueteamAgent to harden target for {finding_id}")
        outcomes.append(generate_fix(
            run_state=state, finding=target_finding, strategy="live",
            repo=args.repo, apply=False, open_pr=False, branch=None,
            allow_dirty=False, push=False, use_golden_patch=False,
            actor="cli:fix", config=config,
            override_authorized=getattr(args, "override_authorized", False),
        ))

    if args.deps:
        if not args.repo:
            _err("--deps requires --repo")
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
    from aegis.adapters.trivy_runner import run_trivy

    _info(f"Running Trivy fs scan on {args.repo}")
    trivy_result = run_trivy(
        args.repo, run_id=state.run_id,
        output_dir=state.run_path / "trivy",
    )
    if not trivy_result.success:
        _warn(f"Trivy run failed: {trivy_result.error}")
    else:
        existing = [AegisFinding.from_dict(f) for f in state.load_findings()]
        by_id = {f.id: f for f in existing}
        for tf in trivy_result.findings:
            by_id[tf.id] = tf
        state.save_findings(list(by_id.values()))
        _info(f"Trivy: {len(trivy_result.findings)} dependency finding(s); "
              f"run now has {len(by_id)} total")

    all_findings = [AegisFinding.from_dict(f) for f in state.load_findings()]
    dep_finding = next((f for f in all_findings if f.id == finding_id), None)
    if dep_finding is None or dep_finding.finding_type != "dependency":
        _err(f"--deps requires a dependency finding id; "
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
                _info(f"Bump diff written to {outcome.diff_path}")
            if outcome.commit_hash:
                _info(f"Bump committed on branch {outcome.branch} ({outcome.commit_hash})")
            if outcome.pr_url:
                _info(f"PR: {outcome.pr_url}")
            if not outcome.success and outcome.error:
                _warn(f"deps: {outcome.error}")
            continue

        if outcome.diff_path:
            _info(f"Patch written to {outcome.diff_path}")
        if outcome.commit_hash:
            _info(f"Committed on branch {outcome.branch} ({outcome.commit_hash})")
        if outcome.pr_url:
            _info(f"PR opened: {outcome.pr_url}")
        if outcome.status == "pending_apply" and not outcome.commit_hash:
            _info("Dry-run OK — patch applies cleanly. Pass --apply to commit.")
        if not outcome.success and outcome.error:
            _warn(f"{outcome.strategy}: {outcome.error}")
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


def cmd_verify(args, config):
    """Verify a finding by replaying its PoC — thin shell over the service.

    F4: when ``--api`` / ``AEGIS_MODE=api`` is set, dispatches to the API.
    """
    from aegis.cli import api_client

    if api_client.is_api_mode(args):
        return _cmd_verify_api(args, config)

    from aegis.services.verify import verify as verify_svc

    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)
    target = next((f for f in findings if f.id == args.finding_id), None)
    if target is None:
        _err(f"Finding '{args.finding_id}' not found in run {state.run_id}.")
        sys.exit(1)

    repo_path = Path(args.repo) if args.repo else None
    result = verify_svc(
        run_state=state,
        finding=target,
        repo_path=repo_path,
        require_rebuilt=not args.no_provenance_check,
        actor="cli:verify",
        config=config,
    )

    status_color = {
        "verified": _GREEN,
        "still_vulnerable": _RED,
        "inconclusive": _YELLOW,
    }.get(result.status, "")
    print()
    print(f"{_BOLD}Verification result{_RESET}")
    print(f"  Finding:  {result.finding_id}")
    print(f"  Strategy: {result.strategy}")
    print(f"  Status:   {status_color}{result.status}{_RESET}")
    if result.notes:
        print(f"  Notes:    {result.notes}")
    print(f"  Saved to: {state.run_path / 'verify' / (result.finding_id + '.json')}")


def cmd_report(args, config):
    """Generate Markdown / JSON / HTML reports — thin shell over the service."""
    from aegis.services.reports import render_reports

    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)

    if not findings:
        return

    html_flag = not getattr(args, "no_html", False)
    outcome = render_reports(run_state=state, findings=findings, html=html_flag)
    _info(f"Report written to {outcome.markdown_path}")
    _info(f"JSON report written to {outcome.json_path}")
    if outcome.html_path is not None:
        _info(f"HTML report written to {outcome.html_path}")


def cmd_targets(args, config):
    """Manage vulnerable-target containers (list / up / down)."""
    from aegis.safety import authorize
    from aegis.state import RunState
    from aegis.targets import get_target_pack, list_target_packs

    action = args.targets_action
    if action == "list":
        for name in list_target_packs():
            print(name)
        return

    pack_name = args.target_pack
    if action == "up":
        state = RunState(config.output_dir) if args.run is None else RunState(config.output_dir, args.run)
        pack = get_target_pack(pack_name, run_path=state.run_path, port=args.port)
        authorize(
            "target.start", pack.runtime.url,
            allowlist=config.target_allowlist, run_path=state.run_path,
            override_authorized=getattr(args, "override_authorized", False),
            detail={"pack": pack_name, "repo": args.repo, "port": args.port},
        )
        if args.repo:
            _info(f"Building {pack_name} from {args.repo} and starting on {pack.runtime.url}")
            runtime = pack.up_from_repo(args.repo)
        else:
            _info(f"Starting {pack_name} from pinned image on {pack.runtime.url}")
            runtime = pack.up(image_tag=getattr(config, "juice_shop_image_tag", None)
                              if pack_name == "juice-shop" else None)
        ready = pack.wait_ready(timeout=args.timeout)
        _info(f"Container ready: {ready} ({runtime.url})")
        return

    if action == "down":
        state = RunState(config.output_dir) if args.run is None else RunState(config.output_dir, args.run)
        pack = get_target_pack(pack_name, run_path=state.run_path)
        authorize(
            "target.down", pack.runtime.url,
            allowlist=config.target_allowlist, run_path=state.run_path,
            detail={"pack": pack_name, "container_name": pack.container_name},
        )
        pack.down()
        _info(f"Stopped {pack.container_name}")
        return

    _err(f"Unknown targets action: {action}")
    sys.exit(1)


def cmd_demo(args, config):
    """Run the opinionated end-to-end demo."""
    from aegis.demo import run_demo

    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        _err(f"--repo path does not exist or is not a directory: {repo_path}")
        sys.exit(1)

    _info(f"Aegis demo starting (repo={repo_path})")
    _info(f"Mode: strix={'live' if args.live_strix else 'fixture'} "
          f"llm={'live' if args.live_llm else 'fixture'} "
          f"apply={'yes' if args.apply else 'dry-run'}")

    outcome = run_demo(
        config,
        repo_path=repo_path,
        live_strix=args.live_strix,
        live_llm=args.live_llm,
        apply=args.apply,
        use_golden_patch=args.use_golden_patch or not args.live_llm,
        keep_target=args.keep_target,
        target_pack_name=args.target_pack,
    )

    print()
    print(f"{_BOLD}Demo summary{_RESET}")
    for s in outcome.stages:
        mark = _GREEN + "✓" + _RESET if s.success else _RED + "✗" + _RESET
        print(f"  {mark} {s.name:<12} mode={s.mode:<14} {s.detail}")
    print(f"\nArtifacts: {outcome.run_path}")
    report_html = Path(outcome.run_path) / "report.html"
    if report_html.exists():
        print(f"Report:    {report_html}")


def cmd_pipeline(args, config):
    """Run the full pipeline: scan -> findings -> export -> report."""
    print(f"{_BOLD}Aegis Pipeline{_RESET}")
    print("=" * 50)

    # Step 1: Scan
    print(f"\n{_BOLD}[1/4] Scan{_RESET}")
    cmd_scan(args, config)

    # Grab the latest run for subsequent steps
    from aegis.state import RunState

    state = RunState.latest_run(config.output_dir)
    if state is None:
        _err("Scan produced no run state.")
        sys.exit(1)

    # Step 2: Findings
    print(f"\n{_BOLD}[2/4] Findings{_RESET}")
    findings_args = argparse.Namespace(run=state.run_id)
    cmd_findings(findings_args, config)

    # Step 3: Export
    print(f"\n{_BOLD}[3/4] Export{_RESET}")
    export_args = argparse.Namespace(format="vulnfixer", run=state.run_id)
    cmd_export(export_args, config)

    # Step 4: Report
    print(f"\n{_BOLD}[4/4] Report{_RESET}")
    report_args = argparse.Namespace(run=state.run_id)
    cmd_report(report_args, config)

    # Final summary
    findings = state.load_findings()
    print()
    print("=" * 50)
    print(f"{_BOLD}Pipeline complete.{_RESET}")
    print(f"  Run ID:   {state.run_id}")
    print(f"  Findings: {len(findings)}")
    print(f"  Output:   {state.run_path}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis — unified security scanning and remediation platform",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to aegis.yaml config file",
        default=None,
    )
    parser.add_argument(
        "--dry-run", dest="global_dry_run", action="store_true",
        help="Refuse destructive operations across all subcommands "
             "(implies no --apply, no --push, no --open-pr).",
    )
    parser.add_argument(
        "--verbose", "-v", dest="global_verbose", action="store_true",
        help="Print extra context (configured paths, audit destinations).",
    )
    parser.add_argument(
        "--i-understand-this-target-is-authorized",
        dest="global_override_authorized", action="store_true",
        help="Authorize active operations against non-allowlisted hosts. "
             "Use only against systems you control and have written permission to test.",
    )
    parser.add_argument(
        "--api", dest="global_api", action="store_true",
        help="Route commands through AEGIS_API_URL instead of the local "
             "filesystem (Phase 3). Equivalent to AEGIS_MODE=api.",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # doctor
    p_doctor = sub.add_parser("doctor", help="Validate the Aegis environment")
    p_doctor.add_argument("--api-mode", dest="api_mode", action="store_true",
                          help="Also probe DB, blob backend, OIDC issuer (Phase 3)")

    # init
    sub.add_parser("init", help="Create a default aegis.yaml in the current directory")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a target URL")
    p_scan.add_argument("target_url", help="Target URL to scan")
    p_scan.add_argument("--repo", help="Path to repository with Strix events", default=None)
    p_scan.add_argument("--events", help="Path to Strix events.jsonl", default=None)
    p_scan.add_argument("--demo", action="store_true", help="Use bundled demo finding fixture")
    p_scan.add_argument("--use-strix", dest="use_strix", action="store_true",
                        help="Invoke Strix as a subprocess against the target URL")
    p_scan.add_argument("--instruction", default=None,
                        help="Free-text scope/rules-of-engagement instruction for Strix")
    p_scan.add_argument("--timeout", type=int, default=1800,
                        help="Strix subprocess timeout in seconds (default: 1800)")
    p_scan.add_argument("--i-understand-this-target-is-authorized",
                        dest="override_authorized", action="store_true",
                        help="Authorize a target outside the allowlist")

    # findings
    p_findings = sub.add_parser("findings", help="List findings from a run")
    p_findings.add_argument("--run", help="Run ID (default: latest)", default=None)

    # export
    p_export = sub.add_parser("export", help="Export findings to external tool format")
    p_export.add_argument("--format", required=True, choices=["vulnfixer"],
                          help="Export format")
    p_export.add_argument("--run", help="Run ID (default: latest)", default=None)

    # fix
    p_fix = sub.add_parser("fix", help="Remediate a specific finding")
    p_fix.add_argument("finding_id", help="ID of the finding to fix")
    p_fix.add_argument("--run", help="Run ID (default: latest)", default=None)
    p_fix.add_argument("--repo", help="Repository path for code patch generation", default=None)
    p_fix.add_argument("--patch", action="store_true",
                       help="Generate a code patch via CAI CodeAgent")
    p_fix.add_argument("--live", action="store_true",
                       help="Harden the target via CAI BlueteamAgent")
    p_fix.add_argument("--deps", action="store_true",
                       help="Run Trivy and synthesize a version-bump patch for "
                            "the specified dependency finding")
    p_fix.add_argument("--apply", action="store_true",
                       help="Actually write the patch to the repo (default: dry-run)")
    p_fix.add_argument("--branch", default=None,
                       help="Branch name (default: aegis/fix/<finding_id>)")
    p_fix.add_argument("--push", action="store_true",
                       help="git push -u origin <branch> before creating PR")
    p_fix.add_argument("--open-pr", dest="open_pr", action="store_true",
                       help="Create a GitHub PR via `gh pr create` after commit")
    p_fix.add_argument("--rollback", action="store_true",
                       help="git reset --hard <ref-before>; requires --repo and --ref-before")
    p_fix.add_argument("--ref-before", dest="ref_before", default=None,
                       help="Commit SHA to roll back to (used with --rollback)")
    p_fix.add_argument("--use-golden-patch", dest="use_golden_patch", action="store_true",
                       help="Use bundled golden patch fixture instead of calling CAI")
    p_fix.add_argument("--allow-dirty", dest="allow_dirty", action="store_true",
                       help="Allow patch on a dirty working tree")
    p_fix.add_argument("--i-understand-this-target-is-authorized",
                       dest="override_authorized", action="store_true",
                       help="Authorize a target outside the allowlist (live hardening)")

    # verify
    p_verify = sub.add_parser("verify", help="Verify a finding by replaying its PoC")
    p_verify.add_argument("finding_id", help="ID of the finding to verify")
    p_verify.add_argument("--run", help="Run ID (default: latest)", default=None)
    p_verify.add_argument("--repo", help="Repository path (required for SAST strategy)", default=None)
    p_verify.add_argument("--no-provenance-check", dest="no_provenance_check",
                          action="store_true",
                          help="Skip the target/runtime.json rebuild check")

    # report
    p_report = sub.add_parser("report", help="Generate a Markdown security report")
    p_report.add_argument("--run", help="Run ID (default: latest)", default=None)
    p_report.add_argument("--html", action="store_true", help="Also emit report.html (default on)")
    p_report.add_argument("--no-html", action="store_true", help="Skip HTML emission")

    # pipeline
    p_pipeline = sub.add_parser("pipeline", help="Run full pipeline: scan -> findings -> export -> report")
    p_pipeline.add_argument("target_url", help="Target URL to scan")
    p_pipeline.add_argument("--repo", help="Path to repository with Strix events", default=None)
    p_pipeline.add_argument("--events", help="Path to Strix events.jsonl", default=None)
    p_pipeline.add_argument("--demo", action="store_true", help="Use bundled demo finding fixture")

    # targets
    p_targets = sub.add_parser("targets", help="Manage vulnerable-target containers")
    targets_sub = p_targets.add_subparsers(dest="targets_action", required=True)
    targets_sub.add_parser("list", help="List available target packs")
    p_targets_up = targets_sub.add_parser("up", help="Start a target")
    p_targets_up.add_argument("target_pack", help="Pack name (e.g. juice-shop, dvwa)")
    p_targets_up.add_argument("--repo", default=None,
                              help="Build from this source repo (source mode). "
                                   "Without --repo a pinned upstream image is used.")
    p_targets_up.add_argument("--port", type=int, default=None,
                              help="Host port to bind (defaults per pack)")
    p_targets_up.add_argument("--run", default=None,
                              help="Reuse an existing run id (default: create new)")
    p_targets_up.add_argument("--timeout", type=int, default=120,
                              help="Readiness probe timeout in seconds")
    p_targets_up.add_argument("--i-understand-this-target-is-authorized",
                              dest="override_authorized", action="store_true",
                              help="Allow non-loopback host bindings")
    p_targets_down = targets_sub.add_parser("down", help="Stop a target")
    p_targets_down.add_argument("target_pack", help="Pack name")
    p_targets_down.add_argument("--run", default=None,
                                help="Run id whose target/runtime.json should be updated")

    # status (Phase 3 M0.5)
    sub.add_parser("status", help="Print active mode, backends, and connectivity")

    # audit (Phase 3 M2 — surface lands now, impl in M2)
    p_audit = sub.add_parser("audit", help="Audit-chain operations")
    audit_sub = p_audit.add_subparsers(dest="audit_action", required=True)
    p_audit_verify = audit_sub.add_parser("verify", help="Verify audit-chain integrity")
    p_audit_verify.add_argument("--run", default=None, help="Verify a specific run's chain")
    p_audit_verify.add_argument("--project", default=None,
                                help="Verify a specific project's chain")
    p_audit_verify.add_argument("--all", action="store_true",
                                help="Verify every chain known to the writer")

    # migrate (Phase 3 M11 — surface lands now, impl in M11)
    p_migrate = sub.add_parser("migrate", help="Move filesystem run data into Postgres (M11)")
    p_migrate.add_argument("direction", choices=["fs->pg"], default="fs->pg", nargs="?",
                           help="Migration direction (only fs->pg in Phase 3)")
    p_migrate.add_argument("--source", required=True,
                           help="Path to aegis_output/ on disk")
    p_migrate.add_argument("--project", required=True,
                           help="Target project slug or id")
    p_migrate.add_argument("--db-url", dest="db_url", default=None,
                           help="Override AEGIS_DB_URL for this migration")
    p_migrate.add_argument("--dry-run", dest="dry_run", action="store_true",
                           help="Print planned counts without writing")

    # ci-gate (Phase 3 M5/M12)
    p_ci = sub.add_parser("ci-gate",
                          help="Evaluate findings against a CI policy and exit 0/1/2")
    p_ci.add_argument("--findings-file", default=None,
                      help="Path to a findings.json")
    p_ci.add_argument("--run", default=None,
                      help="Read findings.json from aegis_output/runs/<run>/")
    p_ci.add_argument("--severity-threshold", default="high",
                      choices=["critical", "high", "medium", "low"])
    p_ci.add_argument("--max-findings", type=int, default=None)
    p_ci.add_argument("--require-validated", action="store_true",
                      help="Only count findings with validation_state=poc_passed")
    p_ci.add_argument("--junit-xml", default=None,
                      help="Path to write a JUnit XML report")

    # demo
    p_demo = sub.add_parser("demo", help="Opinionated end-to-end demo (defaults to fixture-assisted)")
    p_demo.add_argument("--repo", required=True, help="Path to the target source repo to patch")
    p_demo.add_argument("--target-pack", dest="target_pack", default="juice-shop",
                        help="Target pack name (default: juice-shop)")
    p_demo.add_argument("--live-strix", dest="live_strix", action="store_true",
                        help="Invoke Strix instead of using the recorded fixture")
    p_demo.add_argument("--live-llm", dest="live_llm", action="store_true",
                        help="Call CAI CodeAgent instead of using the golden patch")
    p_demo.add_argument("--use-golden-patch", dest="use_golden_patch", action="store_true",
                        help="Force golden patch even when --live-llm is set")
    p_demo.add_argument("--keep-target", dest="keep_target", action="store_true",
                        help="Skip docker teardown so you can poke at the target afterwards")
    p_demo.add_argument("--apply", action="store_true",
                        help="Commit the patch to a new branch in --repo "
                             "(default: dry-run; diff is persisted but the repo is not mutated)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_COMMANDS = {
    "doctor": cmd_doctor,
    "init": cmd_init,
    "scan": cmd_scan,
    "findings": cmd_findings,
    "export": cmd_export,
    "fix": cmd_fix,
    "verify": cmd_verify,
    "report": cmd_report,
    "pipeline": cmd_pipeline,
    "demo": cmd_demo,
    "targets": cmd_targets,
}


def _cmd_status_dispatch(args, config):
    from aegis.cli.status import cmd_status
    cmd_status(args, config)


def _cmd_audit_dispatch(args, config):
    from aegis.cli.audit import cmd_audit_verify
    if args.audit_action == "verify":
        cmd_audit_verify(args, config)
    else:
        _err(f"Unknown audit action: {args.audit_action}")
        sys.exit(2)


def _cmd_migrate_dispatch(args, config):
    from aegis.cli.migrate import cmd_migrate
    cmd_migrate(args, config)


def _cmd_ci_gate_dispatch(args, config):
    from aegis.cli.ci_gate import cmd_ci_gate
    cmd_ci_gate(args, config)


_COMMANDS["status"] = _cmd_status_dispatch
_COMMANDS["audit"] = _cmd_audit_dispatch
_COMMANDS["migrate"] = _cmd_migrate_dispatch
_COMMANDS["ci-gate"] = _cmd_ci_gate_dispatch


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # F4: --api sets AEGIS_MODE=api for the rest of the process so the
    # api_client + status + downstream calls all agree on the mode.
    if getattr(args, "global_api", False):
        import os
        os.environ["AEGIS_MODE"] = "api"

    # Union the global flags with subcommand-specific equivalents.
    if getattr(args, "global_override_authorized", False):
        args.override_authorized = True
    if getattr(args, "global_dry_run", False):
        # Global dry-run refuses to mutate the repo or push. We do not
        # override --apply here silently; instead we abort loudly so the
        # user notices the conflict.
        for mutating in ("apply", "push", "open_pr"):
            if getattr(args, mutating, False):
                _err(f"--dry-run cannot be combined with --{mutating.replace('_','-')}")
                sys.exit(2)
        # Refuse any subcommand that mutates Docker state.
        if args.command == "targets":
            action = getattr(args, "targets_action", None)
            if action in ("up", "down", "rebuild"):
                _err(f"--dry-run cannot be combined with `targets {action}` "
                     f"(would mutate Docker state)")
                sys.exit(2)
        # demo without --apply is read-only; demo --apply was already caught
        # above. Other mutating subcommands should add a similar gate.

    if getattr(args, "global_verbose", False):
        _info(f"config={args.config or '<auto>'}")

    from aegis.config import load_config

    config = load_config(args.config)

    handler = _COMMANDS.get(args.command)
    if handler is None:
        _err(f"Unknown command: {args.command}")
        sys.exit(1)

    handler(args, config)


if __name__ == "__main__":
    main()
