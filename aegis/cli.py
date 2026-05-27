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
# Command implementations
# ---------------------------------------------------------------------------

def cmd_doctor(_args, config):
    """Validate the Aegis development environment."""
    from aegis.doctor import run_doctor

    ok = run_doctor(config)
    sys.exit(0 if ok else 1)


def cmd_init(_args, _config):
    """Create a default aegis.yaml in the current directory."""
    target = Path("aegis.yaml")
    if target.exists():
        _warn("aegis.yaml already exists — skipping.")
        return

    from aegis.config import AegisConfig
    import dataclasses

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
    """Scan a target — normalize existing Strix output or use an explicit demo fixture."""
    from aegis.state import RunState
    from aegis.adapters.strix_adapter import load_strix_events, convert_strix_findings
    from aegis.safety import authorize

    target_url = args.target_url
    repo_path = args.repo

    state = RunState(config.output_dir)
    _info(f"Run ID: {state.run_id}")
    _info(f"Target: {target_url}")

    findings = []

    if getattr(args, "use_strix", False):
        from aegis.adapters.strix_runner import run_strix
        authorize(
            "strix.run", target_url,
            allowlist=config.target_allowlist, run_path=state.run_path,
            override_authorized=getattr(args, "override_authorized", False),
            detail={"target": target_url},
        )
        _info("Launching Strix as a subprocess (this may take a while)")
        result = run_strix(
            target_url, state,
            instruction=getattr(args, "instruction", None),
            timeout=getattr(args, "timeout", 1800),
            strix_command=getattr(config, "strix_command", None),
            strix_path=config.strix_path,
        )
        findings = result.findings
        if result.success:
            _info(f"Strix completed: {len(findings)} finding(s)")
        elif result.partial_success:
            _warn(f"Strix exited rc={result.return_code} but emitted {len(findings)} finding(s) — partial success")
        else:
            _err(f"Strix failed: {result.error or 'unknown error'}")

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
    row_fmt = "{:<14}  {:<10}  {:<45}  {:<12}  {:<14}"

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
        # ANSI codes add ~9 chars that are not visible, compensate
        ansi_pad = len(sev_display) - len(sev_raw.upper())
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
    """Remediate a finding using CAI CodeAgent or BlueteamAgent."""
    from aegis.remediate.cai_runner import run_code_fix, run_live_hardening
    from aegis.remediate.patch_workflow import (
        apply_patch,
        commit_patch,
        open_pull_request,
        rollback,
    )
    from aegis.safety import authorize

    finding_id = args.finding_id
    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)

    target_finding = None
    for f in findings:
        if f.id == finding_id:
            target_finding = f
            break

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

    # Status tracking for the patch path. Defaults: not "fixed" unless
    # an --apply path produces a successful commit.
    patch_status: str | None = None     # None | "fixed" | "failed" | "pending_apply"

    results = []
    if args.patch:
        if args.use_golden_patch:
            _info(f"Using golden patch fixture for {finding_id}")
        else:
            _info(f"Invoking CAI CodeAgent to generate patch for {finding_id}")
        result = run_code_fix(
            target_finding,
            repo_path=args.repo,
            use_golden_patch=args.use_golden_patch,
        )
        results.append(result)
        # If the runner itself failed, that's a hard "failed" — no diff means
        # nothing to apply.
        if not result.success:
            patch_status = "failed"

        if result.success and result.diff and args.repo:
            authorize(
                "patch.apply",
                None,
                allowlist=config.target_allowlist,
                run_path=state.run_path,
                detail={"finding_id": finding_id, "repo": args.repo,
                        "diff_sha256": result.diff_sha256_hex,
                        "source": result.source, "dry_run": not args.apply},
            )
            # Persist the diff regardless of --apply.
            patches_dir = state.run_path / "artifacts" / "patches"
            patches_dir.mkdir(parents=True, exist_ok=True)
            (patches_dir / f"{finding_id}.diff").write_text(result.diff)
            _info(f"Patch written to {patches_dir / f'{finding_id}.diff'}")

            if not args.apply:
                # Dry-run: only validate that the patch *would* apply, never
                # mutate the working tree. apply_patch with dry_run=True maps
                # to ``git apply --check``. A successful dry-run is NOT a
                # "fixed" status — the repo has not actually been patched.
                check = apply_patch(args.repo, result.diff, dry_run=True)
                if check.success:
                    _info("Dry-run OK — patch applies cleanly. Pass --apply to commit.")
                    patch_status = "pending_apply"
                else:
                    _warn(f"Dry-run failed (`git apply --check`): {check.stderr}")
                    patch_status = "failed"
            else:
                # --apply: commit_patch does the single canonical apply +
                # commit on a new branch, with auto-rollback on failure.
                commit_result = commit_patch(
                    args.repo,
                    target_finding,
                    result.diff,
                    branch=args.branch,
                    allow_dirty=args.allow_dirty,
                )
                if commit_result.success:
                    _info(f"Committed on branch {commit_result.branch} ({commit_result.commit_hash})")
                    state.append_remediation_log(
                        finding_id,
                        action="patch_commit",
                        result=(f"branch={commit_result.branch} "
                                f"commit={commit_result.commit_hash} "
                                f"ref_before={commit_result.ref_before} "
                                f"diff_sha256={commit_result.diff_sha256}"),
                        success=True,
                    )
                    patch_status = "fixed"
                    if args.open_pr:
                        authorize(
                            "github.open_pr",
                            None,
                            allowlist=config.target_allowlist,
                            run_path=state.run_path,
                            detail={"branch": commit_result.branch},
                        )
                        ok, url_or_err = open_pull_request(
                            args.repo,
                            commit_result.branch,
                            title=f"Aegis fix: {target_finding.title} ({finding_id})",
                            body=f"Automated fix from Aegis run {state.run_id}.\n\n"
                                 f"Source: {result.source}\n"
                                 f"diff sha256: {commit_result.diff_sha256}\n",
                            push=args.push,
                        )
                        if ok:
                            _info(f"PR opened: {url_or_err}")
                            state.append_remediation_log(
                                finding_id, action="open_pr",
                                result=url_or_err, success=True,
                            )
                        else:
                            _warn(f"PR creation failed: {url_or_err}")
                else:
                    _warn(f"commit failed: {commit_result.error} (repo rolled back to {commit_result.ref_before})")
                    # commit_patch already rolled back; surface the partial
                    # failure to the caller.
                    result.success = False
                    patch_status = "failed"

    live_status: str | None = None
    if args.live:
        authorize(
            "cai.live_hardening",
            target_finding.target,
            allowlist=config.target_allowlist,
            run_path=state.run_path,
            override_authorized=getattr(args, "override_authorized", False),
            detail={"finding_id": finding_id},
        )
        _info(f"Invoking CAI BlueteamAgent to harden target for {finding_id}")
        live_result = run_live_hardening(target_finding)
        results.append(live_result)
        live_status = "fixed" if live_result.success else "failed"

    if args.deps:
        if not args.repo:
            _err("--deps requires --repo")
            sys.exit(1)
        from aegis.adapters.trivy_runner import run_trivy
        from aegis.remediate.deps_workflow import build_version_bump_diff
        from aegis.remediate.patch_workflow import apply_patch, commit_patch

        # Always re-scan so the run's findings reflect repo HEAD before bumping.
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

        # Resolve the dep finding to bump
        all_findings = [AegisFinding.from_dict(f) for f in state.load_findings()]
        dep_finding = next((f for f in all_findings if f.id == finding_id), None)
        if dep_finding is None or dep_finding.finding_type != "dependency":
            _err(f"--deps requires a dependency finding id; '{finding_id}' is missing or wrong type")
            sys.exit(1)

        bump = build_version_bump_diff(dep_finding, args.repo)
        if bump.diff is None:
            _warn(f"could not synthesize bump diff: {bump.error}")
        else:
            authorize(
                "deps.bump", None,
                allowlist=config.target_allowlist, run_path=state.run_path,
                detail={"finding_id": dep_finding.id, "repo": args.repo,
                        "package": dep_finding.package_name,
                        "from": dep_finding.installed_version,
                        "to": dep_finding.fixed_version,
                        "manifest": bump.rel_path},
            )
            patches_dir = state.run_path / "artifacts" / "patches"
            patches_dir.mkdir(parents=True, exist_ok=True)
            (patches_dir / f"{dep_finding.id}.diff").write_text(bump.diff)
            _info(f"Bump diff written to {patches_dir / (dep_finding.id + '.diff')}")

            if args.apply:
                commit_result = commit_patch(
                    args.repo, dep_finding, bump.diff,
                    branch=args.branch, allow_dirty=args.allow_dirty,
                )
                if commit_result.success:
                    _info(f"Bump committed on branch {commit_result.branch} "
                          f"({commit_result.commit_hash})")
                    state.append_remediation_log(
                        dep_finding.id, action="deps_bump",
                        result=(f"branch={commit_result.branch} "
                                f"commit={commit_result.commit_hash} "
                                f"manifest={bump.rel_path} "
                                f"diff_sha256={commit_result.diff_sha256}"),
                        success=True,
                    )
                    state.update_finding_status(dep_finding.id, "fixed")
                    if args.open_pr:
                        ok, url_or_err = open_pull_request(
                            args.repo, commit_result.branch,
                            title=f"Aegis deps: bump {dep_finding.package_name} "
                                  f"to {dep_finding.fixed_version}",
                            body=(f"CVE: {dep_finding.cve or dep_finding.id}\n"
                                  f"Manifest: {bump.rel_path}\n"
                                  f"diff sha256: {commit_result.diff_sha256}\n"),
                            push=args.push,
                        )
                        _info(f"PR: {url_or_err}") if ok else _warn(f"PR failed: {url_or_err}")
                else:
                    _warn(f"bump commit failed: {commit_result.error}")
                    state.update_finding_status(dep_finding.id, "failed")
            else:
                check = apply_patch(args.repo, bump.diff, dry_run=True)
                _info(
                    f"Dry-run: bump {dep_finding.package_name} "
                    f"{dep_finding.installed_version} -> {dep_finding.fixed_version} "
                    f"{'passes' if check.success else 'FAILS git apply --check'}"
                )

    # Resolve the finding's final status. --deps manages its own status
    # inside its branch (and may operate on a different finding id), so we
    # never let the generic logic clobber it. --patch and --live each
    # contribute a status; if both run, "failed" wins.
    candidates: list[str] = []
    if patch_status is not None:
        candidates.append(patch_status)
    if live_status is not None:
        candidates.append(live_status)
    if candidates:
        if "failed" in candidates:
            final_status = "failed"
        elif "pending_apply" in candidates and "fixed" not in candidates:
            final_status = "pending_apply"
        else:
            final_status = "fixed"
        state.update_finding_status(finding_id, final_status)
    elif not args.deps:
        # No strategy actually ran (shouldn't happen given the guard above,
        # but stay safe): leave the "fixing" sentinel as "open" again.
        state.update_finding_status(finding_id, "open")

    for result in results:
        artifact_name = f"remediation-{finding_id}-{result.action}.txt"
        artifact_path = state.save_artifact(artifact_name, result.output)
        state.append_remediation_log(
            finding_id,
            action=result.action,
            result=str(artifact_path),
            success=result.success,
        )
        if result.success:
            _info(f"{result.action} completed. Output saved to {artifact_path}")
        else:
            _warn(f"{result.action} failed: {result.error or 'unknown error'}")
            _info(f"Generated prompt/output saved to {artifact_path}")


def cmd_verify(args, config):
    """Verify a finding by replaying its PoC against the running target."""
    from aegis.verify import verify_finding

    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)
    target = next((f for f in findings if f.id == args.finding_id), None)
    if target is None:
        _err(f"Finding '{args.finding_id}' not found in run {state.run_id}.")
        sys.exit(1)

    repo_path = Path(args.repo) if args.repo else None
    result = verify_finding(
        target,
        run_state=state,
        repo_path=repo_path,
        require_rebuilt=not args.no_provenance_check,
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
    """Generate a Markdown report for a run."""
    state = _resolve_run_state(config, args.run)
    findings = _load_findings_objects(state)

    if not findings:
        return

    # Lazy import — report module may be built in parallel
    try:
        from aegis.report import save_reports
    except ImportError:
        _warn("aegis.report module not yet available — generating minimal report.")
        save_reports = None

    if save_reports is not None:
        html_flag = not getattr(args, "no_html", False)
        md_path, json_path = save_reports(state, findings, html=html_flag)
        _info(f"Report written to {md_path}")
        _info(f"JSON report written to {json_path}")
        if html_flag:
            _info(f"HTML report written to {state.run_path / 'report.html'}")
        return
    else:
        # Minimal fallback
        lines = [
            f"# Aegis Security Report — {state.run_id}",
            "",
            f"**Findings:** {len(findings)}",
            "",
            "| ID | Severity | Title | Status |",
            "|---|---|---|---|",
        ]
        for f in findings:
            lines.append(f"| {f.id} | {f.severity.upper()} | {f.title} | {f.status} |")
        lines.append("")
        md = "\n".join(lines)

    report_file = state.report_path
    report_file.write_text(md)
    _info(f"Report written to {report_file}")


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
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # doctor
    sub.add_parser("doctor", help="Validate the Aegis environment")

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
    p_targets_list = targets_sub.add_parser("list", help="List available target packs")
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


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

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
