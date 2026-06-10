"""Aegis security platform — main CLI entry point.

Usage:
    python -m aegis.cli <command> [options]
    python aegis/cli.py <command> [options]
"""

from __future__ import annotations

import argparse
import json  # noqa: F401  (re-exported for test patch target aegis.cli.main.json)
import sys
from pathlib import Path  # noqa: F401  (re-exported for test patch target aegis.cli.main.Path)

# Console output (ANSI colours + ``[*]``/``[!]`` writers) lives in a dedicated
# peer module now; ``main()`` and every per-command module call through it so
# there is one place to patch console I/O. Run-state resolution likewise moved
# to ``aegis.cli._runstate``.
from aegis.cli import _console

# ``json``, ``Path`` and ``open`` are referenced by the per-command sibling
# modules via this module (e.g. ``aegis.cli.main.open``) so that the existing
# tests can monkeypatch them at ``aegis.cli.main``. ``open`` is the builtin,
# re-bound here only to expose it as a real, importable module attribute.
open = open  # noqa: A001  (intentional builtin re-export for the scan fixture loader)


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
    p_scan.add_argument("--scanner", default="strix",
                        help="Registered scanner adapter to dispatch (default: strix)")
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

    # plugins (community adapter marketplace)
    p_plugins = sub.add_parser("plugins", help="Inspect community scanner/agent adapters")
    plugins_sub = p_plugins.add_subparsers(dest="plugins_action", required=True)
    p_plugins_list = plugins_sub.add_parser(
        "list", help="List discovered third-party plugins (AEGIS_PLUGINS=1)")
    p_plugins_list.add_argument("--json", action="store_true",
                                help="Emit the discovery report as a JSON array")
    p_plugins_sign = plugins_sub.add_parser(
        "sign",
        help="Sign a plugin distribution with an Ed25519 key (produces a .sig)")
    p_plugins_sign.add_argument("--dist", required=True,
                                help="Distribution name to sign (e.g. aegis-plugin-example)")
    p_plugins_sign.add_argument("--version", default=None,
                                help="Distribution version (omit for unversioned)")
    p_plugins_sign.add_argument("--entry-point", dest="entry_point", required=True,
                                help="Entry point GROUP:NAME whose factory is signed "
                                     "(e.g. aegis.scanners:example)")
    p_plugins_sign.add_argument("--key", required=True,
                                help="Path to the Ed25519 private key PEM")
    p_plugins_sign.add_argument("--out", default=None,
                                help="Output directory for the .sig (default: cwd)")

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
# Command re-exports + dispatch table
#
# Each command body now lives in its own per-command sibling module
# (``aegis.cli.scan``, ``aegis.cli.fix``, …), mirroring the already-extracted
# ``status`` / ``audit`` / ``migrate`` / ``ci_gate`` siblings. The bodies are
# re-imported here so that ``aegis.cli.main.cmd_<name>`` keeps resolving for
# external importers (``aegis.cli.__init__``), for ``cmd_pipeline``'s
# in-namespace lookups, and for tests that import or monkeypatch the commands
# at ``aegis.cli.main``.
# ---------------------------------------------------------------------------
from aegis.cli.demo import cmd_demo  # noqa: E402
from aegis.cli.doctor import cmd_doctor  # noqa: E402
from aegis.cli.export import cmd_export  # noqa: E402
from aegis.cli.findings import cmd_findings  # noqa: E402
from aegis.cli.fix import cmd_fix  # noqa: E402
from aegis.cli.init import cmd_init  # noqa: E402
from aegis.cli.pipeline import cmd_pipeline  # noqa: E402
from aegis.cli.report import cmd_report  # noqa: E402
from aegis.cli.scan import cmd_scan  # noqa: E402
from aegis.cli.targets import cmd_targets  # noqa: E402
from aegis.cli.verify import cmd_verify  # noqa: E402

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
        _console._err(f"Unknown audit action: {args.audit_action}")
        sys.exit(2)


def _cmd_migrate_dispatch(args, config):
    from aegis.cli.migrate import cmd_migrate
    cmd_migrate(args, config)


def _cmd_ci_gate_dispatch(args, config):
    from aegis.cli.ci_gate import cmd_ci_gate
    cmd_ci_gate(args, config)


def _cmd_plugins_dispatch(args, config):
    from aegis.cli.plugins import cmd_plugins
    cmd_plugins(args, config)


_COMMANDS["status"] = _cmd_status_dispatch
_COMMANDS["audit"] = _cmd_audit_dispatch
_COMMANDS["migrate"] = _cmd_migrate_dispatch
_COMMANDS["ci-gate"] = _cmd_ci_gate_dispatch
_COMMANDS["plugins"] = _cmd_plugins_dispatch


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
                _console._err(f"--dry-run cannot be combined with --{mutating.replace('_','-')}")
                sys.exit(2)
        # Refuse any subcommand that mutates Docker state.
        if args.command == "targets":
            action = getattr(args, "targets_action", None)
            if action in ("up", "down", "rebuild"):
                _console._err(f"--dry-run cannot be combined with `targets {action}` "
                              f"(would mutate Docker state)")
                sys.exit(2)
        # demo without --apply is read-only; demo --apply was already caught
        # above. Other mutating subcommands should add a similar gate.

    if getattr(args, "global_verbose", False):
        _console._info(f"config={args.config or '<auto>'}")

    from aegis.config import load_config

    config = load_config(args.config)

    handler = _COMMANDS.get(args.command)
    if handler is None:
        _console._err(f"Unknown command: {args.command}")
        sys.exit(1)

    handler(args, config)


if __name__ == "__main__":
    main()
