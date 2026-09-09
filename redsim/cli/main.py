"""Redsim security platform — main CLI entry point.

Usage:
    python -m redsim.cli <command> [options]
    python redsim/cli.py <command> [options]
"""
# ruff: noqa: E402  (this module re-exports the subcommand entry points after the parser is
#                    defined; the late imports avoid a circular import with redsim.cli.<subcommand>)

from __future__ import annotations

import argparse
import builtins
import json  # noqa: F401  (re-exported for test patch target redsim.cli.main.json)
import sys
from pathlib import Path  # noqa: F401  (re-exported for test patch target redsim.cli.main.Path)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redsim.config import RedsimConfig

# Console output (ANSI colours + ``[*]``/``[!]`` writers) lives in a dedicated
# peer module now; ``main()`` and every per-command module call through it so
# there is one place to patch console I/O. Run-state resolution likewise moved
# to ``redsim.cli._runstate``.
from redsim.cli import _console

# ``json``, ``Path`` and ``open`` are referenced by the per-command sibling
# modules via this module (e.g. ``redsim.cli.main.open``) so that the existing
# tests can monkeypatch them at ``redsim.cli.main``. ``open`` is the builtin,
# re-bound here only to expose it as a real, importable module attribute.
open = builtins.open


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redsim",
        description="Redsim — adversarial-ML red-team simulator (platform CLI)",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to redsim.yaml config file",
        default=None,
    )
    parser.add_argument(
        "--dry-run", dest="global_dry_run", action="store_true",
        help="Refuse destructive operations across all subcommands.",
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
        help="Route commands through REDSIM_API_URL instead of the local "
             "filesystem (Phase 3). Equivalent to REDSIM_MODE=api.",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # doctor
    p_doctor = sub.add_parser("doctor", help="Validate the Redsim environment")
    p_doctor.add_argument("--api-mode", dest="api_mode", action="store_true",
                          help="Also probe DB, blob backend, OIDC issuer (Phase 3)")

    # init
    sub.add_parser("init", help="Create a default redsim.yaml in the current directory")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a target through a registered attack adapter")
    p_scan.add_argument("target_url", help="Target URL to scan")
    p_scan.add_argument("--scanner", required=True,
                        help="Registered scanner / attack adapter to dispatch. There is "
                             "no default: ML attack adapters register via redsim.ml.attacks "
                             "(`redsim plugins list` shows third-party adapters).")
    p_scan.add_argument("--instruction", default=None,
                        help="Free-text scope/rules-of-engagement instruction")
    p_scan.add_argument("--timeout", type=int, default=1800,
                        help="Adapter run timeout in seconds (default: 1800)")
    p_scan.add_argument("--i-understand-this-target-is-authorized",
                        dest="override_authorized", action="store_true",
                        help="Authorize a target outside the allowlist")

    # findings
    p_findings = sub.add_parser("findings", help="List findings from a run")
    p_findings.add_argument("--run", help="Run ID (default: latest)", default=None)

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
    p_audit_verify.add_argument("--run-dir", dest="run_dir", default=None, metavar="PATH",
                                help="Verify the offline single-file chain at PATH/audit.jsonl "
                                     "(the layout `redsim ml attack` writes under <out>/<run_id>/). "
                                     "PATH may also be the .jsonl file itself")
    p_audit_export = audit_sub.add_parser(
        "export", help="Export audit chains to the WORM (Object-Lock) bucket")
    p_audit_export.add_argument("--all", action="store_true",
                                help="Export every chain known to the writer (default)")
    p_audit_export.add_argument("--chain", default=None,
                                help="Export a single chain by id (e.g. run:<id>, "
                                     "project:<id>, or system)")
    p_audit_export.add_argument("--no-verify", dest="no_verify", action="store_true",
                                help="Skip hash-chain verification before archiving")

    # tenants (multi-tenancy — org_id integrity reconciliation)
    p_tenants = sub.add_parser("tenants", help="Multi-tenancy maintenance operations")
    tenants_sub = p_tenants.add_subparsers(dest="tenants_action", required=True)
    p_tenants_verify = tenants_sub.add_parser(
        "verify",
        help="Reconcile denormalized org_id against each row's project "
             "(detects tenant drift); exits non-zero if any is found")
    p_tenants_verify.add_argument(
        "--repair", action="store_true",
        help="Backfill each drifted row's org_id from its project "
             "(default: report only)")

    # plugins (community adapter marketplace)
    p_plugins = sub.add_parser("plugins", help="Inspect community scanner/attack adapters")
    plugins_sub = p_plugins.add_subparsers(dest="plugins_action", required=True)
    p_plugins_list = plugins_sub.add_parser(
        "list", help="List discovered third-party plugins (REDSIM_PLUGINS=1)")
    p_plugins_list.add_argument("--json", action="store_true",
                                help="Emit the discovery report as a JSON array")
    p_plugins_sign = plugins_sub.add_parser(
        "sign",
        help="Sign a plugin distribution with an Ed25519 key (produces a .sig)")
    p_plugins_sign.add_argument("--dist", required=True,
                                help="Distribution name to sign (e.g. redsim-plugin-example)")
    p_plugins_sign.add_argument("--version", default=None,
                                help="Distribution version (omit for unversioned)")
    p_plugins_sign.add_argument("--entry-point", dest="entry_point", required=True,
                                help="Entry point GROUP:NAME whose factory is signed "
                                     "(e.g. redsim.scanners:example)")
    p_plugins_sign.add_argument("--key", required=True,
                                help="Path to the Ed25519 private key PEM")
    p_plugins_sign.add_argument("--out", default=None,
                                help="Output directory for the .sig (default: cwd)")

    # ml (adversarial-ML vertical): `redsim ml build-assets | attack | seed`
    from redsim.cli.ml import add_ml_subparser
    add_ml_subparser(sub)

    # evidence-pack — bundle audit + controls evidence for auditors
    p_evidence = sub.add_parser(
        "evidence-pack",
        help="Bundle audit + controls evidence for SOC 2 / ISO 27001 / FedRAMP reviewers",
    )
    p_evidence.add_argument("--out", required=True,
                            help="Output directory for the evidence pack")
    p_evidence.add_argument("--project", default=None,
                            help="Limit the pack to a single project's chain")

    # migrate (Phase 3 M11 — surface lands now, impl in M11)
    p_migrate = sub.add_parser("migrate", help="Move filesystem run data into Postgres (M11)")
    p_migrate.add_argument("direction", choices=["fs->pg"], default="fs->pg", nargs="?",
                           help="Migration direction (only fs->pg in Phase 3)")
    p_migrate.add_argument("--source", required=True,
                           help="Path to redsim_output/ on disk")
    p_migrate.add_argument("--project", required=True,
                           help="Target project slug or id")
    p_migrate.add_argument("--db-url", dest="db_url", default=None,
                           help="Override REDSIM_DB_URL for this migration")
    p_migrate.add_argument("--dry-run", dest="dry_run", action="store_true",
                           help="Print planned counts without writing")

    return parser


# ---------------------------------------------------------------------------
# Command re-exports + dispatch table
#
# Each command body now lives in its own per-command sibling module
# (``redsim.cli.scan``, ``redsim.cli.verify``, …), mirroring the already-extracted
# ``status`` / ``audit`` / ``migrate`` siblings. The bodies are
# re-imported here so that ``redsim.cli.main.cmd_<name>`` keeps resolving for
# external importers (``redsim.cli.__init__``) and for tests that import or
# monkeypatch the commands at ``redsim.cli.main``.
# ---------------------------------------------------------------------------
from redsim.cli.doctor import cmd_doctor
from redsim.cli.findings import cmd_findings
from redsim.cli.init import cmd_init
from redsim.cli.report import cmd_report
from redsim.cli.scan import cmd_scan
from redsim.cli.verify import cmd_verify

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_COMMANDS = {
    "doctor": cmd_doctor,
    "init": cmd_init,
    "scan": cmd_scan,
    "findings": cmd_findings,
    "verify": cmd_verify,
    "report": cmd_report,
}


def _cmd_status_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.status import cmd_status
    cmd_status(args, config)


def _cmd_audit_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.audit import cmd_audit_export, cmd_audit_verify
    if args.audit_action == "verify":
        cmd_audit_verify(args, config)
    elif args.audit_action == "export":
        cmd_audit_export(args, config)
    else:
        _console._err(f"Unknown audit action: {args.audit_action}")
        sys.exit(2)


def _cmd_migrate_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.migrate import cmd_migrate
    cmd_migrate(args, config)


def _cmd_evidence_pack_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.evidence import cmd_evidence_pack
    cmd_evidence_pack(args, config)


def _cmd_plugins_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.plugins import cmd_plugins
    cmd_plugins(args, config)


def _cmd_ml_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.ml import cmd_ml
    cmd_ml(args, config)


def _cmd_tenants_dispatch(args: argparse.Namespace, config: RedsimConfig) -> None:
    from redsim.cli.tenants import cmd_tenants_verify
    if args.tenants_action == "verify":
        cmd_tenants_verify(args, config)
    else:
        _console._err(f"Unknown tenants action: {args.tenants_action}")
        sys.exit(2)


_COMMANDS["status"] = _cmd_status_dispatch
_COMMANDS["audit"] = _cmd_audit_dispatch
_COMMANDS["migrate"] = _cmd_migrate_dispatch
_COMMANDS["evidence-pack"] = _cmd_evidence_pack_dispatch
_COMMANDS["plugins"] = _cmd_plugins_dispatch
_COMMANDS["tenants"] = _cmd_tenants_dispatch
_COMMANDS["ml"] = _cmd_ml_dispatch


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # F4: --api sets REDSIM_MODE=api for the rest of the process so the
    # api_client + status + downstream calls all agree on the mode.
    if getattr(args, "global_api", False):
        import os
        os.environ["REDSIM_MODE"] = "api"

    # Union the global flags with subcommand-specific equivalents.
    if getattr(args, "global_override_authorized", False):
        args.override_authorized = True
    # ``--dry-run`` is a global refusal flag. The pentest subcommands that
    # carried the conflicting mutating flags (--apply / --push / --open-pr)
    # were removed with the pentest domain, so there is nothing to cross-check
    # here; subcommands read ``args.global_dry_run`` themselves when they
    # grow a mutating step (the ML attack adapters' gated actions).

    if getattr(args, "global_verbose", False):
        _console._info(f"config={args.config or '<auto>'}")

    from redsim.config import load_config

    config = load_config(args.config)

    handler = _COMMANDS.get(args.command)
    if handler is None:
        _console._err(f"Unknown command: {args.command}")
        sys.exit(1)

    handler(args, config)


if __name__ == "__main__":
    main()
