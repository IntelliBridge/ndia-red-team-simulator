"""`redsim audit verify` — walks the audit chain and reports integrity.

Where the chain is read from:

- By default the writer ``resolve_writer(config)`` picks: Postgres when
  ``REDSIM_DB_URL`` is set, else the per-chain files under
  ``<output_dir>/audit/`` (``run__<id>.jsonl``, ``project__<id>.jsonl``,
  ``system.jsonl``).
- ``redsim ml attack`` runs offline and writes its whole chain
  ``run:<run_id>`` to one file, ``<out>/<run_id>/audit.jsonl``, which the
  default writer cannot see. ``--run <id>`` therefore falls back to
  ``<output_dir>/<id>/audit.jsonl`` when the primary store has no events
  for that run, and ``--run-dir PATH`` points at a run directory (or the
  ``.jsonl`` file itself) explicitly, for runs written with ``--out``
  somewhere else. The printed ``redsim audit verify --run <id>`` from
  ``redsim ml attack`` works unpatched in the common case.

An explicitly named chain (``--run`` / ``--project``) with no events
anywhere exits 1: "0 events verified" for a run id that does not exist is
not a pass. ``--all`` over an empty store and the implicit ``system``
chain keep their existing exit-0 behaviour.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redsim.cli import _console
from redsim.config import RedsimConfig

if TYPE_CHECKING:
    from redsim.audit.chain import AuditWriter

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"

#: Filename of the single-file chain an offline run directory carries
#: (``redsim.ml.campaign_adapter.AUDIT_FILE_NAME`` and the Phase 2/3
#: ``authorize(run_path=…)`` layout both use it).
OFFLINE_AUDIT_FILE = "audit.jsonl"

EXIT_USAGE = 2


def _output_dir(config: RedsimConfig) -> Path:
    return Path(str(getattr(config, "output_dir", None) or "redsim_output"))


def _offline_run_audit_path(config: RedsimConfig, run_id: str) -> Path | None:
    """``<output_dir>/<run_id>/audit.jsonl`` when it exists, else ``None``."""
    candidate = _output_dir(config) / run_id / OFFLINE_AUDIT_FILE
    return candidate if candidate.is_file() else None


def _single_file_writer(path: Path) -> AuditWriter:
    """A reader over one single-file chain.

    ``path`` is either the run directory holding ``audit.jsonl`` or the
    ``.jsonl`` file itself. Callers check existence first: the writer's
    constructor creates its directory.
    """
    from redsim.audit.chain import JsonlAuditWriter

    if path.is_dir():
        return JsonlAuditWriter(path, single_file=OFFLINE_AUDIT_FILE)
    return JsonlAuditWriter(path.parent, single_file=path.name)


def _resolve_run_dir(raw: str) -> Path:
    """Validate ``--run-dir`` and return the audit file it names (exit 2 otherwise)."""
    path = Path(raw).expanduser()
    if path.is_dir():
        audit = path / OFFLINE_AUDIT_FILE
        if not audit.is_file():
            _console._err(f"--run-dir {path}: no {OFFLINE_AUDIT_FILE} in that directory")
            sys.exit(EXIT_USAGE)
        return audit
    if path.is_file():
        return path
    _console._err(f"--run-dir {path}: no such directory or file")
    sys.exit(EXIT_USAGE)


def _describe(writer: Any) -> str:
    directory = getattr(writer, "directory", None)
    if directory is not None:
        return str(directory)
    return type(writer).__name__


def cmd_audit_verify(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Verify the integrity of one or more audit chains."""
    from redsim.audit.chain import resolve_writer, verify_chain

    run_id = getattr(args, "run", None)
    project_id = getattr(args, "project", None)
    run_dir = getattr(args, "run_dir", None)

    # Where events come from. ``--run-dir`` names the offline file directly
    # and bypasses the primary store. Otherwise the primary store is read and
    # ``--run`` may fall back to the offline file under ``<output_dir>``.
    writer: AuditWriter
    offline_path: Path | None = None
    if run_dir:
        offline_path = _resolve_run_dir(run_dir)
        writer = _single_file_writer(offline_path)
        source = str(offline_path)
    else:
        writer = resolve_writer(config)
        source = _describe(writer)
    fallback = _offline_run_audit_path(config, run_id) if (run_id and not run_dir) else None

    chain_ids: list[str]
    if getattr(args, "all", False):
        chain_ids = list(writer.iter_chain_ids())
    elif run_id:
        chain_ids = [f"run:{run_id}"]
    elif project_id:
        chain_ids = [f"project:{project_id}"]
    elif run_dir:
        # Every chain the offline file carries (normally just run:<run_id>).
        chain_ids = list(writer.iter_chain_ids())
    else:
        chain_ids = ["system"]

    if not chain_ids:
        print(f"{_YELLOW}~{_RESET} no chains found in {source}")
        sys.exit(0)

    explicit = bool(run_id or project_id)
    any_broken = False
    for chain_id in chain_ids:
        used = source
        try:
            events = list(writer.read_chain(chain_id))
        except Exception as exc:  # noqa: BLE001 - fall back to the offline file when we have one
            if fallback is None:
                raise
            print(f"{_YELLOW}~{_RESET} chain {chain_id!r}: primary audit store unavailable "
                  f"({type(exc).__name__}); reading offline chain {fallback}")
            events = []
        if not events and fallback is not None:
            events = list(_single_file_writer(fallback).read_chain(chain_id))
            used = str(fallback)
            if events:
                print(f"{_YELLOW}~{_RESET} chain {chain_id!r}: not in {source}; "
                      f"using offline chain {fallback}")
        if not events and explicit:
            any_broken = True
            looked = source
            hint = ""
            if run_id and not run_dir:
                candidate = _output_dir(config) / run_id / OFFLINE_AUDIT_FILE
                looked = f"{source} and {candidate}"
                hint = " (pass --run-dir <out>/<run_id> for a run written with --out elsewhere)"
            print(f"{_RED}✗{_RESET} chain {chain_id!r}: no events found in {looked}{hint}")
            continue
        result = verify_chain(events)
        where = f" ({used})" if used != source or run_dir else ""
        if result.verified:
            print(f"{_GREEN}✓{_RESET} chain {chain_id!r}: {result.count} events verified{where}")
        else:
            any_broken = True
            print(f"{_RED}✗{_RESET} chain {chain_id!r}: broken at seq={result.broken_at} "
                  f"({result.reason}){where}")
    sys.exit(1 if any_broken else 0)


def cmd_audit_export(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Export audit chains to the WORM (Object-Lock) bucket on demand.

    ``--all`` exports every chain; ``--chain CHAIN_ID`` exports one.
    ``--no-verify`` skips the hash-chain verification before archiving
    (chains are still archived, just not flagged). When WORM is disabled or
    misconfigured we print an actionable message and exit non-zero.
    """
    from redsim.audit.chain import resolve_writer, verify_chain
    from redsim.storage.worm import WormArchive, worm_export_enabled

    if not worm_export_enabled():
        print(f"{_RED}✗{_RESET} WORM export is disabled. Set REDSIM_WORM_EXPORT=1 "
              f"and the REDSIM_WORM_*/REDSIM_S3_* env (bucket must have Object "
              f"Lock enabled) to enable tamper-evident archival.")
        sys.exit(1)

    try:
        archive = WormArchive.from_env()
    except Exception as exc:  # noqa: BLE001 - surface the misconfig actionably
        print(f"{_RED}✗{_RESET} could not initialise WORM archive: {exc}")
        sys.exit(1)

    writer = resolve_writer(config)
    verify = not getattr(args, "no_verify", False)

    if getattr(args, "chain", None):
        chain_id = args.chain
        events = list(writer.read_chain(chain_id))
        if not events:
            print(f"{_YELLOW}~{_RESET} chain {chain_id!r}: no events; nothing to export")
            sys.exit(0)
        verified = True
        broken: list[str] = []
        if verify:
            result = verify_chain(events)
            verified = result.verified
            if not verified:
                broken.append(chain_id)
        ref = archive.archive_chain(chain_id, events, verified=verified)
        if ref is None:
            print(f"{_YELLOW}~{_RESET} chain {chain_id!r}: already archived (no-op)")
        else:
            print(f"{_GREEN}✓{_RESET} chain {chain_id!r}: archived "
                  f"{len(events)} events ({ref.size_bytes} bytes) -> {ref.location}")
        if broken:
            print(f"{_RED}!{_RESET} chain {chain_id!r} failed verification "
                  f"(archived anyway, flagged verified=False)")
        sys.exit(0)

    # Default / --all: export every chain.
    summary = archive.export_all(writer, verify=verify)
    print(f"{_GREEN}✓{_RESET} WORM export to bucket {archive.bucket!r}:")
    print(f"    chains: {summary.chains_total} total, "
          f"{summary.chains_archived} archived, {summary.chains_skipped} skipped")
    print(f"    objects written: {summary.objects_written}  "
          f"bytes: {summary.bytes_written}")
    if summary.broken_chains:
        print(f"{_RED}!{_RESET} broken chains archived (flagged verified=False): "
              f"{', '.join(summary.broken_chains)}")
    sys.exit(0)
