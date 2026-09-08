"""`redsim audit verify` — walks the audit chain and reports integrity.

Full implementation lands in M2; the M0.5 surface here exists so the CLI
subparser is wired and the help text is correct from day one.
"""

from __future__ import annotations

import argparse
import sys

from redsim.config import RedsimConfig

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def cmd_audit_verify(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Verify the integrity of one or more audit chains."""
    from redsim.audit.chain import resolve_writer, verify_chain

    writer = resolve_writer(config)
    chain_ids: list[str]
    if getattr(args, "all", False):
        chain_ids = list(writer.iter_chain_ids())
    elif getattr(args, "run", None):
        chain_ids = [f"run:{args.run}"]
    elif getattr(args, "project", None):
        chain_ids = [f"project:{args.project}"]
    else:
        chain_ids = ["system"]

    if not chain_ids:
        print(f"{_YELLOW}~{_RESET} no chains found")
        sys.exit(0)

    any_broken = False
    for chain_id in chain_ids:
        result = verify_chain(writer.read_chain(chain_id))
        if result.verified:
            print(f"{_GREEN}✓{_RESET} chain {chain_id!r}: {result.count} events verified")
        else:
            any_broken = True
            print(f"{_RED}✗{_RESET} chain {chain_id!r}: broken at seq={result.broken_at} ({result.reason})")
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
