"""`aegis audit verify` — walks the audit chain and reports integrity.

Full implementation lands in M2; the M0.5 surface here exists so the CLI
subparser is wired and the help text is correct from day one.
"""

from __future__ import annotations

import argparse
import sys

from aegis.config import AegisConfig

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def cmd_audit_verify(args: argparse.Namespace, config: AegisConfig) -> None:
    """Verify the integrity of one or more audit chains."""
    from aegis.audit.chain import resolve_writer, verify_chain

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
