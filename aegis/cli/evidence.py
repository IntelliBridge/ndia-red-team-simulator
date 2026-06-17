"""`aegis evidence-pack` — bundle audit + controls evidence for auditors.

Produces a self-contained directory a SOC 2 / ISO 27001 / FedRAMP reviewer
can inspect: exported audit chains, their integrity verdicts, a controls
crosswalk, a secret-free system summary, and a hashed manifest.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from aegis.cli import _console

if TYPE_CHECKING:
    import argparse

    from aegis.config import AegisConfig


def cmd_evidence_pack(args: argparse.Namespace, config: AegisConfig) -> None:
    """Generate a compliance evidence pack at ``--out``."""
    from aegis.services.evidence import generate_evidence_pack

    out_dir = getattr(args, "out", None)
    if not out_dir:
        _console._err("evidence-pack requires --out DIR")
        sys.exit(2)

    project = getattr(args, "project", None)
    manifest = generate_evidence_pack(out_dir, config=config, project=project)

    # Per-chain verify_chain() verdicts live in verification.json; here we
    # just report the chain count alongside the file count + overall hash.
    _console._info(f"Evidence pack written to {manifest.out_dir}")
    _console._info(f"Aegis version: {manifest.aegis_version}")
    _console._info(f"Audit chains exported: {len(manifest.chains)}")
    _console._info(f"Files in pack: {len(manifest.files)}")
    _console._info(f"Overall pack hash (sha256): {manifest.pack_hash}")
    sys.exit(0)
