"""`aegis migrate` — moves filesystem runs into Postgres."""

from __future__ import annotations

import argparse
import sys

from aegis.config import AegisConfig


def cmd_migrate(args: argparse.Namespace, config: AegisConfig) -> None:
    """Migrate filesystem run data into Postgres."""
    direction = getattr(args, "direction", "fs->pg")
    if direction != "fs->pg":
        print(f"unknown migration direction: {direction!r}", file=sys.stderr)
        sys.exit(2)

    try:
        from aegis.migrate.fs_to_pg import migrate as run_migration
    except ImportError:
        print("aegis.migrate module unavailable.", file=sys.stderr)
        sys.exit(1)

    summary = run_migration(
        source_dir=args.source,
        db_url=getattr(args, "db_url", None),
        project_id=args.project,
        dry_run=getattr(args, "dry_run", False),
    )
    # MigrationSummary is a dataclass; serialise via to_dict() to iterate.
    for k, v in summary.to_dict().items():
        print(f"  {k:<28} {v}")
    sys.exit(0 if not summary.failures else 1)
