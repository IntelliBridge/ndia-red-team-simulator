"""`aegis migrate` — moves filesystem runs into Postgres.

Skeleton lands in M0.5 so the subcommand exists; real implementation in M11.
"""

from __future__ import annotations

import sys


def cmd_migrate(args, config) -> None:
    """Migrate filesystem run data into Postgres (M11)."""
    direction = getattr(args, "direction", "fs->pg")
    if direction != "fs->pg":
        print(f"unknown migration direction: {direction!r}", file=sys.stderr)
        sys.exit(2)

    try:
        from aegis.migrate.fs_to_pg import migrate as run_migration  # M11
    except ImportError:
        print("aegis migrate lands in M11; skeleton in place.")
        sys.exit(0)

    summary = run_migration(
        source_dir=args.source,
        db_url=getattr(args, "db_url", None),
        project_id=args.project,
        dry_run=getattr(args, "dry_run", False),
    )
    for k, v in summary.items():
        print(f"  {k:<28} {v}")
    sys.exit(0)
