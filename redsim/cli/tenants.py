"""`redsim tenants verify` — on-demand tenant-isolation reconciliation.

Runs the same scan as the ``redsim.verify_tenant_integrity`` beat task
(``redsim.workers.tasks.tenant_reconcile``) but synchronously, against the
configured Postgres, for an operator who wants an immediate answer. Reports any
row whose denormalized ``org_id`` disagrees with its project's owning org and
exits non-zero when drift is found (so it can gate a CI/ops check).

``--repair`` rewrites each drifted row's ``org_id`` to the project's value; the
0009 ``BEFORE UPDATE`` trigger permits this because the new value matches the
expected org exactly.
"""

from __future__ import annotations

import argparse
import sys

from redsim.config import RedsimConfig

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def cmd_tenants_verify(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Scan the scoped tables for ``org_id`` drift; exit 1 if any is found."""
    # Deferred imports: sqlalchemy / DB session aren't installed on the offline
    # CLI path, and resolving the engine eagerly would break ``redsim --help``.
    from redsim.db.session import get_session
    from redsim.workers.tasks.tenant_reconcile import (
        verify_tenant_integrity_in_session,
    )

    repair = getattr(args, "repair", False)
    try:
        with get_session() as sess:
            report = verify_tenant_integrity_in_session(sess, repair=repair)
    except Exception as exc:  # noqa: BLE001 - surface the misconfig actionably
        print(f"{_RED}✗{_RESET} could not run tenant reconciliation: {exc}")
        print("    Set REDSIM_DB_URL to a Postgres instance and run "
              "`alembic upgrade head` first.")
        sys.exit(1)

    if report.ok:
        scanned = ", ".join(f"{t}={n}" for t, n in report.per_table.items())
        print(f"{_GREEN}✓{_RESET} tenant integrity clean: no org_id drift "
              f"({scanned})")
        sys.exit(0)

    verb = "repaired" if repair else "found"
    print(f"{_RED}✗{_RESET} tenant integrity: {report.total} drifted "
          f"row(s) {verb}")
    for drift in report.drifts:
        print(f"    {drift.table} id={drift.row_id} "
              f"project={drift.project_id} "
              f"org_id={drift.stored_org_id!r} "
              f"expected={drift.expected_org_id!r}")
    if not repair:
        print(f"{_YELLOW}~{_RESET} re-run with --repair to backfill org_id "
              f"from each row's project.")
    # Even after a repair, exit non-zero so the drift is not silently swallowed
    # by a CI gate — the operator should investigate the root cause.
    sys.exit(1)
