"""Redsim service layer.

Phase 4 v0.3.1 F6 split:

- **Admission** (``create_*_job``): request-scoped. Runs ``authorize()``
  against the supplied ``audit_writer``, persists Run+Job rows, and
  enqueues the Celery task. Called from API write routes and the CLI's
  ``--api`` dispatch.
- **Execution** (``start_scan`` / ``verify``):
  long-running. Called from Celery workers and (for backward compat)
  the offline CLI.

Both halves live side-by-side in the same module per primitive so the
audit row's detail and the worker's behaviour can be reasoned about
together.

Import boundary (intentional): admission services enqueue Celery tasks
from ``redsim.workers.tasks.*`` and those tasks call back into the
execution halves here. To break that cycle the ``from
redsim.workers.tasks.* import …`` lines stay **function-level** inside the
``create_*_job`` enqueue blocks — they must not be hoisted to module
scope. See the mirror note in ``redsim.workers.tasks``.
"""

from redsim.services.reports import ReportOutcome, render_reports
from redsim.services.runs import CancelOutcome, cancel_run
from redsim.services.scans import JobHandle, ScanOutcome, create_scan_job, start_scan
from redsim.services.verify import VerifyOutcome, create_verify_job, verify

__all__ = [
    "CancelOutcome",
    "JobHandle",
    "ReportOutcome",
    "ScanOutcome",
    "VerifyOutcome",
    "cancel_run",
    "create_scan_job",
    "create_verify_job",
    "render_reports",
    "start_scan",
    "verify",
]
