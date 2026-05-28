"""Aegis service layer.

The service layer is the single source of orchestration logic for scans,
fixes, verification, reporting, and tool execution. The CLI (`aegis/cli.py`),
the FastAPI service (`aegis/api/`), and the Celery workers (`aegis/workers/`)
all call into these functions. They never duplicate logic.

Each service function:

- Takes a ``RunStateAPI`` and an ``actor`` string.
- Routes active operations through ``aegis.safety.authorize``.
- Emits audit events at operation boundaries (M2).
- Returns a structured dataclass result.
"""

from aegis.services.scans import ScanOutcome, start_scan
from aegis.services.fixes import FixOutcome, generate_fix
from aegis.services.verify import VerifyOutcome, verify
from aegis.services.reports import ReportOutcome, render_reports
from aegis.services.tools import ToolOutcome, run_kali_tool

__all__ = [
    "ScanOutcome", "start_scan",
    "FixOutcome", "generate_fix",
    "VerifyOutcome", "verify",
    "ReportOutcome", "render_reports",
    "ToolOutcome", "run_kali_tool",
]
