"""Scan orchestration service.

Wraps the Phase 2 strix runner + the scanner registry (when M6 lands).
Callable from the CLI, the API, and Celery workers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.config import AegisConfig
from aegis.safety import authorize
from aegis.schema import AegisFinding
from aegis.state import RunState


@dataclass
class ScanOutcome:
    success: bool
    partial_success: bool
    findings: list[AegisFinding]
    scanner: str
    return_code: int | None = None
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def start_scan(
    *,
    run_state: RunState,
    target: str,
    scanner: str = "strix",
    instruction: str | None = None,
    timeout: int = 1800,
    actor: str,
    config: AegisConfig,
    override_authorized: bool = False,
    use_strix: bool = True,
) -> ScanOutcome:
    """Run a scan against ``target`` and return a structured outcome.

    For Phase 2 / 3 the only live scanner is Strix; ``scanner`` is reserved
    for the M6 registry dispatch. When ``use_strix=False`` and an events
    file is later loaded by the caller, this function is a no-op shell that
    still emits the authorization audit so the chain is honest.
    """
    authorize(
        "scan.start",
        target,
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        override_authorized=override_authorized,
        detail={"actor": actor, "scanner": scanner, "target": target,
                "instruction_set": bool(instruction)},
    )

    if not use_strix:
        return ScanOutcome(
            success=True, partial_success=False, findings=[],
            scanner=scanner, return_code=None,
            detail={"mode": "events-only"},
        )

    from aegis.adapters.strix_runner import run_strix
    result = run_strix(
        target, run_state,
        instruction=instruction,
        timeout=timeout,
        strix_command=getattr(config, "strix_command", None),
        strix_path=config.strix_path,
    )
    run_state.save_findings(result.findings)
    return ScanOutcome(
        success=result.success,
        partial_success=result.partial_success,
        findings=result.findings,
        scanner=scanner,
        return_code=result.return_code,
        error=result.error,
        detail={"command": result.command, "log_path": result.log_path,
                "events_path": result.events_path},
    )
