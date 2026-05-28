"""Verification orchestration service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.config import AegisConfig
from aegis.safety import authorize
from aegis.schema import AegisFinding
from aegis.state import RunState
from aegis.verify import verify_finding


@dataclass
class VerifyOutcome:
    finding_id: str
    status: str         # "verified" | "still_vulnerable" | "inconclusive"
    strategy: str
    evidence: dict[str, Any]
    notes: str


def verify(
    *,
    run_state: RunState,
    finding: AegisFinding,
    repo_path: Path | None,
    require_rebuilt: bool = True,
    require_source_rebuild: bool = True,
    actor: str,
    config: AegisConfig,
) -> VerifyOutcome:
    authorize(
        "verify.replay",
        finding.target or "localhost",
        allowlist=config.target_allowlist,
        run_path=run_state.run_path,
        detail={"actor": actor, "finding_id": finding.id,
                "require_rebuilt": require_rebuilt,
                "require_source_rebuild": require_source_rebuild},
    )
    result = verify_finding(
        finding,
        run_state=run_state,
        repo_path=repo_path,
        require_rebuilt=require_rebuilt,
        require_source_rebuild=require_source_rebuild,
    )
    return VerifyOutcome(
        finding_id=result.finding_id,
        status=result.status,
        strategy=result.strategy,
        evidence=result.evidence,
        notes=result.notes,
    )
