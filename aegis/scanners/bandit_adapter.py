"""BanditAdapter — Python SAST via the Bandit CLI."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan,
    which_available,
)
from aegis.schema import AegisFinding, CodeLocation, Confidence, Severity

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

_CONFIDENCE_MAP: dict[str, Confidence] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _convert(r: dict, run_id: str) -> AegisFinding:
    filename = r.get("filename") or "unknown"
    line_number = r.get("line_number", 0)
    test_id = r.get("test_id") or "bandit.test"
    severity = _SEVERITY_MAP.get(
        (r.get("issue_severity") or "").upper(), "medium"
    )
    confidence = _CONFIDENCE_MAP.get(
        (r.get("issue_confidence") or "").upper(), "medium"
    )
    return AegisFinding(
        id=f"bandit:{test_id}:{filename}:{line_number}",
        title=r.get("test_name") or test_id,
        severity=severity,
        finding_type="sast",
        description=r.get("issue_text") or test_id,
        source_tool="bandit",
        source_run_id=run_id,
        affected_component=filename,
        confidence=confidence,
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        cwe=(r.get("issue_cwe") or {}).get("id"),
        code_locations=[CodeLocation(
            file=filename,
            start_line=line_number,
            end_line=line_number,
            snippet=r.get("code", ""),
        )],
    )


class BanditAdapter:
    name = "bandit"
    capabilities = {"sast"}
    default_timeout = 600

    def adapter_version(self) -> str:
        return cli_version("bandit", merge_stderr=True)

    def health_check(self) -> bool:
        return which_available("bandit")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target

        def parse(proc: subprocess.CompletedProcess[str],
                  run_id: str) -> list[AegisFinding]:
            payload = json.loads(proc.stdout or "{}")
            return [_convert(r, run_id) for r in payload.get("results", [])]

        return run_cli_scan(
            self, options, run_state,
            argv=["bandit", "-r", "-f", "json", str(target)],
            command_str=f"bandit -r -f json {target}",
            subdir="bandit", raw_filename="results.json",
            parse=parse, parse_error_label="bandit json",
        )


register(BanditAdapter())
