"""CheckovAdapter — IaC misconfiguration scanning via the Checkov CLI."""

from __future__ import annotations

import json
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
from aegis.schema import AegisFinding, CodeLocation, Severity

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _convert(c: dict, run_id: str) -> AegisFinding:
    check_id = c.get("check_id") or "checkov.check"
    file_path = c.get("file_path") or "unknown"
    resource = c.get("resource") or ""
    severity = _SEVERITY_MAP.get((c.get("severity") or "").upper(), "medium")
    title = c.get("check_name") or check_id
    line_range = c.get("file_line_range") or []
    code_locations = None
    if line_range:
        code_locations = [CodeLocation(
            file=file_path,
            start_line=line_range[0],
            end_line=line_range[-1],
        )]
    return AegisFinding(
        id=f"checkov:{check_id}:{file_path}:{resource}",
        title=title,
        severity=severity,
        finding_type="config",
        description=c.get("check_name") or check_id,
        source_tool="checkov",
        source_run_id=run_id,
        affected_component=file_path,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        references=[c["guideline"]] if c.get("guideline") else [],
        code_locations=code_locations,
    )


class CheckovAdapter:
    name = "checkov"
    capabilities = {"iac"}
    default_timeout = 600

    def adapter_version(self) -> str:
        return cli_version("checkov", merge_stderr=True)

    def health_check(self) -> bool:
        return which_available("checkov")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target

        def parse(proc, run_id):
            payload = json.loads(proc.stdout or "{}")
            results = payload.get("results") or {}
            return [_convert(c, run_id)
                    for c in results.get("failed_checks", [])]

        return run_cli_scan(
            self, options, run_state,
            argv=["checkov", "-o", "json", "-d", str(target)],
            command_str=f"checkov -o json -d {target}",
            subdir="checkov", raw_filename="results.json",
            parse=parse, parse_error_label="checkov json",
        )


register(CheckovAdapter())
