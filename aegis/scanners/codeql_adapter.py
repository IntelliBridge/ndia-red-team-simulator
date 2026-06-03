"""CodeqlAdapter — SAST via CodeQL (SARIF output)."""

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
    "error": "high", "warning": "medium", "note": "low",
}


def _convert(result: dict, run_id: str) -> AegisFinding:
    rule_id = result.get("ruleId") or "codeql.rule"
    severity = _SEVERITY_MAP.get((result.get("level") or "").lower(), "medium")
    message = (result.get("message") or {}).get("text") or rule_id
    locations = result.get("locations") or []
    phys = (locations[0] if locations else {}).get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri") or "unknown"
    region = phys.get("region") or {}
    start_line = region.get("startLine", 0)
    end_line = region.get("endLine", start_line)
    return AegisFinding(
        id=f"codeql:{rule_id}:{uri}:{start_line}",
        title=rule_id,
        severity=severity,
        finding_type="sast",
        description=message,
        source_tool="codeql",
        source_run_id=run_id,
        affected_component=uri,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        code_locations=[CodeLocation(
            file=uri,
            start_line=start_line,
            end_line=end_line,
        )],
    )


def _extract_results(payload: dict) -> list[dict]:
    results: list[dict] = []
    for run in payload.get("runs") or []:
        results.extend(run.get("results") or [])
    return results


class CodeqlAdapter:
    name = "codeql"
    capabilities = {"sast"}
    default_timeout = 3600

    def adapter_version(self) -> str:
        return cli_version("codeql", first_line=True)

    def health_check(self) -> bool:
        return which_available("codeql")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target

        def parse(proc, run_id):
            payload = json.loads(proc.stdout or "{}")
            return [_convert(r, run_id) for r in _extract_results(payload)]

        return run_cli_scan(
            self, options, run_state,
            argv=["codeql", "database", "analyze", "--format=sarif-latest",
                  target],
            command_str=f"codeql database analyze --format=sarif-latest {target}",
            subdir="codeql", raw_filename="results.sarif",
            parse=parse, parse_error_label="codeql sarif",
        )


register(CodeqlAdapter())
