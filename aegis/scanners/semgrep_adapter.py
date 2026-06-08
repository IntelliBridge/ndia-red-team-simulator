"""SemgrepAdapter — SAST via the Semgrep CLI."""

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
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "low",
}


def _convert(finding: dict, run_id: str) -> AegisFinding:
    extra = finding.get("extra") or {}
    metadata = extra.get("metadata") or {}
    severity = _SEVERITY_MAP.get(
        (extra.get("severity") or "").upper(), "medium"
    )
    start = finding.get("start") or {}
    end = finding.get("end") or {}
    snippet = (extra.get("lines") or "")[:4096]
    rule_id = finding.get("check_id") or "semgrep.rule"
    file_path = finding.get("path") or "unknown"
    return AegisFinding(
        id=f"semgrep:{rule_id}:{file_path}:{start.get('line', 0)}",
        title=metadata.get("title") or rule_id,
        severity=severity,
        finding_type="sast",
        description=extra.get("message") or rule_id,
        source_tool="semgrep",
        source_run_id=run_id,
        affected_component=file_path,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        cwe=(metadata.get("cwe") or [None])[0]
            if isinstance(metadata.get("cwe"), list) else metadata.get("cwe"),
        references=metadata.get("references") or [],
        code_locations=[CodeLocation(
            file=file_path,
            start_line=start.get("line", 0),
            end_line=end.get("line", 0),
            snippet=snippet,
        )],
    )


class SemgrepAdapter:
    name = "semgrep"
    capabilities = {"sast"}
    default_timeout = 600

    def adapter_version(self) -> str:
        return cli_version("semgrep")

    def health_check(self) -> bool:
        return which_available("semgrep")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        repo = options.target
        rules = options.extra.get("rules", "auto")

        def parse(proc, run_id):
            payload = json.loads(proc.stdout or "{}")
            return [_convert(r, run_id) for r in payload.get("results", [])]

        # Persist the raw payload for forensic / re-parse use.
        return run_cli_scan(
            self, options, run_state,
            argv=["semgrep", "--json", "--quiet", f"--config={rules}", str(repo)],
            command_str=f"semgrep --json --config={rules} {repo}",
            subdir="semgrep", raw_filename="results.json",
            parse=parse, parse_error_label="semgrep json",
        )


register(SemgrepAdapter())
