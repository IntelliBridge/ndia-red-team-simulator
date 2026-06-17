"""NucleiAdapter — DAST via template-based Nuclei."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan_jsonl,
    which_available,
)
from aegis.schema import AegisFinding, Severity

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": "critical", "high": "high",
    "medium": "medium", "low": "low", "info": "low",
}


def _convert(record: dict, run_id: str) -> AegisFinding:
    info = record.get("info") or {}
    severity = _SEVERITY_MAP.get(
        (info.get("severity") or "").lower(), "medium"
    )
    template_id = record.get("template-id") or "nuclei.template"
    matched_at = record.get("matched-at") or record.get("host", "unknown")
    return AegisFinding(
        id=f"nuclei:{template_id}:{matched_at}",
        title=info.get("name") or template_id,
        severity=severity,
        finding_type="dast",
        description=info.get("description") or "",
        source_tool="nuclei",
        source_run_id=run_id,
        affected_component=matched_at,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        target=record.get("host"),
        endpoint=matched_at,
        references=info.get("reference") or [],
    )


class NucleiAdapter:
    name = "nuclei"
    capabilities = {"dast"}
    default_timeout = 900

    def adapter_version(self) -> str:
        return cli_version("nuclei", subcommand="-version", merge_stderr=True)

    def health_check(self) -> bool:
        return which_available("nuclei")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target
        templates = options.extra.get("templates", "cves,vulnerabilities")
        return run_cli_scan_jsonl(
            self, options, run_state,
            argv=["nuclei", "-target", target, "-jsonl", "-silent",
                  "-t", templates],
            command_str=f"nuclei -target {target} -t {templates}",
            subdir="nuclei", raw_filename="results.jsonl",
            convert=_convert,
        )


register(NucleiAdapter())
