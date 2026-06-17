"""NucleiAdapter — DAST via template-based Nuclei."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aegis.scanners.dast_auth import REDACTED, DastAuthError, auth_header
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
        argv = ["nuclei", "-target", target, "-jsonl", "-silent",
                "-t", templates]
        command_str = f"nuclei -target {target} -t {templates}"

        # Authenticated DAST: nuclei natively replays a custom header on
        # every request via ``-H "Name: value"``. The secret lives only in
        # the argv handed to subprocess.run — the recorded ``command_str``
        # carries a redacted copy so logs/artifacts stay secret-free.
        auth = (options.extra or {}).get("auth")
        if auth:
            try:
                header_name, header_value = auth_header(auth)
            except DastAuthError as exc:
                return ScanResult(
                    findings=[], adapter_name=self.name,
                    adapter_version=self.adapter_version(),
                    command_str=command_str,
                    exit_code=-1, error=str(exc),
                )
            argv += ["-H", f"{header_name}: {header_value}"]
            command_str += f' -H "{header_name}: {REDACTED}"'

        return run_cli_scan_jsonl(
            self, options, run_state,
            argv=argv,
            command_str=command_str,
            subdir="nuclei", raw_filename="results.jsonl",
            convert=_convert,
        )


register(NucleiAdapter())
