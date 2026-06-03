"""ZapAdapter — DAST via OWASP ZAP (traditional-json report)."""

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
from aegis.schema import AegisFinding, Severity

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

_SEVERITY_MAP: dict[str, Severity] = {
    "3": "high", "2": "medium", "1": "low", "0": "low",
}


def _convert(alert: dict, run_id: str) -> AegisFinding:
    instances = alert.get("instances") or []
    first = instances[0] if instances else {}
    uri = first.get("uri") or alert.get("name") or "unknown"
    severity = _SEVERITY_MAP.get(str(alert.get("riskcode", "")), "medium")
    return AegisFinding(
        id=f'zap:{alert.get("pluginid", "")}:{uri}',
        title=alert.get("name") or "zap.alert",
        severity=severity,
        finding_type="dast",
        description=alert.get("desc") or "",
        source_tool="zap",
        source_run_id=run_id,
        affected_component=uri,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        endpoint=first.get("uri"),
        method=first.get("method"),
        cwe=alert.get("cweid"),
        remediation_steps=alert.get("solution"),
    )


def _extract_alerts(payload: dict) -> list[dict]:
    alerts: list[dict] = []
    for site in payload.get("site") or []:
        alerts.extend(site.get("alerts") or [])
    return alerts


class ZapAdapter:
    name = "zap"
    capabilities = {"dast"}
    default_timeout = 1800

    def adapter_version(self) -> str:
        return cli_version("zap-cli", merge_stderr=True)

    def health_check(self) -> bool:
        return which_available("zap-cli", "zap.sh")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target

        def parse(proc, run_id):
            payload = json.loads(proc.stdout or "{}")
            return [_convert(a, run_id) for a in _extract_alerts(payload)]

        return run_cli_scan(
            self, options, run_state,
            argv=["zap-cli", "report", "-o", "-", "-f", "json", target],
            command_str=f"zap-cli report -o - -f json {target}",
            subdir="zap", raw_filename="report.json",
            parse=parse, parse_error_label="zap json",
        )


register(ZapAdapter())
