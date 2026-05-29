"""ZapAdapter — DAST via OWASP ZAP (traditional-json report)."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.schema import AegisFinding
from aegis.state import RunState


_SEVERITY_MAP = {
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
        try:
            out = subprocess.run(["zap-cli", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return ((out.stdout or "") + (out.stderr or "")).strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return (shutil.which("zap-cli") is not None
                or shutil.which("zap.sh") is not None)

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"zap-cli report -o - -f json {target}"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["zap-cli", "report", "-o", "-", "-f", "json", target],
                capture_output=True, text=True, timeout=options.timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=command_str,
                exit_code=-1, duration_s=time.monotonic() - started,
                error=str(exc),
            )
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=command_str,
                exit_code=proc.returncode,
                duration_s=time.monotonic() - started,
                error=f"failed to parse zap json: {exc}",
            )
        findings = [_convert(a, run_state.run_id)
                    for a in _extract_alerts(payload)]
        raw_dir = Path(run_state.run_path) / "zap"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "report.json").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(ZapAdapter())
