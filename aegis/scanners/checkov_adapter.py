"""CheckovAdapter — IaC misconfiguration scanning via the Checkov CLI."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.schema import AegisFinding, CodeLocation
from aegis.state import RunState

_SEVERITY_MAP = {
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
        try:
            out = subprocess.run(["checkov", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return ((out.stdout or "") + (out.stderr or "")).strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("checkov") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"checkov -o json -d {target}"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["checkov", "-o", "json", "-d", str(target)],
                capture_output=True, text=True, timeout=options.timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=command_str,
                exit_code=-1,
                duration_s=time.monotonic() - started,
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
                error=f"failed to parse checkov json: {exc}",
            )
        results = payload.get("results") or {}
        findings = [_convert(c, run_state.run_id)
                    for c in results.get("failed_checks", [])]
        raw_dir = Path(run_state.run_path) / "checkov"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.json").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(CheckovAdapter())
