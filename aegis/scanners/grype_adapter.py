"""GrypeAdapter — container/dependency vuln scanning via the Grype CLI."""

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
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NEGLIGIBLE": "low",
    "UNKNOWN": "low",
}


def _convert(m: dict, run_id: str) -> AegisFinding:
    vuln = m.get("vulnerability") or {}
    art = m.get("artifact") or {}
    vuln_id = vuln.get("id") or "GRYPE-UNKNOWN"
    name = art.get("name") or "unknown"
    version = art.get("version")
    severity = _SEVERITY_MAP.get((vuln.get("severity") or "").upper(), "low")
    fixed_versions = (vuln.get("fix") or {}).get("versions") or []
    data_source = vuln.get("dataSource")
    return AegisFinding(
        id=f"grype:{vuln_id}:{name}:{art.get('version', '')}",
        title=f"{vuln_id} in {name}",
        severity=severity,
        finding_type="dependency",
        description=vuln.get("description") or vuln_id,
        source_tool="grype",
        source_run_id=run_id,
        affected_component=name,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        cve=vuln_id if vuln_id.startswith("CVE") else None,
        package_name=name,
        installed_version=version,
        fixed_version=fixed_versions[0] if fixed_versions else None,
        references=[data_source] if data_source else [],
    )


class GrypeAdapter:
    name = "grype"
    capabilities = {"dependency"}
    default_timeout = 900

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["grype", "version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("grype") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"grype -o json {target}"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["grype", "-o", "json", str(target)],
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
                error=f"failed to parse grype json: {exc}",
            )
        findings = [_convert(m, run_state.run_id)
                    for m in payload.get("matches", [])]
        raw_dir = Path(run_state.run_path) / "grype"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.json").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(GrypeAdapter())
