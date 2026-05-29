"""SonarQubeAdapter — SAST via sonar-scanner + the SonarQube issues API."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from datetime import datetime, timezone

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.schema import AegisFinding
from aegis.state import RunState


_SEVERITY_MAP = {
    "BLOCKER": "critical",
    "CRITICAL": "high",
    "MAJOR": "medium",
    "MINOR": "low",
    "INFO": "low",
}


def _convert(issue: dict, run_id: str) -> AegisFinding:
    key = issue.get("key") or "unknown"
    rule = issue.get("rule") or "sonarqube.rule"
    severity = _SEVERITY_MAP.get((issue.get("severity") or "").upper(), "medium")
    message = issue.get("message")
    component = issue.get("component") or "unknown"
    return AegisFinding(
        id=f"sonarqube:{key}",
        title=message or rule,
        severity=severity,
        finding_type="sast",
        description=message or rule,
        source_tool="sonarqube",
        source_run_id=run_id,
        affected_component=component,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


class SonarQubeAdapter:
    name = "sonarqube"
    capabilities = {"sast"}
    default_timeout = 1800

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["sonar-scanner", "--version"],
                                 capture_output=True, text=True, timeout=3,
                                 check=False)
            return (out.stdout or "").strip().splitlines()[0] \
                if (out.stdout or "").strip() else "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("sonar-scanner") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        host = options.extra.get("sonar_host_url") or os.environ.get("SONAR_HOST_URL")
        token = options.extra.get("sonar_token") or os.environ.get("SONAR_TOKEN")
        if not host:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str="sonar-scanner",
                error="no SONAR_HOST_URL configured",
            )
        target = options.target
        command_str = f"sonar-scanner -Dsonar.host.url={host}"
        started = time.monotonic()
        try:
            args = ["sonar-scanner", f"-Dsonar.host.url={host}",
                    f"-Dsonar.projectBaseDir={target}"]
            if token:
                args.append(f"-Dsonar.token={token}")
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=options.timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=command_str,
                exit_code=-1, duration_s=time.monotonic() - started,
                error=str(exc),
            )
        # Best-effort: issues are fetched from the web API by a later step;
        # the offline path drives _convert directly.
        return ScanResult(
            findings=[], adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(SonarQubeAdapter())
