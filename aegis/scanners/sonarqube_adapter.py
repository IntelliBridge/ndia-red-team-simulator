"""SonarQubeAdapter — SAST via sonar-scanner + the SonarQube issues API."""

from __future__ import annotations

import os
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
        return cli_version("sonar-scanner", first_line=True)

    def health_check(self) -> bool:
        return which_available("sonar-scanner")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
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
        args = ["sonar-scanner", f"-Dsonar.host.url={host}",
                f"-Dsonar.projectBaseDir={target}"]
        if token:
            args.append(f"-Dsonar.token={token}")

        # Best-effort: issues are fetched from the web API by a later step, so
        # the CLI run persists nothing and yields no findings here.
        def parse(proc, run_id):
            return []

        return run_cli_scan(
            self, options, run_state,
            argv=args,
            command_str=f"sonar-scanner -Dsonar.host.url={host}",
            parse=parse,
        )


register(SonarQubeAdapter())
