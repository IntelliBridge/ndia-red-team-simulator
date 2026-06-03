"""GrypeAdapter — container/dependency vuln scanning via the Grype CLI."""

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
from aegis.scanners.severity import canon_severity
from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.state import RunStateAPI


def _convert(m: dict, run_id: str) -> AegisFinding:
    vuln = m.get("vulnerability") or {}
    art = m.get("artifact") or {}
    vuln_id = vuln.get("id") or "GRYPE-UNKNOWN"
    name = art.get("name") or "unknown"
    version = art.get("version")
    severity = canon_severity(vuln.get("severity"))
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
        return cli_version("grype", subcommand="version")

    def health_check(self) -> bool:
        return which_available("grype")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target

        def parse(proc, run_id):
            payload = json.loads(proc.stdout or "{}")
            return [_convert(m, run_id) for m in payload.get("matches", [])]

        return run_cli_scan(
            self, options, run_state,
            argv=["grype", "-o", "json", str(target)],
            command_str=f"grype -o json {target}",
            subdir="grype", raw_filename="results.json",
            parse=parse, parse_error_label="grype json",
        )


register(GrypeAdapter())
