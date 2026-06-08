"""Convert AegisFindings to the vulnerability-fixer export format."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.schema import AegisFinding


@dataclass
class ExportResult:
    """Result of attempting to export a finding to vuln-fixer format."""
    routable_to_vulnfixer: bool
    requires_code_fix: bool
    reason: str
    payload: dict | None = None  # Only set if routable


def to_vulnfixer_vulnerability(finding: AegisFinding) -> ExportResult:
    """Convert an AegisFinding to vulnerability-fixer Vulnerability format.

    Returns ExportResult indicating whether the finding is routable.
    Dependency findings with package info are routable.
    Appsec findings (DAST/SAST without package versions) are NOT routable
    and should go to CAI remediation instead.
    """
    if not finding.is_dependency_finding:
        return ExportResult(
            routable_to_vulnfixer=False,
            requires_code_fix=True,
            reason=f"Appsec finding ({finding.finding_type}) without package version information",
        )

    payload = {
        "id": finding.id,
        "cveId": finding.cve or finding.id,
        "packageName": finding.package_name,
        "installedVersion": finding.installed_version or "unknown",
        "fixedVersion": finding.fixed_version or "N/A",
        "severity": finding.severity.upper(),
        "description": finding.description,
        "cvssScore": finding.cvss or 0.0,
        "references": finding.references or [],
        "vulnerable": True,
        "fixed": False,
        "source": "other",
    }

    return ExportResult(
        routable_to_vulnfixer=True,
        requires_code_fix=False,
        reason="Dependency finding with package version information",
        payload=payload,
    )


def export_findings(findings: list[AegisFinding], output_path: str | Path) -> dict[str, Any]:
    """Export routable findings to a JSON file for vulnerability-fixer.

    Returns a summary dict with counts of routable vs code-fix findings.
    """
    output_path = Path(output_path)

    routable = []
    code_fix_needed = []

    for finding in findings:
        result = to_vulnfixer_vulnerability(finding)
        if result.routable_to_vulnfixer and result.payload:
            routable.append(result.payload)
        else:
            code_fix_needed.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "finding_type": finding.finding_type,
                "reason": result.reason,
            })

    summary: dict[str, int] = {
        "total": len(findings),
        "routable_to_vulnfixer": len(routable),
        "requires_code_fix": len(code_fix_needed),
    }
    export_data = {
        "vulnerabilities": routable,
        "code_fix_required": code_fix_needed,
        "summary": summary,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2)

    return summary
