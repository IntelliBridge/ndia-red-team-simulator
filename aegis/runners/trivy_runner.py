"""Run Trivy filesystem scan against a local repo and normalize results.

This adapter replaces deeper integration with the (UI-only) vulnerability-fixer
project for Phase 2. We invoke ``trivy fs --format json`` on the repo, parse
``Results[*].Vulnerabilities[*]``, and yield ``AegisFinding`` objects with
``finding_type='dependency'`` — routable to the existing vulnfixer JSON export
and to a small CAI prompt for the version bump.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aegis.scanners.severity import canon_severity
from aegis.schema import AegisFinding


@dataclass
class TrivyRunResult:
    success: bool
    return_code: int
    findings: list[AegisFinding]
    raw_json_path: str | None
    error: str | None = None


def parse_trivy_json(raw: dict, run_id: str, *, repo_path: str | None = None) -> list[AegisFinding]:
    findings: list[AegisFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    for result in raw.get("Results", []) or []:
        target = result.get("Target") or ""
        for v in result.get("Vulnerabilities", []) or []:
            cvss_score = None
            cvss_block = v.get("CVSS") or {}
            for source in ("nvd", "redhat", "ghsa"):
                node = cvss_block.get(source) or {}
                for key in ("V3Score", "V2Score"):
                    score = node.get(key)
                    if isinstance(score, (int, float)):
                        cvss_score = float(score)
                        break
                if cvss_score is not None:
                    break

            findings.append(AegisFinding(
                id=f"{v.get('VulnerabilityID', 'UNKNOWN')}@{v.get('PkgName', 'unknown')}",
                title=v.get("Title") or v.get("VulnerabilityID") or "Dependency vulnerability",
                severity=canon_severity(v.get("Severity")),
                finding_type="dependency",
                description=v.get("Description") or "",
                source_tool="trivy",
                source_run_id=run_id,
                affected_component=f"{v.get('PkgName')} ({target})",
                confidence="high",
                status="open",
                created_at=now,
                updated_at=now,
                cve=v.get("VulnerabilityID"),
                cvss=cvss_score,
                cwe=(v.get("CweIDs") or [None])[0],
                references=v.get("References") or [],
                package_name=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion"),
            ))
    return findings


def run_trivy(
    repo_path: Path | str,
    *,
    run_id: str,
    output_dir: Path | None = None,
    trivy_command: str | None = None,
    extra_args: list[str] | None = None,
) -> TrivyRunResult:
    repo = Path(repo_path)
    if not repo.is_dir():
        return TrivyRunResult(False, -1, [], None, f"repo not found: {repo}")
    cmd_head = [trivy_command] if trivy_command else [shutil.which("trivy") or "trivy"]
    if not shutil.which(cmd_head[0]):
        return TrivyRunResult(False, -1, [], None,
                              "trivy CLI not found — install with `brew install trivy` or `apt install trivy`")
    cmd = cmd_head + ["fs", "--quiet", "--format", "json", "--no-progress"]
    if extra_args:
        cmd += list(extra_args)
    cmd += [str(repo)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=900)
    except subprocess.TimeoutExpired:
        return TrivyRunResult(False, -1, [], None, "trivy timed out")
    except FileNotFoundError as exc:
        return TrivyRunResult(False, -1, [], None, str(exc))

    raw_path = None
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_path = output_dir / "trivy.json"
        raw_path.write_text(result.stdout or "")
    if result.returncode != 0 and not result.stdout:
        return TrivyRunResult(False, result.returncode, [],
                              str(raw_path) if raw_path else None,
                              result.stderr or "trivy failed")
    try:
        raw_json = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return TrivyRunResult(False, result.returncode, [],
                              str(raw_path) if raw_path else None,
                              f"failed to parse trivy json: {exc}")

    findings = parse_trivy_json(raw_json, run_id, repo_path=str(repo))
    return TrivyRunResult(
        success=True, return_code=result.returncode, findings=findings,
        raw_json_path=str(raw_path) if raw_path else None,
    )
