"""CodeqlAdapter — SAST via CodeQL (SARIF output)."""

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
    "error": "high", "warning": "medium", "note": "low",
}


def _convert(result: dict, run_id: str) -> AegisFinding:
    rule_id = result.get("ruleId") or "codeql.rule"
    severity = _SEVERITY_MAP.get((result.get("level") or "").lower(), "medium")
    message = (result.get("message") or {}).get("text") or rule_id
    locations = result.get("locations") or []
    phys = (locations[0] if locations else {}).get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri") or "unknown"
    region = phys.get("region") or {}
    start_line = region.get("startLine", 0)
    end_line = region.get("endLine", start_line)
    return AegisFinding(
        id=f"codeql:{rule_id}:{uri}:{start_line}",
        title=rule_id,
        severity=severity,
        finding_type="sast",
        description=message,
        source_tool="codeql",
        source_run_id=run_id,
        affected_component=uri,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        code_locations=[CodeLocation(
            file=uri,
            start_line=start_line,
            end_line=end_line,
        )],
    )


def _extract_results(payload: dict) -> list[dict]:
    results: list[dict] = []
    for run in payload.get("runs") or []:
        results.extend(run.get("results") or [])
    return results


class CodeqlAdapter:
    name = "codeql"
    capabilities = {"sast"}
    default_timeout = 3600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["codeql", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip().splitlines()[0] \
                if (out.stdout or "").strip() else "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("codeql") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"codeql database analyze --format=sarif-latest {target}"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["codeql", "database", "analyze", "--format=sarif-latest",
                 target],
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
                error=f"failed to parse codeql sarif: {exc}",
            )
        findings = [_convert(r, run_state.run_id)
                    for r in _extract_results(payload)]
        raw_dir = Path(run_state.run_path) / "codeql"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.sarif").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(CodeqlAdapter())
