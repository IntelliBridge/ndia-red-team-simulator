"""BanditAdapter — Python SAST via the Bandit CLI."""

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
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

_CONFIDENCE_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _convert(r: dict, run_id: str) -> AegisFinding:
    filename = r.get("filename") or "unknown"
    line_number = r.get("line_number", 0)
    test_id = r.get("test_id") or "bandit.test"
    severity = _SEVERITY_MAP.get(
        (r.get("issue_severity") or "").upper(), "medium"
    )
    confidence = _CONFIDENCE_MAP.get(
        (r.get("issue_confidence") or "").upper(), "medium"
    )
    return AegisFinding(
        id=f"bandit:{test_id}:{filename}:{line_number}",
        title=r.get("test_name") or test_id,
        severity=severity,
        finding_type="sast",
        description=r.get("issue_text") or test_id,
        source_tool="bandit",
        source_run_id=run_id,
        affected_component=filename,
        confidence=confidence,
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        cwe=(r.get("issue_cwe") or {}).get("id"),
        code_locations=[CodeLocation(
            file=filename,
            start_line=line_number,
            end_line=line_number,
            snippet=r.get("code", ""),
        )],
    )


class BanditAdapter:
    name = "bandit"
    capabilities = {"sast"}
    default_timeout = 600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["bandit", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return ((out.stdout or "") + (out.stderr or "")).strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("bandit") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"bandit -r -f json {target}"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["bandit", "-r", "-f", "json", str(target)],
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
                error=f"failed to parse bandit json: {exc}",
            )
        findings = [_convert(r, run_state.run_id)
                    for r in payload.get("results", [])]
        raw_dir = Path(run_state.run_path) / "bandit"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.json").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(BanditAdapter())
