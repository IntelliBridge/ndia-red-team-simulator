"""SemgrepAdapter — SAST via the Semgrep CLI."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.schema import AegisFinding, CodeLocation
from aegis.state import RunState


_SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "low",
}


def _convert(finding: dict, run_id: str) -> AegisFinding:
    extra = finding.get("extra") or {}
    metadata = extra.get("metadata") or {}
    severity = _SEVERITY_MAP.get(
        (extra.get("severity") or "").upper(), "medium"
    )
    start = finding.get("start") or {}
    end = finding.get("end") or {}
    snippet = (extra.get("lines") or "")[:4096]
    rule_id = finding.get("check_id") or "semgrep.rule"
    file_path = finding.get("path") or "unknown"
    return AegisFinding(
        id=f"semgrep:{rule_id}:{file_path}:{start.get('line', 0)}",
        title=metadata.get("title") or rule_id,
        severity=severity,
        finding_type="sast",
        description=extra.get("message") or rule_id,
        source_tool="semgrep",
        source_run_id=run_id,
        affected_component=file_path,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        cwe=(metadata.get("cwe") or [None])[0]
            if isinstance(metadata.get("cwe"), list) else metadata.get("cwe"),
        references=metadata.get("references") or [],
        code_locations=[CodeLocation(
            file=file_path,
            start_line=start.get("line", 0),
            end_line=end.get("line", 0),
            snippet=snippet,
        )],
    )


class SemgrepAdapter:
    name = "semgrep"
    capabilities = {"sast"}
    default_timeout = 600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["semgrep", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        from pathlib import Path
        repo = options.target
        rules = options.extra.get("rules", "auto")
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["semgrep", "--json", "--quiet", f"--config={rules}", str(repo)],
                capture_output=True, text=True, timeout=options.timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=f"semgrep --json --config={rules} {repo}",
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
                command_str=f"semgrep --json --config={rules} {repo}",
                exit_code=proc.returncode,
                duration_s=time.monotonic() - started,
                error=f"failed to parse semgrep json: {exc}",
            )
        findings = [_convert(r, run_state.run_id)
                    for r in payload.get("results", [])]
        # Persist the raw payload for forensic / re-parse use.
        raw_dir = Path(run_state.run_path) / "semgrep"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.json").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=f"semgrep --json --config={rules} {repo}",
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(SemgrepAdapter())
