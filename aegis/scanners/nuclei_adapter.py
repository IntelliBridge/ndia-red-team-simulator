"""NucleiAdapter — DAST via template-based Nuclei."""

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
    "critical": "critical", "high": "high",
    "medium": "medium", "low": "low", "info": "low",
}


def _convert(record: dict, run_id: str) -> AegisFinding:
    info = record.get("info") or {}
    severity = _SEVERITY_MAP.get(
        (info.get("severity") or "").lower(), "medium"
    )
    template_id = record.get("template-id") or "nuclei.template"
    matched_at = record.get("matched-at") or record.get("host", "unknown")
    return AegisFinding(
        id=f"nuclei:{template_id}:{matched_at}",
        title=info.get("name") or template_id,
        severity=severity,
        finding_type="dast",
        description=info.get("description") or "",
        source_tool="nuclei",
        source_run_id=run_id,
        affected_component=matched_at,
        confidence="high",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        target=record.get("host"),
        endpoint=matched_at,
        references=info.get("reference") or [],
    )


class NucleiAdapter:
    name = "nuclei"
    capabilities = {"dast"}
    default_timeout = 900

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["nuclei", "-version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return ((out.stdout or "") + (out.stderr or "")).strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("nuclei") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        templates = options.extra.get("templates", "cves,vulnerabilities")
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["nuclei", "-target", target, "-jsonl", "-silent",
                 "-t", templates],
                capture_output=True, text=True, timeout=options.timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return ScanResult(
                findings=[], adapter_name=self.name,
                adapter_version=self.adapter_version(),
                command_str=f"nuclei -target {target}",
                exit_code=-1, duration_s=time.monotonic() - started,
                error=str(exc),
            )
        findings: list[AegisFinding] = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(_convert(rec, run_state.run_id))
        raw_dir = Path(run_state.run_path) / "nuclei"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.jsonl").write_text(proc.stdout or "")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=f"nuclei -target {target} -t {templates}",
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(NucleiAdapter())
