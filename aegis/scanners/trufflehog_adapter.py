"""TrufflehogAdapter — secret detection via the TruffleHog CLI (JSONL output)."""

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


def _source_location(d: dict) -> tuple[str, int]:
    data = ((d.get("SourceMetadata") or {}).get("Data")) or {}
    for key in ("Filesystem", "Git"):
        src = data.get(key)
        if src:
            return src.get("file", "unknown"), src.get("line", 0)
    return "unknown", 0


def _convert(d: dict, run_id: str) -> AegisFinding:
    detector = d.get("DetectorName") or "secret"
    verified = bool(d.get("Verified"))
    file_path, line = _source_location(d)
    return AegisFinding(
        id=f"trufflehog:{detector}:{file_path}:{line}",
        title=f"{detector} secret",
        severity="high" if verified else "medium",
        finding_type="runtime",
        description=f"Potential {detector} secret detected",
        source_tool="trufflehog",
        source_run_id=run_id,
        affected_component=file_path,
        confidence="high" if verified else "medium",
        status="open",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        evidence="<redacted>",
    )


class TrufflehogAdapter:
    name = "trufflehog"
    capabilities = {"secret"}
    default_timeout = 600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["trufflehog", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return ((out.stdout or "") + (out.stderr or "")).strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("trufflehog") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"trufflehog filesystem --json {target}"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["trufflehog", "filesystem", "--json", str(target)],
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
        raw_dir = Path(run_state.run_path) / "trufflehog"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.jsonl").write_text(proc.stdout or "")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(TrufflehogAdapter())
