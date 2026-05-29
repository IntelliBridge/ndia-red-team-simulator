"""BumblebeeAdapter — MCP supply-chain scanning via the bumblebee CLI (NDJSON output).

Security note: bumblebee parses MCP-host configs that may carry credentials. This
adapter NEVER copies credential values (e.g. ``redacted_credential``) or any raw
config value into an ``AegisFinding``; ``evidence`` is left ``None``. Only the
config file PATH (``source_config``) is safe to reference, and we do not even
surface that as a secret-bearing field. This mirrors trufflehog's ``evidence``
redaction.
"""

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

_KNOWN_SEVERITIES = {"critical", "high", "medium", "low"}


def _normalize_severity(value: str) -> str:
    """Lowercase and pass through known severities; everything else -> 'low'.

    Covers ``info``/``unknown``/missing the way trivy's severity map does.
    """
    sev = (value or "").lower()
    return sev if sev in _KNOWN_SEVERITIES else "low"


def _convert(record: dict, run_id: str) -> AegisFinding:
    finding_id = record.get("id") or (
        f"bumblebee:{record.get('package', 'unknown')}:{record.get('exposure', '?')}"
    )
    now = datetime.now(timezone.utc).isoformat()
    return AegisFinding(
        id=finding_id,
        title=record.get("title") or "Supply-chain exposure",
        severity=_normalize_severity(record.get("severity", "")),
        finding_type="supply_chain",
        description=record.get("description", ""),
        source_tool="bumblebee",
        source_run_id=run_id,
        affected_component=record.get("package") or record.get("mcp_server") or "unknown",
        confidence="medium",
        status="open",
        created_at=now,
        updated_at=now,
        references=record.get("references") or [],
        package_name=record.get("package"),
        installed_version=record.get("version"),
        remediation_steps=record.get("remediation"),
        # NEVER copy the raw record or any credential value into the finding.
        evidence=None,
    )


class BumblebeeAdapter:
    name = "bumblebee"
    capabilities = {"supply_chain"}
    default_timeout = 600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["bumblebee", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("bumblebee") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"bumblebee scan --target {target} --format ndjson"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["bumblebee", "scan", "--target", str(target), "--format", "ndjson"],
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
            if rec.get("type") == "finding":
                findings.append(_convert(rec, run_state.run_id))
        raw_dir = Path(run_state.run_path) / "bumblebee"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "results.ndjson").write_text(proc.stdout or "")
        return ScanResult(
            findings=findings, adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(BumblebeeAdapter())
