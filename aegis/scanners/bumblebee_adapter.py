"""BumblebeeAdapter — supply-chain package-exposure scanning via the bumblebee CLI.

bumblebee is a read-only endpoint package inventory collector. It walks
filesystem roots, inventories installed packages, and matches them against an
operator-supplied JSON exposure catalog, emitting NDJSON records (one JSON
object per line) discriminated by a ``record_type`` field
(``package`` | ``finding`` | ``scan_summary`` | ``diagnostic``). This adapter
runs ``bumblebee scan ... --findings-only`` so only ``finding`` (plus
``scan_summary``/``diagnostic``) records are produced, and converts each
``finding`` record into a common ``AegisFinding``.

Security note: bumblebee scans roots that may contain MCP-host configs,
lockfiles, and other metadata that can carry secrets. This adapter NEVER copies
raw record values or any credential-bearing data into an ``AegisFinding``;
``evidence`` is left ``None`` and only a small set of known-safe, non-secret
fields (package name, version, ecosystem, catalog id/name) are surfaced. This
mirrors trufflehog's ``evidence`` redaction guarantee.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from aegis.config import load_config
from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.schema import AegisFinding
from aegis.state import RunState

_KNOWN_SEVERITIES = {"critical", "high", "medium", "low"}


def _normalize_severity(value: str) -> str:
    """Lowercase and pass through known severities; everything else -> 'low'.

    bumblebee echoes the catalog entry's severity (e.g. "critical"/"high"), but
    the field is ``omitempty`` so it may be absent entirely. Absent/unknown maps
    to 'low' the way trivy's severity map does.
    """
    sev = (value or "").lower()
    return sev if sev in _KNOWN_SEVERITIES else "low"


def _convert(record: dict, run_id: str) -> AegisFinding:
    """Map a bumblebee ``record_type=finding`` record to an ``AegisFinding``.

    Only known-safe, non-secret fields are copied. The raw record is never
    serialized into the finding, and ``evidence`` is always ``None``.
    """
    package_name = record.get("package_name")
    version = record.get("version")
    ecosystem = record.get("ecosystem")
    catalog_name = record.get("catalog_name")

    finding_id = record.get("record_id") or (
        f"bumblebee:{record.get('catalog_id', 'unknown')}:"
        f"{package_name or '?'}@{version or '?'}"
    )

    title = catalog_name or (
        f"Package exposure: {package_name or ''}@{version or ''}"
    )

    # Short synthesized sentence — no raw record dump.
    parts = [f"Package {package_name or 'unknown'}"]
    if version:
        parts.append(f"version {version}")
    if ecosystem:
        parts.append(f"({ecosystem})")
    description = " ".join(parts) + " matched a known exposure catalog entry"
    if catalog_name:
        description += f": {catalog_name}"
    description += "."

    now = datetime.now(timezone.utc).isoformat()
    return AegisFinding(
        id=finding_id,
        title=title,
        severity=_normalize_severity(record.get("severity", "")),
        finding_type="supply_chain",
        description=description,
        source_tool="bumblebee",
        source_run_id=run_id,
        affected_component=package_name,
        confidence=record.get("confidence") or "medium",
        status="open",
        created_at=now,
        updated_at=now,
        references=[],
        package_name=package_name,
        installed_version=version,
        remediation_steps=None,
        # NEVER copy the raw record or any credential value into the finding.
        evidence=None,
    )


class BumblebeeAdapter:
    name = "bumblebee"
    capabilities = {"supply_chain"}
    default_timeout = 600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["bumblebee", "version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("bumblebee") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        cfg = load_config()
        catalog_dir = Path(cfg.bumblebee_path) / "threat_intel"
        command = [
            "bumblebee", "scan",
            "--root", str(target),
            "--exposure-catalog", str(catalog_dir),
            "--findings-only",
            "--output", "stdout",
        ]
        command_str = " ".join(command)
        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
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
            if rec.get("record_type") == "finding":
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
