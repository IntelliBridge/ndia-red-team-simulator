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

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.config import load_config
from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan_jsonl,
    which_available,
)
from aegis.schema import AegisFinding, Severity

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

_KNOWN_SEVERITIES: dict[str, Severity] = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
}


def _canon_severity(value: str) -> Severity:
    """Lowercase and pass through known severities; everything else -> 'low'.

    bumblebee echoes the catalog entry's severity (e.g. "critical"/"high"), but
    the field is ``omitempty`` so it may be absent entirely. Absent/unknown maps
    to 'low' the way trivy's severity map does.
    """
    sev = (value or "").lower()
    return _KNOWN_SEVERITIES.get(sev, "low")


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
        severity=_canon_severity(record.get("severity", "")),
        finding_type="supply_chain",
        description=description,
        source_tool="bumblebee",
        source_run_id=run_id,
        affected_component=package_name or "",
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


def _convert_finding(record: dict[str, Any], run_id: str) -> AegisFinding | None:
    """Per-line callback: convert only ``record_type == "finding"`` records.

    bumblebee emits NDJSON discriminated by ``record_type``
    (``package``/``finding``/``scan_summary``/``diagnostic``); returning ``None``
    for the non-``finding`` records filters them out, preserving the in-loop
    filter the adapter previously applied.
    """
    if record.get("record_type") != "finding":
        return None
    return _convert(record, run_id)


class BumblebeeAdapter:
    name = "bumblebee"
    capabilities = {"supply_chain"}
    default_timeout = 600

    def adapter_version(self) -> str:
        return cli_version("bumblebee", subcommand="version")

    def health_check(self) -> bool:
        return which_available("bumblebee")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target
        config = load_config()
        catalog_dir = Path(config.bumblebee_path) / "threat_intel"
        command = [
            "bumblebee", "scan",
            "--root", str(target),
            "--exposure-catalog", str(catalog_dir),
            "--findings-only",
            "--output", "stdout",
        ]

        return run_cli_scan_jsonl(
            self, options, run_state,
            argv=command,
            command_str=" ".join(command),
            subdir="bumblebee", raw_filename="results.ndjson",
            convert=_convert_finding,
        )


register(BumblebeeAdapter())
