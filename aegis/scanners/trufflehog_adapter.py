"""TrufflehogAdapter — secret detection via the TruffleHog CLI (JSONL output)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan_jsonl,
    which_available,
)
from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.state import RunStateAPI


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
        return cli_version("trufflehog", merge_stderr=True)

    def health_check(self) -> bool:
        return which_available("trufflehog")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target
        return run_cli_scan_jsonl(
            self, options, run_state,
            argv=["trufflehog", "filesystem", "--json", str(target)],
            command_str=f"trufflehog filesystem --json {target}",
            subdir="trufflehog", raw_filename="results.jsonl",
            convert=_convert,
        )


register(TrufflehogAdapter())
