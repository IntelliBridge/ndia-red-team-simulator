"""SyftAdapter — SBOM generation (CycloneDX) via the Syft CLI.

Syft produces an SBOM *inventory* artifact, not AegisFindings, so ``scan``
always returns ``findings=[]`` and persists the CycloneDX document under the
run path.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.state import RunState


def _summarize_sbom(doc: dict) -> int:
    return len(doc.get("components", []))


class SyftAdapter:
    name = "syft"
    capabilities = {"sbom"}
    default_timeout = 600

    def adapter_version(self) -> str:
        try:
            out = subprocess.run(["syft", "version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("syft") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        target = options.target
        command_str = f"syft {target} -o cyclonedx-json"
        started = time.monotonic()
        try:
            proc = subprocess.run(
                ["syft", str(target), "-o", "cyclonedx-json"],
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
        raw_dir = Path(run_state.run_path) / "syft"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "sbom.cyclonedx.json").write_text(proc.stdout or "{}")
        return ScanResult(
            findings=[], adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
        )


register(SyftAdapter())
