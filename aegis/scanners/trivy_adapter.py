"""TrivyAdapter — wraps aegis.adapters.trivy_runner.run_trivy."""

from __future__ import annotations

import shutil
import time

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.state import RunState


class TrivyAdapter:
    name = "trivy"
    capabilities = {"dependency"}
    default_timeout = 900

    def adapter_version(self) -> str:
        try:
            import subprocess
            out = subprocess.run(["trivy", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").splitlines()[0].strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("trivy") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        from aegis.adapters.trivy_runner import run_trivy
        started = time.monotonic()
        result = run_trivy(
            options.target,
            run_id=run_state.run_id,
            output_dir=run_state.run_path / "trivy",
        )
        return ScanResult(
            findings=result.findings,
            adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str="trivy fs",
            exit_code=result.return_code,
            duration_s=time.monotonic() - started,
            error=result.error,
        )


register(TrivyAdapter())
