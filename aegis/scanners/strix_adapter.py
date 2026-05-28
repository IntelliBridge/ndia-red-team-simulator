"""StrixAdapter — wraps aegis.adapters.strix_runner.run_strix."""

from __future__ import annotations

import shutil
import time

from aegis.scanners.registry import ScanOptions, ScanResult, register
from aegis.state import RunState


class StrixAdapter:
    name = "strix"
    capabilities = {"dast"}
    default_timeout = 1800

    def adapter_version(self) -> str:
        try:
            import subprocess
            out = subprocess.run(["strix", "--version"], capture_output=True,
                                 text=True, timeout=3, check=False)
            return (out.stdout or "").strip() or "unknown"
        except Exception:
            return "unknown"

    def health_check(self) -> bool:
        return shutil.which("strix") is not None

    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult:
        from aegis.adapters.strix_runner import run_strix
        started = time.monotonic()
        result = run_strix(
            options.target, run_state,
            instruction=options.instruction,
            timeout=options.timeout or self.default_timeout,
        )
        return ScanResult(
            findings=result.findings,
            adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=" ".join(result.command or []),
            exit_code=result.return_code or 0,
            duration_s=time.monotonic() - started,
            error=result.error,
        )


register(StrixAdapter())
