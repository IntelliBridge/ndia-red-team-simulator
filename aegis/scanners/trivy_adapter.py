"""TrivyAdapter — wraps aegis.runners.trivy_runner.run_trivy."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from aegis.scanners.registry import ScanOptions, ScanResult, cli_version, register, which_available

if TYPE_CHECKING:
    from aegis.state import RunStateAPI


class TrivyAdapter:
    name = "trivy"
    capabilities = {"dependency"}
    default_timeout = 900

    def adapter_version(self) -> str:
        return cli_version("trivy", first_line=True)

    def health_check(self) -> bool:
        return which_available("trivy")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        from aegis.runners.trivy_runner import run_trivy
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
