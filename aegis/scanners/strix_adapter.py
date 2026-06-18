"""StrixAdapter — wraps aegis.runners.strix_runner.run_strix."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from aegis.scanners.registry import ScanOptions, ScanResult, cli_version, register, which_available

if TYPE_CHECKING:
    from aegis.state import RunStateAPI


class StrixAdapter:
    name = "strix"
    capabilities = {"dast"}
    default_timeout = 1800

    def adapter_version(self) -> str:
        return cli_version("strix")

    def health_check(self) -> bool:
        return which_available("strix")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        from aegis.runners.strix_runner import run_strix
        started = time.monotonic()
        result = run_strix(
            options.target, run_state,
            instruction=options.instruction,
            timeout=options.timeout or self.default_timeout,
            scan_mode=options.scan_mode,
            targets=options.targets,
            instruction_file=options.instruction_file,
            scope_mode=options.scope_mode,
            diff_base=options.diff_base,
        )
        return ScanResult.from_runner(
            result,
            adapter_name=self.name,
            adapter_version=self.adapter_version(),
            duration_s=time.monotonic() - started,
        )


register(StrixAdapter())
