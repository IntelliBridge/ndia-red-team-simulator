"""SyftAdapter — SBOM generation (CycloneDX) via the Syft CLI.

Syft produces an SBOM *inventory* artifact, not AegisFindings, so ``scan``
always returns ``findings=[]`` and persists the CycloneDX document under the
run path.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from aegis.scanners.registry import (
    ScanOptions,
    ScanResult,
    cli_version,
    register,
    run_cli_scan,
    which_available,
)

if TYPE_CHECKING:
    from aegis.schema import AegisFinding
    from aegis.state import RunStateAPI


def _summarize_sbom(doc: dict) -> int:
    return len(doc.get("components", []))


class SyftAdapter:
    name = "syft"
    capabilities = {"sbom"}
    default_timeout = 600

    def adapter_version(self) -> str:
        return cli_version("syft", subcommand="version")

    def health_check(self) -> bool:
        return which_available("syft")

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        target = options.target

        # Syft yields an SBOM artifact, not findings: the parse step always
        # returns [] and the raw CycloneDX document is persisted by the runner.
        def parse(proc: subprocess.CompletedProcess[str],
                  run_id: str) -> list[AegisFinding]:
            return []

        return run_cli_scan(
            self, options, run_state,
            argv=["syft", str(target), "-o", "cyclonedx-json"],
            command_str=f"syft {target} -o cyclonedx-json",
            subdir="syft", raw_filename="sbom.cyclonedx.json",
            parse=parse,
        )


register(SyftAdapter())
