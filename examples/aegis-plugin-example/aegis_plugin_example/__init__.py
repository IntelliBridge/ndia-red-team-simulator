"""Reference Aegis community scanner adapter.

A minimal, copyable template that satisfies the ``ScannerAdapter`` Protocol
(``name``, ``capabilities``, ``default_timeout`` + ``adapter_version`` /
``health_check`` / ``scan``). It finds nothing — its job is to demonstrate the
entry-point seam, not to scan. Copy this directory, rename the package and the
``[project.entry-points."aegis.scanners"]`` key, and replace ``scan`` with a
real implementation.

The ``aegis`` package is imported lazily inside ``scan`` so this template is
importable on its own (e.g. for the conformance check) without Aegis present.
"""

from __future__ import annotations


class ExampleScanner:
    """A no-op DAST scanner that always returns zero findings."""

    name = "example"
    capabilities = {"dast"}
    default_timeout = 60

    def adapter_version(self) -> str:
        return "0.1.0"

    def health_check(self) -> bool:
        # A real adapter would probe its backing tool here.
        return True

    def scan(self, run_state, options):
        # Lazy import keeps the package importable without Aegis installed.
        from aegis.scanners.registry import ScanResult

        return ScanResult(
            findings=[],
            adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str="example-scanner --noop",
            exit_code=0,
            duration_s=0.0,
        )


def create_scanner() -> ExampleScanner:
    """Entry-point factory returning a fresh adapter instance."""
    return ExampleScanner()
