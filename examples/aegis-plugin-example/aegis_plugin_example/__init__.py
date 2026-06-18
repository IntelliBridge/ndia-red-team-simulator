"""Reference Aegis community scanner adapter — a *working sandboxed* template.

A minimal, copyable scanner that satisfies the ``ScannerAdapter`` Protocol
(``name``, ``capabilities``, ``default_timeout`` + ``adapter_version`` /
``health_check`` / ``scan``) and actually finds something: it walks the scan
``target`` directory and flags any line containing the marker token
``AEGIS-EXAMPLE-SECRET`` as a (low-severity) hardcoded-secret finding. That is
enough to exercise the real finding pipeline end-to-end while remaining trivial
and offline — copy this directory, rename the package and the
``[project.entry-points."aegis.scanners"]`` key, and swap the body of ``scan``
for a real tool invocation.

Sandboxed by default
====================

Because this package is discovered through the ``aegis.scanners`` entry point
(opt-in via ``AEGIS_PLUGINS=1``), Aegis runs its ``scan()`` **out-of-process**:
the scanner registry wraps it in
:class:`aegis.scanners.sandbox.SandboxedScanner`, which launches
``python -m aegis.scanners.sandbox_worker`` with resource rlimits + a wall-clock
timeout and a network-off environment, hands the run over a JSON stdin/stdout
contract, and rebuilds the resulting :class:`ScanResult`. Nothing about the
adapter changes to get this — writing a conformant scanner is enough; the host
imposes the isolation. (Set ``AEGIS_PLUGINS_SANDBOX=0`` to run trusted plugins
in-process.)

The ``aegis`` package is imported lazily inside ``scan`` so this template stays
importable on its own (e.g. for the conformance check, or when signing it)
without Aegis present — exactly as the sandbox worker imports it in the child.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.scanners.registry import ScanOptions, ScanResult
    from aegis.state import RunStateAPI

# The marker the example scanner looks for. A real adapter would shell out to a
# secret scanner; we keep it to one deterministic token so the example is fast,
# offline, and exercises the finding path without false positives.
MARKER = "AEGIS-EXAMPLE-SECRET"  # noqa: S105 - a demo marker, not a real secret

# Only walk text-ish files, and bound the walk so a huge target can't make the
# example run unbounded inside the sandbox.
_TEXT_SUFFIXES = {".py", ".txt", ".md", ".cfg", ".ini", ".env", ".yaml", ".yml", ".json"}
_MAX_FILES = 2000
_MAX_BYTES = 1_000_000


class ExampleScanner:
    """A tiny, offline secret scanner that flags a marker token in the target."""

    name = "example"
    capabilities = {"secret"}
    default_timeout = 60

    def adapter_version(self) -> str:
        return "0.1.0"

    def health_check(self) -> bool:
        # A real adapter would probe its backing tool here.
        return True

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        # Lazy import keeps the package importable without Aegis installed and
        # mirrors how the sandbox worker resolves these types in the child.
        from aegis.scanners.registry import ScanResult

        findings = [
            self._finding(run_state.run_id, hit)
            for hit in self._scan_target(Path(options.target))
        ]
        # Demonstrate that a sandboxed plugin can still persist artifacts into
        # the run directory it was handed (written inside the child process).
        run_state.save_artifact(
            "example-scanner.txt",
            f"example scanner inspected {options.target!r}; {len(findings)} hit(s)\n",
        )
        return ScanResult(
            findings=findings,
            adapter_name=self.name,
            adapter_version=self.adapter_version(),
            command_str=f"example-scanner --target {options.target}",
            exit_code=0,
            duration_s=0.0,
        )

    def _scan_target(self, target: Path) -> list[tuple[str, int, str]]:
        """Return ``(file, line_no, line)`` for every marker hit under ``target``.

        ``target`` may be a single file or a directory; non-text files, files
        larger than the byte cap, and unreadable files are skipped. The walk is
        bounded by ``_MAX_FILES`` so the example stays fast inside the sandbox.
        """
        if target.is_file():
            candidates = [target]
        elif target.is_dir():
            candidates = [
                p for p in sorted(target.rglob("*"))
                if p.is_file() and p.suffix.lower() in _TEXT_SUFFIXES
            ][:_MAX_FILES]
        else:
            return []

        hits: list[tuple[str, int, str]] = []
        for path in candidates:
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                if MARKER in line:
                    hits.append((str(path), line_no, line.strip()[:200]))
        return hits

    def _finding(self, run_id: str, hit: tuple[str, int, str]) -> Any:
        from aegis.schema import AegisFinding, CodeLocation

        path, line_no, snippet = hit
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        return AegisFinding(
            id=f"example-{abs(hash((path, line_no))) % (10**8):08d}",
            title="Hardcoded example marker detected",
            severity="low",
            finding_type="sast",
            description=(
                "The example scanner found its demo marker token "
                f"({MARKER!r}). A real scanner would report a genuine secret."
            ),
            source_tool="example",
            source_run_id=run_id,
            affected_component=path,
            confidence="high",
            status="open",
            created_at=now,
            updated_at=now,
            code_locations=[CodeLocation(
                file=path, start_line=line_no, end_line=line_no, snippet=snippet,
            )],
            remediation_steps="Remove the marker / move the secret to a secret store.",
        )


def create_scanner() -> ExampleScanner:
    """Entry-point factory returning a fresh adapter instance."""
    return ExampleScanner()
