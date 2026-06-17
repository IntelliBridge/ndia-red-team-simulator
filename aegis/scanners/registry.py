"""Scanner adapter Protocol + registry."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from aegis.registry import Registry
from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

logger = logging.getLogger(__name__)

# Open capability vocabulary. Adding a capability is a one-line append here;
# a declared capability outside this set logs a warning but still registers,
# so third-party plugins can introduce their own without patching core.
KNOWN_CAPABILITIES: set[str] = {
    "dast", "sast", "dependency", "iac", "secret", "sbom", "supply_chain", "code_audit",
}
Capability = str  # back-compat alias; validated against KNOWN_CAPABILITIES at register()


_DEFAULT_TIMEOUT = 1800


@dataclass
class ScanOptions:
    target: str
    instruction: str | None = None
    timeout: int = _DEFAULT_TIMEOUT
    scan_mode: str = "standard"
    # Strix depth (v0.10.0). All optional and adapter-specific: an adapter that
    # doesn't understand them ignores them, so the single-target default path is
    # unchanged. ``targets`` augments ``target`` for multi-target sweeps;
    # ``instruction_file`` is a path read in lieu of ``instruction``;
    # ``scope_mode``/``diff_base`` control code-target diff scoping.
    targets: list[str] | None = None
    instruction_file: str | None = None
    scope_mode: str = "auto"
    diff_base: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class RunnerResult(Protocol):
    """Duck-typed shape of a runner result consumed by :meth:`ScanResult.from_runner`.

    Both ``aegis.runners.strix_runner.StrixRunResult`` and
    ``aegis.runners.trivy_runner.TrivyRunResult`` satisfy this without the
    scanner layer importing the runner layer (which would invert the dependency:
    runners must never import the scanner registry). ``command`` is optional —
    ``TrivyRunResult`` has no command list, so the trivy adapter passes an
    explicit ``command_str`` instead.
    """
    findings: list[AegisFinding]
    return_code: int
    error: str | None


@dataclass
class ScanResult:
    findings: list[AegisFinding]
    adapter_name: str
    adapter_version: str
    command_str: str
    env_keys: list[str] = field(default_factory=list)
    exit_code: int = 0
    duration_s: float = 0.0
    error: str | None = None

    @classmethod
    def from_runner(
        cls,
        result: RunnerResult,
        *,
        adapter_name: str,
        adapter_version: str,
        duration_s: float,
        command_str: str | None = None,
    ) -> ScanResult:
        """Wrap a duck-typed runner result (Strix/Trivy) into a ``ScanResult``.

        Collapses the verbatim re-wrap both delegating adapters performed:
        ``findings``/``error`` pass straight through, ``exit_code`` is
        ``result.return_code or 0`` (a non-zero rc is preserved; the strix
        adapter already coalesced ``None``→0 and trivy's rc is always an int, so
        this is byte-for-byte identical for both). ``command_str`` defaults to
        ``" ".join(result.command or [])`` — the strix form — but accepts an
        explicit override for runners with no ``command`` attribute (trivy passes
        the literal ``"trivy fs"``).
        """
        if command_str is None:
            command_str = " ".join(getattr(result, "command", None) or [])
        return cls(
            findings=result.findings,
            adapter_name=adapter_name,
            adapter_version=adapter_version,
            command_str=command_str,
            exit_code=result.return_code or 0,
            duration_s=duration_s,
            error=result.error,
        )


def run_cli_scan(
    adapter: ScannerAdapter,
    options: ScanOptions,
    run_state: RunStateAPI,
    *,
    argv: list[str],
    command_str: str,
    parse: Callable[[subprocess.CompletedProcess, str], list[AegisFinding]],
    subdir: str | None = None,
    raw_filename: str | None = None,
    parse_error_label: str | None = None,
    raw_empty: str = "{}",
) -> ScanResult:
    """Run a CLI-subprocess scanner and assemble its ``ScanResult``.

    Owns the boilerplate that every CLI adapter's ``scan()`` repeated verbatim:
    the started-timer, the ``subprocess.run`` invocation, the
    ``TimeoutExpired``/``FileNotFoundError`` error envelope, the optional
    JSON-parse error envelope, raw-payload persistence, and the success result.
    Each adapter supplies only the bits that genuinely vary:

    * ``argv`` — the command list passed to ``subprocess.run``.
    * ``command_str`` — the human-readable command recorded on the result.
    * ``parse`` — callback ``(proc, run_id) -> findings``. It may raise
      ``json.JSONDecodeError``; when ``parse_error_label`` is set, that becomes
      the ``"failed to parse <label>: <exc>"`` envelope (exit_code from the
      process). JSONL adapters that swallow bad lines simply never raise.
    * ``subdir`` / ``raw_filename`` — where under ``run_state.run_path`` the raw
      stdout is persisted (e.g. ``"grype"`` + ``"results.json"``). Leave both
      ``None`` for adapters that persist nothing (e.g. sonarqube, whose
      findings arrive from the web API later).
    * ``parse_error_label`` — label used in the parse-error message. Leave
      ``None`` for adapters that never surface a parse error (JSONL/SBOM).
    * ``raw_empty`` — placeholder written when stdout is empty (``"{}"`` for
      JSON, ``""`` for JSONL).
    """
    version = adapter.adapter_version()
    started = time.monotonic()
    # ``ScanOptions.timeout`` defaults to the registry sentinel; when the caller
    # never overrode it, honour the adapter's declared ``default_timeout``.
    timeout = (adapter.default_timeout if options.timeout == _DEFAULT_TIMEOUT
               else options.timeout)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return ScanResult(
            findings=[], adapter_name=adapter.name,
            adapter_version=version,
            command_str=command_str,
            exit_code=-1,
            duration_s=time.monotonic() - started,
            error=str(exc),
        )
    try:
        findings = parse(proc, run_state.run_id)
    except json.JSONDecodeError as exc:
        return ScanResult(
            findings=[], adapter_name=adapter.name,
            adapter_version=version,
            command_str=command_str,
            exit_code=proc.returncode,
            duration_s=time.monotonic() - started,
            error=f"failed to parse {parse_error_label}: {exc}",
        )
    if subdir is not None and raw_filename is not None:
        raw_dir = Path(run_state.run_path) / subdir
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / raw_filename).write_text(proc.stdout or raw_empty)
    return ScanResult(
        findings=findings, adapter_name=adapter.name,
        adapter_version=version,
        command_str=command_str,
        exit_code=proc.returncode,
        duration_s=time.monotonic() - started,
    )


def run_cli_scan_jsonl(
    adapter: ScannerAdapter,
    options: ScanOptions,
    run_state: RunStateAPI,
    *,
    argv: list[str],
    command_str: str,
    convert: Callable[[dict[str, Any], str], AegisFinding | None],
    subdir: str | None = None,
    raw_filename: str | None = None,
) -> ScanResult:
    """Run a line-oriented (JSONL/NDJSON) CLI scanner and assemble its ``ScanResult``.

    The line-oriented sibling of :func:`run_cli_scan`. It shares the same
    subprocess invocation, ``default_timeout`` honouring, the
    ``TimeoutExpired``/``FileNotFoundError`` error envelope, raw-payload
    persistence, and success-result assembly, but parses stdout **one line at a
    time** and is tolerant of malformed lines: a line that is not valid JSON is
    silently skipped (the verbatim per-adapter behaviour) rather than failing the
    whole scan, so there is no JSON-parse error envelope. Each adapter supplies:

    * ``argv`` / ``command_str`` — as in :func:`run_cli_scan`.
    * ``convert`` — callback ``(record, run_id) -> AegisFinding | None`` invoked
      once per parsed JSON object. Returning ``None`` filters that line out (e.g.
      bumblebee keeps only ``record_type == "finding"`` records).
    * ``subdir`` / ``raw_filename`` — where under ``run_state.run_path`` the raw
      stdout is persisted; empty stdout writes the empty string (the JSONL
      placeholder). Leave both ``None`` to persist nothing.
    """
    version = adapter.adapter_version()
    started = time.monotonic()
    timeout = (adapter.default_timeout if options.timeout == _DEFAULT_TIMEOUT
               else options.timeout)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return ScanResult(
            findings=[], adapter_name=adapter.name,
            adapter_version=version,
            command_str=command_str,
            exit_code=-1,
            duration_s=time.monotonic() - started,
            error=str(exc),
        )
    findings: list[AegisFinding] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = convert(rec, run_state.run_id)
        if finding is not None:
            findings.append(finding)
    if subdir is not None and raw_filename is not None:
        raw_dir = Path(run_state.run_path) / subdir
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / raw_filename).write_text(proc.stdout or "")
    return ScanResult(
        findings=findings, adapter_name=adapter.name,
        adapter_version=version,
        command_str=command_str,
        exit_code=proc.returncode,
        duration_s=time.monotonic() - started,
    )


def cli_version(
    executable: str,
    *,
    subcommand: str = "--version",
    merge_stderr: bool = False,
    first_line: bool = False,
    timeout: int = 3,
) -> str:
    """Probe a CLI tool's version banner, or ``"unknown"`` on any failure.

    Centralizes the ``subprocess.run`` + short timeout + swallow-everything
    contract that every single-executable adapter's ``adapter_version()``
    repeated verbatim. The flags cover the only ways the probes vary:

    * ``subcommand`` — the version flag (tools differ: ``--version``,
      ``version``, ``-version``).
    * ``merge_stderr`` — append stderr for tools that print the banner there.
    * ``first_line`` — keep only the first line of a multi-line banner.
    """
    try:
        out = subprocess.run(
            [executable, subcommand], capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        text = (out.stdout or "")
        if merge_stderr:
            text += (out.stderr or "")
        text = text.strip()
        if first_line:
            text = text.splitlines()[0] if text else ""
        return text or "unknown"
    except Exception:
        return "unknown"


def which_available(*executables: str) -> bool:
    """True when any of ``executables`` resolves on PATH (``shutil.which``)."""
    return any(shutil.which(exe) is not None for exe in executables)


@runtime_checkable
class ScannerAdapter(Protocol):
    name: str
    capabilities: set[str]
    default_timeout: int

    def adapter_version(self) -> str: ...
    def health_check(self) -> bool: ...
    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult: ...


def _validate(adapter: ScannerAdapter) -> None:
    unknown = set(adapter.capabilities) - KNOWN_CAPABILITIES
    if unknown:
        logger.warning(
            "scanner %r declares unknown capabilities %s; registering anyway",
            adapter.name, sorted(unknown),
        )


_scanner_registry: Registry[ScannerAdapter] = Registry(
    "scanner", validate=_validate, protocol=ScannerAdapter,
)
# Historical public handle: callers and tests pop/iterate this dict directly,
# so it must stay the live backing store (same object as the registry's).
_REGISTRY: dict[str, ScannerAdapter] = _scanner_registry._items

register = _scanner_registry.register
get = _scanner_registry.get


def list_scanners() -> list[str]:
    return _scanner_registry.list_names()


def dispatch(name_or_capability: str,
             run_state: RunStateAPI,
             options: ScanOptions) -> ScanResult:
    """Run a registered scanner by name; otherwise pick the first scanner
    that claims the given capability."""
    if name_or_capability in _REGISTRY:
        return _REGISTRY[name_or_capability].scan(run_state, options)
    for adapter in _REGISTRY.values():
        if name_or_capability in adapter.capabilities:
            return adapter.scan(run_state, options)
    raise KeyError(f"no scanner registered for {name_or_capability!r}")


def maybe_load_entry_points() -> None:
    """Third-party adapter discovery, gated by AEGIS_PLUGINS=1."""
    _scanner_registry.maybe_load_entry_points("aegis.scanners")
