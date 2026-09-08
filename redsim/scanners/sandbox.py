"""Out-of-process sandbox for third-party (plugin) scanner adapters.

Built-in adapters are trusted code maintained in-tree; third-party adapters
discovered via the ``redsim.scanners`` entry-point group (gated by
``REDSIM_PLUGINS=1`` + the ``REDSIM_PLUGINS_ALLOW`` allowlist, and optionally the
Ed25519 signature gate in :mod:`redsim.supply_chain.signing`) are *not*. This
module isolates a plugin scanner's ``scan()`` into a short-lived child process
so a buggy or hostile plugin cannot read the parent's memory, exhaust its
resources, or reach the network by default.

The seam
========

During eager discovery the scanner registry wraps every conformant,
signature-approved plugin adapter in a :class:`SandboxedScanner` (via
``redsim.scanners.registry._sandbox_wrap``) — itself a structurally-conformant
:class:`~redsim.scanners.registry.ScannerAdapter` — whose ``scan()`` does not run
the plugin in-process. Instead it (through :func:`run_scanner_sandboxed`):

#. Serializes the run id, run directory, and :class:`ScanOptions` to JSON.
#. Spawns ``python -m redsim.scanners.sandbox_worker --entry-point <ep>`` with a
   **list argv** (never ``shell=True`` — the existing safe pattern shared by
   every CLI adapter, e.g. :func:`redsim.scanners.registry.run_cli_scan`).
#. Applies POSIX ``resource`` rlimits (CPU seconds, address space, file size,
   open files, processes, no core dump) via a ``preexec_fn``, runs the child in
   its own session/process group, and enforces a wall-clock ``timeout`` that
   kills the whole group (not just the direct child).
#. Passes the child a **minimal allowlisted environment** — the parent's
   secrets (DB credentials, signing/encryption keys, API tokens) are never
   handed to plugin code — and strips proxy vars unless network is opted in.
#. Reads the worker's single JSON line from stdout and rebuilds a
   :class:`ScanResult`.

Scope of the boundary
=====================

This is **defense-in-depth**, not a jail against a determined adversary: it is
process isolation + resource limits + a wall-clock kill + a minimal environment
+ the signature/allowlist gate. It does **not** provide a network namespace or a
filesystem jail — a hostile plugin can still open sockets or touch files the
worker's UID can reach. Stripping proxy env reduces accidental egress but is not
an egress control. Kernel-level isolation (network/mount namespaces, seccomp, or
a gVisor/Firecracker-per-plugin runtime) is tracked as a follow-up spike (see
``docs/adr``); until then, only run plugins you have vetted and signed.

Any failure mode — the worker crashing, exceeding a limit, timing out, emitting
unparseable output — is converted into a clean ``ScanResult`` carrying an
``error`` and ``exit_code=-1`` (mirroring :func:`run_cli_scan`'s error
envelope), so a misbehaving plugin degrades to a no-finding error rather than
taking down the host scan.

The entry point reference (``module.path:factory``) must be supplied at wrap
time because a live adapter instance does not carry the import path that
produced it; the registry knows the entry point and passes it through.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from redsim.scanners.registry import _DEFAULT_TIMEOUT, ScanOptions, ScanResult
from redsim.schema import RedsimFinding
from redsim.state import RunStateAPI

try:  # ``resource`` is POSIX-only; on Windows the sandbox runs without rlimits.
    import resource

    _RESOURCE_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - non-POSIX host
    _RESOURCE_AVAILABLE = False

logger = logging.getLogger(__name__)

# Env var names (mirrored in redsim.config for discoverability/docs).
ENV_SANDBOX = "REDSIM_PLUGINS_SANDBOX"
ENV_NETWORK = "REDSIM_PLUGIN_SANDBOX_NETWORK"
ENV_CPU_SECONDS = "REDSIM_PLUGIN_SANDBOX_CPU_SECONDS"
ENV_MEMORY_MB = "REDSIM_PLUGIN_SANDBOX_MEMORY_MB"
ENV_FILESIZE_MB = "REDSIM_PLUGIN_SANDBOX_FILESIZE_MB"

# Network-revealing environment variables; only restored to the child when the
# operator explicitly opts a plugin back into the network.
_NETWORK_ENV_KEYS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
    "NO_PROXY", "no_proxy",
)

# Allowlisted environment passed to the untrusted child. We start from an EMPTY
# environment and copy only these keys (when present) so the parent's secrets —
# REDSIM_* (DB URL, worker-signing/Fernet keys, S3 creds), cloud tokens, etc. —
# are never exposed to plugin code. The set is intentionally small: just what a
# Python interpreter needs to start and import the plugin's package.
_SAFE_ENV_KEYS = (
    "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONHASHSEED",
    "VIRTUAL_ENV", "HOME", "TMPDIR", "TEMP", "TMP",
    "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "SYSTEMROOT",
)


@dataclass(frozen=True)
class SandboxConfig:
    """Resource/network policy applied to a sandboxed plugin scanner.

    Defaults are deliberately generous enough for a real scanner yet bounded so
    a runaway plugin is contained. ``timeout_s`` is the wall-clock kill switch;
    ``cpu_seconds`` the CPU rlimit (``RLIMIT_CPU``); ``memory_mb`` the address
    space cap (``RLIMIT_AS``); ``file_size_mb`` the largest file the child may
    write (``RLIMIT_FSIZE``); ``allow_network`` whether proxy env is preserved
    (the sandbox never adds network access — this only refrains from stripping
    it). ``open_files`` caps file descriptors (``RLIMIT_NOFILE``).
    """

    timeout_s: int = 600
    cpu_seconds: int = 300
    memory_mb: int = 1024
    file_size_mb: int = 256
    open_files: int = 256
    max_processes: int = 256
    allow_network: bool = False

    @classmethod
    def from_env(cls, *, timeout_s: int | None = None) -> SandboxConfig:
        """Build a config from ``REDSIM_PLUGIN_SANDBOX_*`` env vars + defaults.

        ``timeout_s`` (when provided, e.g. from the adapter's resolved scan
        timeout) overrides the default wall-clock budget. Malformed numeric env
        values fall back to the default with a warning rather than raising, so a
        typo never hard-fails discovery.
        """
        base = cls()
        return cls(
            timeout_s=timeout_s if timeout_s is not None else base.timeout_s,
            cpu_seconds=_int_env(ENV_CPU_SECONDS, base.cpu_seconds),
            memory_mb=_int_env(ENV_MEMORY_MB, base.memory_mb),
            file_size_mb=_int_env(ENV_FILESIZE_MB, base.file_size_mb),
            open_files=base.open_files,
            allow_network=_bool_env(ENV_NETWORK, base.allow_network),
        )


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("ignoring non-integer %s=%r; using default %d", name, raw, default)
        return default
    return value if value > 0 else default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def sandbox_enabled(config: object | None = None) -> bool:
    """Whether plugin scanners should be sandboxed (default **on**).

    Sandboxing is the secure default for untrusted plugin code; an operator can
    disable it with ``REDSIM_PLUGINS_SANDBOX=0`` (or the ``plugins_sandbox``
    config flag) when running first-party plugins in a trusted context. The env
    var wins over config, mirroring :func:`signing._enforcement_enabled`.
    """
    raw = os.environ.get(ENV_SANDBOX)
    if raw is not None:
        return raw.strip().lower() not in ("0", "false", "no", "off")
    if config is not None:
        return bool(getattr(config, "plugins_sandbox", True))
    return True


def _rlimit_preexec(cfg: SandboxConfig) -> Callable[[], None] | None:
    """Return a ``preexec_fn`` that imposes ``cfg``'s rlimits in the child.

    Returns ``None`` on non-POSIX hosts where ``resource`` is unavailable (the
    sandbox still provides process isolation + the wall-clock timeout). Each
    limit is set with both soft and hard equal to the configured cap; failures
    to set an individual limit are swallowed (best-effort hardening) so the
    child still launches.
    """
    if not _RESOURCE_AVAILABLE:
        return None

    cpu = cfg.cpu_seconds
    mem_bytes = cfg.memory_mb * 1024 * 1024
    fsize_bytes = cfg.file_size_mb * 1024 * 1024
    nofile = cfg.open_files
    nproc = cfg.max_processes
    nproc_res = getattr(resource, "RLIMIT_NPROC", None)

    def _apply() -> None:  # pragma: no cover - runs only in the forked child
        limits = [
            (resource.RLIMIT_CPU, cpu),
            (resource.RLIMIT_AS, mem_bytes),
            (resource.RLIMIT_FSIZE, fsize_bytes),
            (resource.RLIMIT_NOFILE, nofile),
            (resource.RLIMIT_CORE, 0),
        ]
        if nproc_res is not None:
            # Best-effort fork-bomb cap. RLIMIT_NPROC is per-UID, so a cap below
            # the user's current process count simply fails and is skipped; the
            # process-group kill on timeout is the real containment.
            limits.append((nproc_res, nproc))
        for res, limit in limits:
            try:
                resource.setrlimit(res, (limit, limit))
            except (ValueError, OSError):
                pass

    return _apply


def _child_env(cfg: SandboxConfig) -> dict[str, str]:
    """Build a **minimal allowlisted** child environment.

    Critically, this does NOT inherit the parent's full environment: untrusted
    plugin code must never see the parent's secrets (``REDSIM_DB_URL``,
    ``REDSIM_WORKER_SIGNING_KEY``, ``REDSIM_AUTH_PROFILES_KEY``, S3/cloud creds,
    API tokens, …). We copy only ``_SAFE_ENV_KEYS`` (what the interpreter needs
    to start and import the one factory) and pin ``REDSIM_PLUGINS=0`` so the child
    never recurses into plugin discovery. Proxy vars are restored only when the
    operator explicitly opts this plugin back into the network.
    """
    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    env["REDSIM_PLUGINS"] = "0"
    if cfg.allow_network:
        for key in _NETWORK_ENV_KEYS:
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def _options_to_payload(options: ScanOptions) -> dict[str, object]:
    """Serialize ``ScanOptions`` to a JSON-safe dict for the worker request."""
    return {
        "target": options.target,
        "instruction": options.instruction,
        "timeout": options.timeout,
        "scan_mode": options.scan_mode,
        "targets": list(options.targets) if options.targets is not None else None,
        "instruction_file": options.instruction_file,
        "scope_mode": options.scope_mode,
        "diff_base": options.diff_base,
        "extra": dict(options.extra),
    }


def _error_result(
    *, adapter_name: str, command_str: str, started: float, error: str
) -> ScanResult:
    """Assemble the no-finding error envelope (mirrors run_cli_scan)."""
    return ScanResult(
        findings=[],
        adapter_name=adapter_name,
        adapter_version="unknown",
        command_str=command_str,
        exit_code=-1,
        duration_s=time.monotonic() - started,
        error=error,
    )


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    """SIGKILL the worker's whole process group (created via start_new_session).

    ``proc.kill()`` reaps only the direct child, so a plugin that forked its own
    grandchildren would orphan them past the wall-clock timeout. Killing the
    session's process group takes the entire subtree down. Falls back to a plain
    kill if the group is already gone or unavailable (non-POSIX).
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError, AttributeError):
        try:
            proc.kill()
        except OSError:
            pass


def run_scanner_sandboxed(
    entry_point: str,
    run_state: RunStateAPI,
    options: ScanOptions,
    *,
    adapter_name: str,
    config: SandboxConfig,
) -> ScanResult:
    """Run the plugin scanner named by ``entry_point`` out-of-process.

    ``entry_point`` is ``module.path:factory``. The child is launched with a
    list argv (no shell), the configured rlimits + ``timeout``, and a
    network-off environment. The worker's JSON stdout is parsed back into a
    :class:`ScanResult`; any failure (non-zero exit, timeout, unparseable
    output, structured error envelope) becomes a no-finding error result.
    """
    started = time.monotonic()
    argv = [sys.executable, "-m", "redsim.scanners.sandbox_worker",
            "--entry-point", entry_point]
    command_str = " ".join(argv)
    request = json.dumps({
        "run_id": run_state.run_id,
        "run_path": str(run_state.run_path),
        "options": _options_to_payload(options),
    })

    try:
        # start_new_session=True puts the child in its own process group so a
        # timeout can kill the whole subtree (orphaned grandchildren included),
        # not just the direct child.
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_child_env(config),
            preexec_fn=_rlimit_preexec(config),  # noqa: PLW1509 - rlimits must apply in the child
            start_new_session=True,
        )
    except (FileNotFoundError, OSError) as exc:
        return _error_result(
            adapter_name=adapter_name, command_str=command_str, started=started,
            error=f"failed to launch sandbox worker: {exc}",
        )

    try:
        stdout, stderr = proc.communicate(request, timeout=config.timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        try:  # reap so we do not leak a zombie; discard any late output
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return _error_result(
            adapter_name=adapter_name, command_str=command_str, started=started,
            error=f"sandboxed scan timed out after {config.timeout_s}s",
        )

    completed = subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
    return _parse_worker_output(
        completed, adapter_name=adapter_name, command_str=command_str, started=started,
    )


def _parse_worker_output(
    proc: subprocess.CompletedProcess[str],
    *,
    adapter_name: str,
    command_str: str,
    started: float,
) -> ScanResult:
    """Rebuild a :class:`ScanResult` from the worker's JSON stdout envelope."""
    stdout = (proc.stdout or "").strip()
    if not stdout:
        detail = (proc.stderr or "").strip()[:500]
        return _error_result(
            adapter_name=adapter_name, command_str=command_str, started=started,
            error=f"sandbox worker produced no output (exit {proc.returncode}): {detail}",
        )
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return _error_result(
            adapter_name=adapter_name, command_str=command_str, started=started,
            error=f"unparseable sandbox worker output: {exc}",
        )

    if not isinstance(envelope, dict) or not envelope.get("ok"):
        reason = ""
        if isinstance(envelope, dict):
            reason = str(envelope.get("error", ""))
        return _error_result(
            adapter_name=adapter_name, command_str=command_str, started=started,
            error=f"sandboxed plugin failed: {reason}" if reason else "sandboxed plugin failed",
        )

    payload = envelope.get("result") or {}
    findings = [RedsimFinding.from_dict(f) for f in payload.get("findings", [])]
    return ScanResult(
        findings=findings,
        adapter_name=payload.get("adapter_name", adapter_name),
        adapter_version=payload.get("adapter_version", "unknown"),
        command_str=command_str,
        env_keys=list(payload.get("env_keys", [])),
        exit_code=int(payload.get("exit_code", proc.returncode)),
        duration_s=time.monotonic() - started,
        error=payload.get("error"),
    )


class SandboxedScanner:
    """A :class:`ScannerAdapter` whose ``scan()`` runs out-of-process.

    Wraps a discovered plugin adapter, mirroring its public metadata
    (``name`` / ``capabilities`` / ``default_timeout`` / ``adapter_version`` /
    ``health_check``) so it is indistinguishable from the wrapped adapter to the
    registry and dispatcher, but routing ``scan()`` through
    :func:`run_scanner_sandboxed`. Metadata methods (``adapter_version`` /
    ``health_check``) still run in-process: they are cheap, side-effect-light
    probes the wrapped adapter already exposes, and the registry calls them
    during registration before any scan; only ``scan()`` executes untrusted
    work against a target and therefore gets the subprocess boundary.
    """

    def __init__(self, adapter: object, entry_point: str) -> None:
        self._adapter = adapter
        self._entry_point = entry_point
        self.name: str = getattr(adapter, "name")  # noqa: B009 - adapter is typed object
        self.capabilities: set[str] = set(getattr(adapter, "capabilities", set()))
        self.default_timeout: int = int(getattr(adapter, "default_timeout", _DEFAULT_TIMEOUT))

    def adapter_version(self) -> str:
        return str(self._adapter.adapter_version())  # type: ignore[attr-defined]

    def health_check(self) -> bool:
        return bool(self._adapter.health_check())  # type: ignore[attr-defined]

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        timeout = (self.default_timeout if options.timeout == _DEFAULT_TIMEOUT
                   else options.timeout)
        cfg = SandboxConfig.from_env(timeout_s=timeout)
        return run_scanner_sandboxed(
            self._entry_point, run_state, options,
            adapter_name=self.name, config=cfg,
        )


def entry_point_ref(ep: object, factory: object) -> str | None:
    """Derive a ``module:attr`` reference the sandbox worker can re-import.

    Prefers the entry point's own ``.value`` (``importlib.metadata`` exposes the
    ``module:attr`` string declared in ``pyproject.toml``). Falls back to the
    loaded factory's ``__module__`` + ``__qualname__`` for fakes/tests that lack
    a ``.value``. Returns ``None`` when neither yields a usable, top-level
    reference (e.g. a lambda or a nested function the child could not import) —
    the caller then skips sandboxing and logs.
    """
    value = getattr(ep, "value", None)
    if isinstance(value, str) and ":" in value:
        module, _, attr = value.partition(":")
        # ``module:attr [extras]`` — drop any extras suffix.
        attr = attr.split("[", 1)[0].strip()
        module = module.strip()
        if module and attr and "." not in attr:
            return f"{module}:{attr}"

    module_name = getattr(factory, "__module__", None)
    qualname = getattr(factory, "__qualname__", None)
    if (isinstance(module_name, str) and isinstance(qualname, str)
            and module_name not in ("__main__", "")
            and "." not in qualname and "<" not in qualname):
        return f"{module_name}:{qualname}"
    return None
