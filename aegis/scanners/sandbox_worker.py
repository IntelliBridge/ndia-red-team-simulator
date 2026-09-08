"""Subprocess entry point that runs one plugin scanner out-of-process.

This is the child half of the plugin sandbox (the parent is
:mod:`aegis.scanners.sandbox`). It is launched as a module —
``python -m aegis.scanners.sandbox_worker`` — with a single ``--entry-point``
argument naming the plugin factory (``pkg.module:create_scanner``). The contract
is a JSON document on **stdin** and a JSON document on **stdout**; nothing else
is written to stdout (diagnostics go to stderr), so the parent can parse the
result deterministically.

Request (stdin)::

    {"run_id": "...", "run_path": "/abs/run/dir", "options": {<ScanOptions>}}

Response (stdout)::

    {"ok": true,  "result": {<ScanResult-as-dict>}}
    {"ok": false, "error": "<message>"}

The worker imports the factory *inside* the sandboxed process, instantiates the
adapter, and invokes ``adapter.scan(run_state, options)`` against a filesystem
:class:`~aegis.state.RunState` rooted at ``run_path``. Because the import and
the scan both happen here, an exploding plugin can crash only this short-lived
child — the parent observes a non-zero exit / error envelope and surfaces a
clean :class:`~aegis.scanners.registry.ScanResult` error instead of dying.

Resource limits, the wall-clock timeout, and the network-off environment are
imposed by the *parent* (see :mod:`aegis.scanners.sandbox`) before this code
runs; the worker itself stays deliberately small and dependency-light.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from importlib import import_module
from pathlib import Path
from typing import Any

# Stdout (fd 1) is the JSON result channel; nothing the plugin emits may corrupt
# it. ``main`` dups the real stdout to a private fd and then points fd 1 (and
# ``sys.stdout``) at stderr, so even a raw ``os.write(1, ...)`` or a child
# process that inherits stdout lands on stderr instead of the envelope. The
# private dup is stored here. ``run`` is importable/unit-testable without it.
_RESULT_STREAM: Any = None


def _parse_entry_point(spec: str) -> tuple[str, str]:
    """Split a ``module.path:attr`` entry-point spec into ``(module, attr)``.

    Mirrors the ``aegis.scanners:example`` form used across the marketplace
    tooling (the CLI ``plugins sign --entry-point`` flag and the entry-point
    metadata). Raises ``ValueError`` on a malformed spec.
    """
    module, sep, attr = spec.partition(":")
    if not sep or not module or not attr:
        raise ValueError(
            f"invalid entry point {spec!r}; expected 'module.path:factory'"
        )
    return module, attr


def _load_factory(spec: str) -> Any:
    """Import ``module:attr`` and return the referenced factory callable."""
    module_name, attr = _parse_entry_point(spec)
    module = import_module(module_name)
    factory = getattr(module, attr, None)
    if factory is None:
        raise AttributeError(f"{module_name!r} has no attribute {attr!r}")
    return factory


def _build_options(payload: dict[str, Any]) -> Any:
    """Reconstruct a :class:`ScanOptions` from the request's ``options`` dict.

    Unknown keys are dropped (forward-compatible with a parent that learns new
    option fields) and ``extra`` is preserved verbatim.
    """
    from aegis.scanners.registry import ScanOptions

    known = {f for f in ScanOptions.__dataclass_fields__}
    kwargs = {k: v for k, v in payload.items() if k in known}
    return ScanOptions(**kwargs)


def run(spec: str, request: dict[str, Any]) -> dict[str, Any]:
    """Run the named plugin scanner for one request and return the envelope.

    Pure-ish core (no process exit, no stdout writes) so it is unit-testable in
    process: returns the success/error dict the caller serializes to stdout.
    """
    from aegis.scanners.registry import ScanResult

    run_path = Path(request["run_path"])
    run_id = str(request.get("run_id") or run_path.name)
    options = _build_options(request.get("options") or {})
    factory = _load_factory(spec)
    adapter = factory()

    run_state = _open_run_state(run_path, run_id)
    result = adapter.scan(run_state, options)
    if not isinstance(result, ScanResult):
        raise TypeError(
            f"plugin scanner {getattr(adapter, 'name', spec)!r} returned "
            f"{type(result).__name__}, expected ScanResult"
        )
    return {"ok": True, "result": _result_to_dict(result)}


def _open_run_state(run_path: Path, run_id: str) -> Any:
    """Build a filesystem :class:`RunState` pinned to the parent's run dir.

    ``FilesystemRunState`` derives every artifact path from ``run_path``. When
    the parent's path follows the canonical ``<output_dir>/runs/<run_id>``
    layout we reconstruct ``output_dir`` so the backend resolves the same path
    natively. Otherwise we construct against ``run_path`` and pin the attributes
    so the plugin still writes into the real run directory. Either way the
    resulting ``run_path``/``run_id`` equal exactly what the parent handed us.
    """
    from aegis.state import RunState

    run_path.mkdir(parents=True, exist_ok=True)
    if run_path.name == run_id and run_path.parent.name == "runs":
        return RunState(str(run_path.parent.parent), run_id=run_id)
    state = RunState(str(run_path), run_id=run_id)
    state.output_dir = run_path.parent
    state.run_path = run_path
    state.run_id = run_id
    return state


def _result_to_dict(result: Any) -> dict[str, Any]:
    """Serialize a :class:`ScanResult` (findings → dicts) for the JSON channel."""
    return {
        "findings": [f.to_dict() for f in result.findings],
        "adapter_name": result.adapter_name,
        "adapter_version": result.adapter_version,
        "command_str": result.command_str,
        "env_keys": list(result.env_keys),
        "exit_code": result.exit_code,
        "duration_s": result.duration_s,
        "error": result.error,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry: read the JSON request from stdin, emit the JSON envelope.

    Returns a process exit code: ``0`` on a produced envelope (success *or* a
    structured ``{"ok": false}`` error — both are valid results the parent
    parses), ``2`` only when the request itself could not be read/parsed (no
    usable envelope could be formed).
    """
    parser = argparse.ArgumentParser(prog="aegis.scanners.sandbox_worker")
    parser.add_argument("--entry-point", required=True,
                        help="plugin factory as 'module.path:create_scanner'")
    args = parser.parse_args(argv)

    # Move the JSON result channel out of the plugin's reach: dup the real
    # stdout to a private fd, then point fd 1 (and sys.stdout) at stderr. Any
    # plugin write to stdout — including raw os.write(1, ...) or a child process
    # inheriting fd 1 — then lands on stderr and cannot corrupt the envelope.
    # When a unit test has injected _RESULT_STREAM we skip the fd surgery and
    # write straight to it (no real fds to protect in-process).
    global _RESULT_STREAM
    if _RESULT_STREAM is None:
        _real_stdout_fd = os.dup(1)
        os.dup2(2, 1)
        _RESULT_STREAM = os.fdopen(_real_stdout_fd, "w", closefd=True)
    sys.stdout = sys.stderr

    try:
        raw = sys.stdin.read()
        request = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError) as exc:
        _emit({"ok": False, "error": f"unreadable sandbox request: {exc}"})
        return 2

    try:
        envelope = run(args.entry_point, request)
    except Exception as exc:  # any plugin failure → structured error envelope
        envelope = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    _emit(envelope)
    return 0


def _emit(envelope: dict[str, Any]) -> None:
    """Write the single JSON result line to the private real-stdout dup."""
    stream = _RESULT_STREAM if _RESULT_STREAM is not None else sys.__stdout__
    if stream is not None:
        stream.write(json.dumps(envelope))
        stream.flush()


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
