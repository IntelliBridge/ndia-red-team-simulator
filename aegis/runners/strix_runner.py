"""Subprocess-based Strix runner with live events.jsonl tailing.

We treat Strix as an external CLI tool. The command is discovered in this
order:
  1. ``config.strix_command`` (override).
  2. ``shutil.which("strix")``.
  3. ``python -m strix`` with PYTHONPATH=<config.strix_path>/src.

The runner streams the Strix process stdout/stderr to ``strix/strix.log``
and records the command and (key-only) environment to ``strix/run.json``.

Strix itself writes each run under ``<cwd>/strix_runs/<run_name>/`` with its
events at ``<cwd>/strix_runs/<run_name>/events.jsonl`` (the run name is
auto-generated). We therefore launch Strix with ``cwd`` set to the per-run
``strix/`` directory and, once the process exits, discover the newest
``strix/strix_runs/*/events.jsonl`` and parse it — dedup'd by finding ``id``.
If the process exits non-zero but at least one finding was emitted, the
result is ``partial_success`` and findings are preserved. A missing events
file degrades gracefully to an empty findings list.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable

from aegis.runners.strix_converter import convert_strix_finding
from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.state import RunStateAPI


@dataclass
class StrixRunResult:
    success: bool                     # True only when return_code == 0
    partial_success: bool             # findings emitted even though rc != 0
    return_code: int
    findings: list[AegisFinding] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    log_path: str | None = None
    events_path: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Strix command discovery
# ---------------------------------------------------------------------------

def discover_strix_command(
    *,
    strix_command: str | None = None,
    strix_path: str | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Return (argv prefix, env additions) for invoking Strix.

    Raises FileNotFoundError if no viable command can be found.
    """
    if strix_command:
        return list(strix_command.split()), {}

    found = shutil.which("strix")
    if found:
        return [found], {}

    if strix_path:
        src = Path(strix_path) / "src"
        if src.is_dir():
            return [sys.executable, "-m", "strix"], {"PYTHONPATH": str(src)}

    raise FileNotFoundError(
        "Strix CLI not found. Set config.strix_command, install `strix` on PATH, "
        "or ensure config.strix_path/src is importable."
    )


# ---------------------------------------------------------------------------
# Event tailing
# ---------------------------------------------------------------------------

def parse_events_lines(lines: Iterable[str], run_id: str,
                       seen_ids: set[str]) -> list[AegisFinding]:
    findings: list[AegisFinding] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "finding.created":
            continue
        report = None
        payload = event.get("payload")
        if isinstance(payload, dict):
            report = payload.get("report") or payload
        if report is None and isinstance(event.get("data"), dict):
            report = event["data"]
        if not isinstance(report, dict) or "id" not in report:
            continue
        fid = report["id"]
        if fid in seen_ids:
            continue
        seen_ids.add(fid)
        findings.append(convert_strix_finding(report, run_id))
    return findings


def tail_events(
    events_path: Path,
    run_id: str,
    *,
    on_finding: Callable[[AegisFinding], None] | None = None,
    is_done: Callable[[], bool],
    interval: float = 0.5,
    final_drain_passes: int = 2,
) -> list[AegisFinding]:
    """Follow events.jsonl until ``is_done()`` is True, then drain remaining lines.

    Returns the list of new findings (dedup'd by id).
    """
    findings: list[AegisFinding] = []
    seen_ids: set[str] = set()
    position = 0

    def _drain(pos: int) -> int:
        if events_path.exists():
            with open(events_path) as fh:
                fh.seek(pos)
                new_lines = fh.readlines()
                pos = fh.tell()
            if new_lines:
                batch = parse_events_lines(new_lines, run_id, seen_ids)
                findings.extend(batch)
                if on_finding:
                    for f in batch:
                        on_finding(f)
        return pos

    while True:
        position = _drain(position)
        if is_done():
            # Drain a couple more times in case the producer flushed late.
            for _ in range(final_drain_passes):
                position = _drain(position)
            return findings
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Strix run-output discovery
# ---------------------------------------------------------------------------

VALID_SCAN_MODES = frozenset({"quick", "standard", "deep"})
VALID_SCOPE_MODES = frozenset({"auto", "diff", "full"})


def discover_events_path(strix_dir: Path) -> Path | None:
    """Return the newest ``strix_dir/strix_runs/*/events.jsonl``, or None.

    Strix auto-generates a run-name subdirectory under ``strix_runs/`` and
    writes its events there, so the concrete path is not known until after the
    process has run. Pick the most recently modified candidate.
    """
    candidates = list(strix_dir.glob("strix_runs/*/events.jsonl"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def docker_available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_strix(
    target: str,
    run_state: RunStateAPI,
    *,
    instruction: str | None = None,
    timeout: int = 1800,
    scan_mode: str = "standard",
    targets: list[str] | None = None,
    instruction_file: str | None = None,
    scope_mode: str = "auto",
    diff_base: str | None = None,
    llm_env: dict[str, str] | None = None,
    strix_command: str | None = None,
    strix_path: str | None = None,
    on_finding: Callable[[AegisFinding], None] | None = None,
    skip_docker_check: bool = False,
) -> StrixRunResult:
    strix_dir = run_state.run_path / "strix"
    strix_dir.mkdir(parents=True, exist_ok=True)
    log_path = strix_dir / "strix.log"
    # Strix writes events under strix_dir/strix_runs/<auto-name>/events.jsonl;
    # the concrete path is discovered after the process runs. Until then this
    # placeholder only labels the pre-run error returns (no events exist yet).
    events_path: Path | None = None

    def _err(msg: str, command: list[str] | None = None) -> StrixRunResult:
        return StrixRunResult(
            success=False, partial_success=False, return_code=-1,
            command=command or [], log_path=str(log_path), events_path=str(strix_dir),
            error=msg,
        )

    if not skip_docker_check and not docker_available():
        return _err("docker is not available — start Docker Desktop or the daemon")

    try:
        cmd_prefix, env_additions = discover_strix_command(
            strix_command=strix_command, strix_path=strix_path,
        )
    except FileNotFoundError as exc:
        return _err(str(exc))

    if scan_mode not in VALID_SCAN_MODES:
        scan_mode = "standard"
    if scope_mode not in VALID_SCOPE_MODES:
        scope_mode = "auto"

    # Strix's -t/--target is repeatable (action="append"); a single-target call
    # (targets None/empty) emits exactly one --target, identical to before.
    effective_targets = targets if targets else [target]
    target_args: list[str] = []
    for t in effective_targets:
        target_args += ["--target", t]

    cmd = list(cmd_prefix) + target_args + ["-n", "--scan-mode", scan_mode,
                                            "--scope-mode", scope_mode]
    # --instruction and --instruction-file are mutually exclusive at Strix
    # (it calls parser.error if both are given); prefer the file when set.
    if instruction_file:
        cmd += ["--instruction-file", instruction_file]
    elif instruction:
        cmd += ["--instruction", instruction]
    if diff_base:
        cmd += ["--diff-base", diff_base]

    env = os.environ.copy()
    env.update(env_additions)
    if llm_env:
        env.update(llm_env)

    # Persist invocation metadata (env *keys* only — never values).
    (strix_dir / "run.json").write_text(json.dumps({
        "command": cmd, "env_keys": sorted(env_additions.keys() | (llm_env.keys() if llm_env else set())),
        "started_at": time.time(),
    }, indent=2))

    log_fh = open(log_path, "wb")
    try:
        # Launch with cwd=strix_dir so Strix's strix_runs/ tree lands there
        # predictably (strix uses Path.cwd() / "strix_runs").
        proc = subprocess.Popen(
            cmd, stdout=log_fh, stderr=subprocess.STDOUT,
            env=env, cwd=str(strix_dir),
        )
    except FileNotFoundError as exc:
        log_fh.close()
        return _err(f"failed to launch strix: {exc}", command=cmd)

    started = time.monotonic()

    def is_done() -> bool:
        if time.monotonic() - started > timeout:
            try:
                proc.terminate()
            except Exception:
                pass
            return True
        return proc.poll() is not None

    # Strix creates its strix_runs/<name>/ subdir shortly after launch, so the
    # events file path is not known up front. Poll for it while the process
    # runs; once it appears we can tail it live (preserving on_finding
    # streaming). If the process exits before it ever appears, fall back to a
    # final glob of the newest strix_runs/*/events.jsonl.
    findings: list[AegisFinding] = []
    while True:
        events_path = discover_events_path(strix_dir)
        if events_path is not None:
            findings = tail_events(
                events_path, run_state.run_id,
                on_finding=on_finding, is_done=is_done,
            )
            break
        if is_done():
            # Process finished without ever creating an events file; make one
            # last attempt to discover late-flushed output.
            events_path = discover_events_path(strix_dir)
            if events_path is not None:
                findings = tail_events(
                    events_path, run_state.run_id,
                    on_finding=on_finding, is_done=lambda: True,
                )
            break
        time.sleep(0.5)

    return_code = proc.wait()
    log_fh.close()

    return StrixRunResult(
        success=return_code == 0,
        partial_success=return_code != 0 and bool(findings),
        return_code=return_code,
        findings=findings,
        command=cmd,
        log_path=str(log_path),
        events_path=str(events_path) if events_path is not None else str(strix_dir),
        error=None if return_code == 0 else f"strix exited with code {return_code}",
    )
