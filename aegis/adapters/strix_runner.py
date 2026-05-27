"""Subprocess-based Strix runner with live events.jsonl tailing.

We treat Strix as an external CLI tool. The command is discovered in this
order:
  1. ``config.strix_command`` (override).
  2. ``shutil.which("strix")``.
  3. ``python -m strix`` with PYTHONPATH=<config.strix_path>/src.

The runner streams the Strix process stdout/stderr to ``strix/strix.log``,
records the command and (key-only) environment to ``strix/run.json``, and
tails ``strix/events.jsonl`` until the process exits — dedup'd by finding
``id``. If the process exits non-zero but at least one finding was emitted,
the result is ``partial_success`` and findings are preserved.
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
from typing import Callable, Iterable

from aegis.adapters.strix_adapter import convert_strix_finding
from aegis.schema import AegisFinding
from aegis.state import RunState


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
    while True:
        if events_path.exists():
            with open(events_path) as fh:
                fh.seek(position)
                new_lines = fh.readlines()
                position = fh.tell()
            if new_lines:
                batch = parse_events_lines(new_lines, run_id, seen_ids)
                findings.extend(batch)
                if on_finding:
                    for f in batch:
                        on_finding(f)
        if is_done():
            # Drain a couple more times in case the producer flushed late.
            for _ in range(final_drain_passes):
                if events_path.exists():
                    with open(events_path) as fh:
                        fh.seek(position)
                        new_lines = fh.readlines()
                        position = fh.tell()
                    if new_lines:
                        batch = parse_events_lines(new_lines, run_id, seen_ids)
                        findings.extend(batch)
                        if on_finding:
                            for f in batch:
                                on_finding(f)
            return findings
        time.sleep(interval)


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
    run_state: RunState,
    *,
    instruction: str | None = None,
    timeout: int = 1800,
    llm_env: dict[str, str] | None = None,
    strix_command: str | None = None,
    strix_path: str | None = None,
    on_finding: Callable[[AegisFinding], None] | None = None,
    skip_docker_check: bool = False,
) -> StrixRunResult:
    strix_dir = run_state.run_path / "strix"
    strix_dir.mkdir(parents=True, exist_ok=True)
    events_path = strix_dir / "events.jsonl"
    log_path = strix_dir / "strix.log"

    if not skip_docker_check and not docker_available():
        return StrixRunResult(
            success=False, partial_success=False, return_code=-1,
            command=[], log_path=str(log_path), events_path=str(events_path),
            error="docker is not available — start Docker Desktop or the daemon",
        )

    try:
        cmd_prefix, env_additions = discover_strix_command(
            strix_command=strix_command, strix_path=strix_path,
        )
    except FileNotFoundError as exc:
        return StrixRunResult(
            success=False, partial_success=False, return_code=-1,
            command=[], log_path=str(log_path), events_path=str(events_path),
            error=str(exc),
        )

    cmd = list(cmd_prefix) + ["--target", target, "-n", "--output-dir", str(strix_dir)]
    if instruction:
        cmd += ["--instruction", instruction]

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
        proc = subprocess.Popen(
            cmd, stdout=log_fh, stderr=subprocess.STDOUT,
            env=env, cwd=str(run_state.run_path),
        )
    except FileNotFoundError as exc:
        log_fh.close()
        return StrixRunResult(
            success=False, partial_success=False, return_code=-1,
            command=cmd, log_path=str(log_path), events_path=str(events_path),
            error=f"failed to launch strix: {exc}",
        )

    started = time.monotonic()

    def is_done() -> bool:
        if time.monotonic() - started > timeout:
            try:
                proc.terminate()
            except Exception:
                pass
            return True
        return proc.poll() is not None

    findings = tail_events(
        events_path, run_state.run_id,
        on_finding=on_finding, is_done=is_done,
    )
    return_code = proc.wait()
    log_fh.close()

    return StrixRunResult(
        success=return_code == 0,
        partial_success=return_code != 0 and bool(findings),
        return_code=return_code,
        findings=findings,
        command=cmd,
        log_path=str(log_path),
        events_path=str(events_path),
        error=None if return_code == 0 else f"strix exited with code {return_code}",
    )
