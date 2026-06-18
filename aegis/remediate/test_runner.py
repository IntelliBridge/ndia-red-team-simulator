"""Run an operator-configured project test command after a patch is applied.

Cluster C13 (iterative-agent-loops): the remediation loop applies a generated
patch to the repo and then runs the project's own test suite to decide whether
the fix is good. This module owns that single, deliberately small step.

SECURITY: the test command is **operator-configured** (``config.remediation_test_command``
/ ``AEGIS_REMEDIATION_TEST_COMMAND``) and is *never* derived from untrusted
finding or patch content. It is split with :func:`shlex.split` and executed as
an explicit argv list via :func:`subprocess.run` — we never pass ``shell=True``,
so a malicious finding/diff cannot inject shell metacharacters into the command
line. The command runs with ``cwd`` pinned to the repository under test.
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Cap captured output so a runaway test suite can't blow up memory / the prompt
# we feed back to the agent. We keep the *tail* (failures usually surface last).
_MAX_CAPTURE_CHARS = 16_000

DEFAULT_TEST_TIMEOUT_SECONDS = 600


@dataclass
class TestRunResult:
    """Outcome of running the operator-configured project test command."""

    ran: bool
    passed: bool
    returncode: int | None
    stdout: str
    stderr: str
    command: list[str]
    error: str | None = None

    @property
    def combined_output(self) -> str:
        """stdout + stderr, tail-truncated — what we feed back to the agent."""
        parts = [self.stdout.strip(), self.stderr.strip()]
        return _tail("\n".join(p for p in parts if p))


def _tail(text: str, *, limit: int = _MAX_CAPTURE_CHARS) -> str:
    if len(text) <= limit:
        return text
    return "...[truncated]...\n" + text[-limit:]


def parse_test_command(command: str | None) -> list[str] | None:
    """Split an operator-configured command string into an argv list.

    Returns ``None`` when no command is configured (or it is blank/unparseable),
    which the caller treats as "no test gate — fall through to the single-shot
    patch path". Uses :func:`shlex.split` so the result is a plain argv list with
    no shell interpretation at execution time.
    """
    if not command or not command.strip():
        return None
    try:
        argv = shlex.split(command)
    except ValueError:
        logger.warning("remediation_test_command is not parseable; ignoring")
        return None
    return argv or None


def run_project_tests(
    repo_path: Path | str,
    command_argv: list[str],
    *,
    timeout: float = DEFAULT_TEST_TIMEOUT_SECONDS,
) -> TestRunResult:
    """Execute the operator-configured test command in ``repo_path``.

    ``command_argv`` MUST be a pre-parsed argv list (see
    :func:`parse_test_command`) — this function never re-parses a string and
    never uses ``shell=True``. A zero exit code is success; any non-zero exit,
    timeout, or launch failure is a (non-raising) failure with the captured
    output preserved for feedback to the agent.
    """
    repo = Path(repo_path)
    try:
        proc = subprocess.run(
            command_argv,
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return TestRunResult(
            ran=False, passed=False, returncode=None, stdout="", stderr="",
            command=command_argv, error=f"test command not found: {exc}",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return TestRunResult(
            ran=True, passed=False, returncode=None,
            stdout=_tail(stdout), stderr=_tail(stderr),
            command=command_argv,
            error=f"test command timed out after {timeout}s",
        )
    return TestRunResult(
        ran=True, passed=proc.returncode == 0, returncode=proc.returncode,
        stdout=_tail(proc.stdout or ""), stderr=_tail(proc.stderr or ""),
        command=command_argv,
    )
