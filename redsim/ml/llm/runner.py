"""Worker-parent side of a probe run: work directory, key file, child environment, wall clock (LLM-10, -18, -33).

The probe child is a network-capable, credential-minimised process, not the
network-less model sandbox of ``redsim.ml.sandbox``: it must reach the Pythia
gateway, so proxy and TLS variables survive, but it receives nothing else the
worker holds. Concretely :func:`build_child_env` starts from the interpreter
allowlist the plugin sandbox uses (``redsim.scanners.sandbox._child_env`` with
``allow_network=True``), moves ``HOME`` and ``TMPDIR`` into the work directory,
adds the TLS variables (``SSL_CERT_FILE``, ``REQUESTS_CA_BUNDLE``,
``REDSIM_TLS_TRUSTSTORE``, ``REDSIM_CA_BUNDLE``), garak's XDG directories and
log file under the work directory, the Hugging Face offline pins, and pins
``REDSIM_ENV_FILE`` to an absent file so no ``.env`` can be read in the child.
A final sweep removes every ``PYTHIA_*``, ``AWS_*``, ``KAGGLE*``, ``OPENAI*``,
``HF_TOKEN``, ``HUGGING_FACE*`` and every other ``REDSIM_*`` name: no database
URL, no S3 or Fernet key, no worker signing key, and no probe key in the
environment. The key travels only through a 0600 file in the 0700 work
directory that the child deletes after reading and the parent deletes again
in ``finally``.

:func:`run_probe_child` launches ``python -m redsim.ml.llm.probe_child`` in its
own session with the plugin sandbox's rlimits, waits on a wall clock
(``REDSIM_LLM_PROBE_TIMEOUT_S``, default 1500 s, below the Celery soft limit),
kills the whole process group on timeout or cancellation, and returns a
:class:`ChildOutcome` with the parsed ``child_result.json``, the paths of the
files the worker may store (``report.jsonl``, ``hitlog.jsonl``, the digest
HTML, ``usage.json``) and the ones it must discard (``garak.log`` holds prompts
and responses at DEBUG). Every excerpt of child output is scrubbed of the key
before it reaches a log or a result.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from redsim.ml.errors import MLError
from redsim.ml.llm.probe_child import (
    ENV_KEYS_FILE,
    GARAK_DIR,
    GARAK_LOG_FILE,
    KEY_FILE,
    PROGRESS_FILE,
    REPORT_PREFIX,
    RESULT_FILE,
    SPEC_FILE,
    USAGE_FILE,
    ChildResult,
    LLMProbeChildSpec,
    ProgressSnapshot,
    scrub_text,
)

logger = logging.getLogger(__name__)

#: A ``progress.json`` larger than this is not the child's one-line snapshot and is read as absent.
PROGRESS_MAX_BYTES = 64 * 1024

ENV_TIMEOUT_S = "REDSIM_LLM_PROBE_TIMEOUT_S"
ENV_CPU_SECONDS = "REDSIM_LLM_PROBE_CPU_SECONDS"
ENV_MEMORY_MB = "REDSIM_LLM_PROBE_MEMORY_MB"
ENV_FILESIZE_MB = "REDSIM_LLM_PROBE_FILESIZE_MB"
ENV_MAX_PROCESSES = "REDSIM_LLM_PROBE_MAX_PROCESSES"
ENV_KEEP_WORK_DIR = "REDSIM_ML_KEEP_WORK_DIR"
#: Celery ``task_soft_time_limit`` of the worker (redsim/workers/celery_app.py); the wall clock stays below it.
CELERY_SOFT_LIMIT_S = 1800

#: TLS and proxy names the child keeps (behind the corporate proxy; none on Fargate).
TLS_ENV_KEYS: tuple[str, ...] = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "REDSIM_TLS_TRUSTSTORE", "REDSIM_CA_BUNDLE")
PROXY_ENV_KEYS: tuple[str, ...] = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")
#: The only ``REDSIM_*`` names the child may see: two TLS settings and two pins. Never a secret.
ALLOWED_REDSIM_KEYS: frozenset[str] = frozenset({"REDSIM_TLS_TRUSTSTORE", "REDSIM_CA_BUNDLE", "REDSIM_ENV_FILE", "REDSIM_PLUGINS"})
#: Prefixes swept from the child environment after the allowlist is applied.
FORBIDDEN_ENV_PREFIXES: tuple[str, ...] = ("PYTHIA_", "AWS_", "KAGGLE", "OPENAI", "HF_TOKEN", "HUGGING_FACE", "GOOGLE_", "AZURE_", "ANTHROPIC_")
NO_ENV_FILE_NAME = "no-env"

OutcomeStatus = Literal["succeeded", "failed", "timed_out", "cancelled"]


class ProbeChildTimeout(MLError):
    """The probe child exceeded its wall clock; the process group was killed and partial files kept."""

    code = "probe_child_timeout"


class ProbeChildFailed(MLError):
    """The probe child exited non-zero; ``child_result.json`` (when written) carries the reason."""

    code = "probe_child_failed"


class ProbeChildCancelled(MLError):
    """The run was cancelled while the child was running; the process group was killed."""

    code = "probe_child_cancelled"


def _int_env(name: str, default: int, environ: Mapping[str, str]) -> int:
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class ProbeRunnerConfig:
    """Wall clock and rlimits of the probe child (``REDSIM_LLM_PROBE_*``)."""

    timeout_s: int = 1500
    cpu_seconds: int = 1200
    memory_mb: int = 4096
    file_size_mb: int = 1024
    open_files: int = 256
    max_processes: int = 64
    keep_work_dir: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ProbeRunnerConfig:
        env = os.environ if environ is None else environ
        base = cls()
        cfg = cls(
            timeout_s=_int_env(ENV_TIMEOUT_S, base.timeout_s, env),
            cpu_seconds=_int_env(ENV_CPU_SECONDS, base.cpu_seconds, env),
            memory_mb=_int_env(ENV_MEMORY_MB, base.memory_mb, env),
            file_size_mb=_int_env(ENV_FILESIZE_MB, base.file_size_mb, env),
            max_processes=_int_env(ENV_MAX_PROCESSES, base.max_processes, env),
            keep_work_dir=env.get(ENV_KEEP_WORK_DIR, "").strip().lower() in {"1", "true", "yes", "on"},
        )
        if cfg.timeout_s >= CELERY_SOFT_LIMIT_S:
            logger.warning("%s=%d is not below the Celery soft limit (%ds)", ENV_TIMEOUT_S, cfg.timeout_s, CELERY_SOFT_LIMIT_S)
        return cfg


@dataclass
class ChildOutcome:
    """What the parent knows after the child exits (or is killed)."""

    status: OutcomeStatus
    exit_code: int | None
    work_dir: Path
    wall_time_s: float
    result: ChildResult | None = None
    progress: ProgressSnapshot | None = None                         # the last snapshot the parent observed
    files: dict[str, Path | None] = field(default_factory=dict)      # storable: report, hitlog, digest, usage
    discard: dict[str, Path | None] = field(default_factory=dict)    # never stored: garak.log, config, stdout/stderr, progress
    stdout_tail: str = ""
    stderr_tail: str = ""
    env_keys: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "succeeded" and self.result is not None and self.result.status == "succeeded"

    def raise_for_status(self) -> None:
        if self.succeeded:
            return
        if self.status == "timed_out":
            raise ProbeChildTimeout(self.error or "probe child timed out")
        if self.status == "cancelled":
            raise ProbeChildCancelled(self.error or "probe run cancelled")
        detail = self.error or (self.result.error if self.result is not None else None) or "probe child failed"
        if self.result is not None and self.result.error_type:
            detail = f"{self.result.error_type}: {detail}"
        raise ProbeChildFailed(detail)

    def cleanup(self, *, keep: bool | None = None) -> None:
        """Remove the work directory (garak.log, xdg cache, partial files). ``keep`` overrides the env pin."""
        keep_it = ProbeRunnerConfig.from_env().keep_work_dir if keep is None else keep
        if keep_it:
            return
        shutil.rmtree(self.work_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Work directory, key file, environment
# ---------------------------------------------------------------------------


def prepare_work_dir(job_id: str | None = None, *, root: Path | None = None) -> Path:
    """A fresh 0700 directory: ``<root>/llm-<job_id>`` or a temp name under the ML work-dir root."""
    if root is None:
        from redsim.ml.sandbox import work_dir_root

        root = work_dir_root()
    root.mkdir(parents=True, exist_ok=True)
    if job_id:
        from redsim.ml.sandbox import _JOB_DIR_NAME

        if not _JOB_DIR_NAME.match(job_id):
            raise ValueError(f"job id {job_id!r} is not usable as a work directory name")
        path = root / f"llm-{job_id}"
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
        path.mkdir(mode=0o700)
    else:
        path = Path(tempfile.mkdtemp(prefix="llm-", dir=root))
    os.chmod(path, 0o700)
    return path


def write_key_file(work_dir: Path, api_key: str) -> Path:
    """The probe key as a 0600 file the child reads once and deletes."""
    if not api_key or not api_key.strip():
        raise ValueError("probe key is empty")
    path = work_dir / KEY_FILE
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, api_key.strip().encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


def build_child_env(work_dir: Path, *, hf_home: str | None = None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The child's environment: interpreter allowlist, TLS and proxy, garak pins. No credential of any kind."""
    from redsim.scanners.sandbox import SandboxConfig, _child_env

    source = os.environ if environ is None else environ
    saved = os.environ.copy() if environ is not None else None
    try:
        if saved is not None:
            os.environ.clear()
            os.environ.update(source)
        env = _child_env(SandboxConfig(allow_network=True))
    finally:
        if saved is not None:
            os.environ.clear()
            os.environ.update(saved)
    import redsim

    package_root = str(Path(redsim.__file__).resolve().parents[1])
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = package_root if not existing else f"{package_root}{os.pathsep}{existing}"
    env.update({
        "HOME": str(work_dir),
        "TMPDIR": str(work_dir),
        "TEMP": str(work_dir),
        "TMP": str(work_dir),
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "REDSIM_PLUGINS": "0",
        "REDSIM_ENV_FILE": str(work_dir / NO_ENV_FILE_NAME),
        "XDG_DATA_HOME": str(work_dir / "xdg" / "data"),
        "XDG_CONFIG_HOME": str(work_dir / "xdg" / "config"),
        "XDG_CACHE_HOME": str(work_dir / "xdg" / "cache"),
        "GARAK_LOG_FILE": str(work_dir / GARAK_LOG_FILE),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "TOKENIZERS_PARALLELISM": "false",
    })
    for key in TLS_ENV_KEYS + PROXY_ENV_KEYS:
        if key in source and source[key]:
            env[key] = source[key]
    if hf_home:
        env["HF_HOME"] = str(hf_home)
    for key in list(env):
        upper = key.upper()
        if upper.startswith(FORBIDDEN_ENV_PREFIXES) or (upper.startswith("REDSIM_") and key not in ALLOWED_REDSIM_KEYS):
            del env[key]
    assert_child_env_minimal(env)
    return env


def assert_child_env_minimal(env: Mapping[str, str]) -> None:
    """Raise when a credential-bearing name survived; the boundary test calls this too."""
    leaked = sorted(
        k for k in env
        if k.upper().startswith(FORBIDDEN_ENV_PREFIXES) or (k.upper().startswith("REDSIM_") and k not in ALLOWED_REDSIM_KEYS)
    )
    if leaked:
        raise RuntimeError(f"credential-bearing names in the probe child environment: {leaked}")


def scrub_output(text: str, *secrets: str) -> str:
    """Replace every supplied secret and every ``pk_…`` shape; pure Python, so the parent needs no garak."""
    return scrub_text(text, *secrets)


def _tail(path: Path, *secrets: str, limit: int = 4000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return scrub_output(data[-limit:], *secrets)


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def _load_result(work_dir: Path, *secrets: str) -> ChildResult | None:
    path = work_dir / RESULT_FILE
    if not path.is_file():
        return None
    try:
        text = scrub_output(path.read_text(encoding="utf-8"), *secrets)
        return ChildResult.model_validate_json(text)
    except Exception as exc:  # noqa: BLE001 - an unreadable result is reported as absent
        logger.warning("child_result.json unreadable: %s", type(exc).__name__)
        return None


def _read_progress(work_dir: Path, *secrets: str) -> ProgressSnapshot | None:
    """The child's latest snapshot, or ``None`` when absent, mid-write, oversized or not the model's shape."""
    path = work_dir / PROGRESS_FILE
    try:
        if not path.is_file() or path.stat().st_size > PROGRESS_MAX_BYTES:
            return None
        text = scrub_output(path.read_text(encoding="utf-8"), *secrets)
        return ProgressSnapshot.model_validate_json(text)
    except Exception:  # noqa: BLE001 - a snapshot the child is still writing is simply not there yet
        logger.debug("progress.json unreadable", exc_info=True)
        return None


def _load_env_keys(work_dir: Path) -> list[str]:
    path = work_dir / ENV_KEYS_FILE
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return []
    return [str(k) for k in data] if isinstance(data, list) else []


def _existing(path: Path) -> Path | None:
    return path if path.is_file() else None


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------


def run_probe_child(
    spec: LLMProbeChildSpec,
    *,
    api_key: str,
    config: ProbeRunnerConfig | None = None,
    python: str | None = None,
    environ: Mapping[str, str] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
    poll_s: float = 0.5,
    on_progress: Callable[[ProgressSnapshot], None] | None = None,
) -> ChildOutcome:
    """Run the child for ``spec`` (whose ``work_dir`` must exist, 0700) and return the outcome.

    ``api_key`` is written to the 0600 key file named by ``spec.key_file`` and never
    to the environment, the spec or a log. The caller stores what it needs from
    ``outcome.files`` and then calls ``outcome.cleanup()``. ``on_progress`` receives
    the child's ``progress.json`` snapshot once per new ``seq`` on every poll and
    once more after the loop; an exception it raises is logged and never changes
    the outcome.
    """
    from redsim.scanners.sandbox import SandboxConfig, _rlimit_preexec

    cfg = config or ProbeRunnerConfig.from_env()
    work_dir = Path(spec.work_dir)
    if not work_dir.is_dir():
        raise ValueError(f"work_dir does not exist: {work_dir}")
    os.chmod(work_dir, 0o700)
    key_path = Path(spec.key_file)
    if key_path.parent.resolve() != work_dir.resolve():
        raise ValueError("key_file must live inside work_dir")
    spec_path = work_dir / SPEC_FILE
    spec_path.write_text(spec.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.chmod(spec_path, 0o600)
    env = build_child_env(work_dir, hf_home=spec.hf_home, environ=environ)
    rlimits = SandboxConfig(
        timeout_s=cfg.timeout_s, cpu_seconds=cfg.cpu_seconds, memory_mb=cfg.memory_mb,
        file_size_mb=cfg.file_size_mb, open_files=cfg.open_files, max_processes=cfg.max_processes,
        allow_network=True,
    )
    stdout_path = work_dir / "child_stdout.log"
    stderr_path = work_dir / "child_stderr.log"
    argv = [python or sys.executable, "-m", "redsim.ml.llm.probe_child", "--spec", str(spec_path)]

    started = time.monotonic()
    status: OutcomeStatus = "failed"
    exit_code: int | None = None
    error: str | None = None
    last_progress: ProgressSnapshot | None = None

    def deliver() -> None:
        """Hand the newest snapshot to ``on_progress`` once per ``seq``; the callback never fails the run."""
        nonlocal last_progress
        snapshot = _read_progress(work_dir, api_key)
        if snapshot is None or (last_progress is not None and snapshot.seq <= last_progress.seq):
            return
        last_progress = snapshot
        if on_progress is None:
            return
        try:
            on_progress(snapshot)
        except Exception:  # noqa: BLE001 - progress is best effort
            logger.warning("on_progress callback failed (seq=%d)", snapshot.seq, exc_info=True)

    write_key_file(work_dir, api_key)
    try:
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                argv, cwd=str(work_dir), env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                start_new_session=True,
                preexec_fn=_rlimit_preexec(rlimits),  # noqa: PLW1509 - POSIX rlimits
            )
            deadline = started + cfg.timeout_s
            while True:
                try:
                    exit_code = proc.wait(timeout=poll_s)
                    break
                except subprocess.TimeoutExpired:
                    pass
                deliver()
                if is_cancelled is not None and is_cancelled():
                    _kill_group(proc)
                    status, error = "cancelled", "probe run cancelled; process group killed"
                    break
                if time.monotonic() >= deadline:
                    _kill_group(proc)
                    status, error = "timed_out", f"probe child exceeded {cfg.timeout_s}s; process group killed"
                    break
    finally:
        key_path.unlink(missing_ok=True)
    wall = time.monotonic() - started
    deliver()  # a snapshot written after the last poll, on every exit of the loop

    result = _load_result(work_dir, api_key)
    if status == "failed":  # the child exited on its own
        if exit_code == 0 and result is not None and result.status == "succeeded":
            status = "succeeded"
        else:
            error = (result.error if result is not None and result.error else None) or f"probe child exited {exit_code}"
    garak_dir = work_dir / GARAK_DIR
    files: dict[str, Path | None] = {
        "report_jsonl": _existing(garak_dir / f"{REPORT_PREFIX}.report.jsonl"),
        "hitlog_jsonl": _existing(garak_dir / f"{REPORT_PREFIX}.hitlog.jsonl"),
        "digest_html": _existing(garak_dir / f"{REPORT_PREFIX}.report.html"),
        "usage_json": _existing(work_dir / USAGE_FILE),
        "child_result_json": _existing(work_dir / RESULT_FILE),
    }
    discard: dict[str, Path | None] = {
        "garak_log": _existing(work_dir / GARAK_LOG_FILE),
        "garak_config": _existing(work_dir / "garak.yaml"),
        "stdout": _existing(stdout_path),
        "stderr": _existing(stderr_path),
        "progress": _existing(work_dir / PROGRESS_FILE),
    }
    outcome = ChildOutcome(
        status=status, exit_code=exit_code, work_dir=work_dir, wall_time_s=round(wall, 3), result=result,
        progress=last_progress,
        files=files, discard=discard, stdout_tail=_tail(stdout_path, api_key), stderr_tail=_tail(stderr_path, api_key),
        env_keys=_load_env_keys(work_dir), error=scrub_output(error, api_key) if error else None,
    )
    logger.info("probe child %s in %.1fs (exit %s, %d probes run)", outcome.status, wall, exit_code,
                len(result.probes_run) if result is not None else 0)
    return outcome


__all__ = [
    "ALLOWED_REDSIM_KEYS",
    "CELERY_SOFT_LIMIT_S",
    "ENV_KEEP_WORK_DIR",
    "ENV_TIMEOUT_S",
    "FORBIDDEN_ENV_PREFIXES",
    "PROGRESS_MAX_BYTES",
    "PROXY_ENV_KEYS",
    "TLS_ENV_KEYS",
    "ChildOutcome",
    "ProbeChildCancelled",
    "ProbeChildFailed",
    "ProbeChildTimeout",
    "ProbeRunnerConfig",
    "assert_child_env_minimal",
    "build_child_env",
    "prepare_work_dir",
    "run_probe_child",
    "scrub_output",
    "write_key_file",
]
