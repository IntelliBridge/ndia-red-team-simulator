"""Credential-free child-process envelope for adversarial-ML execution (spec 9.4).

The parent builds an :class:`MlSandboxConfig` from ``REDSIM_ML_SANDBOX_*``,
creates a per-job work directory (``REDSIM_ML_WORK_DIR/<job_id>``, mode 0700),
spawns ``python -m redsim.ml.sandbox_worker`` in its own process group under
POSIX rlimits, polls it for stage events and cancellation, and reads back one
typed envelope. Every way the child can fail maps onto a spec 10.6 class:

* wall clock exceeded -> process group SIGKILLed, files the child had written
  are persisted under ``ml/partial/`` and :class:`SandboxTimeout` is raised;
* non-zero exit (rlimit, signal, crash) -> :class:`SandboxKilled`;
* missing / unparseable / ill-shaped envelope -> :class:`EnvelopeInvalid`;
* ``{"ok": false, "error_class": ...}`` -> that ``redsim.ml.errors`` class.

The child inherits the generic plugin-sandbox allowlist (``_SAFE_ENV_KEYS``),
which strips every ``REDSIM_*`` variable so credentials never reach it. The one
operator setting the child legitimately needs is the bundled asset tree
(``REDSIM_ML_ASSETS_DIR``): bundled targets, tabular targets and the evaluation
split of uploaded models all resolve ``MANIFEST.json`` from it. The parent
therefore resolves that directory once, to an absolute path, and hands it to the
child explicitly, both as the ``assets_dir`` field of the request JSON (which
``sandbox_worker`` applies before any ML import) and as a ``REDSIM_*`` variable
in the child env. The only other ``REDSIM_*`` values the child sees are pins, not
settings: ``REDSIM_PLUGINS=0`` (no plugin discovery in the child),
``REDSIM_ENV_FILE=<work_dir>/no-env`` (``redsim.llm.pythia`` otherwise falls back
to ``./.env`` and the repo-root ``.env``, so a checkout holding a real gateway key
would reach the child through the file even with every ``PYTHIA_*`` variable
stripped, and naming an absent file inside the just-cleared work directory
switches that fallback off) and ``REDSIM_DISABLE_LLM=1`` (the narrative is the
worker parent's job, spec 10.8 / 16.1). No other ``REDSIM_*`` value, proxy setting or
API token crosses the boundary, and the ML child never gets network
configuration regardless of ``REDSIM_PLUGIN_SANDBOX_NETWORK``.

Endpoint targets (spec 9.1 rule 4, ENDPOINT-05): when a job names a remote predict
endpoint, the parent starts a ``redsim.ml.endpoint_broker.PredictBroker`` on a unix
socket inside the 0700 work directory before spawning the child, writes only the
socket path and the credential-free descriptor (``target_endpoint``: host, scheme,
auth profile *id*, batch and timeout caps, dataset binding) into the request JSON,
and stops the broker in a ``finally`` block whether the child exited, timed out or
was killed. The AuthProfile secret is handed to the broker object in memory and is
never serialised; the child's environment is unchanged. The broker's counters
(rows, requests, bytes per purpose, rate-limit waits, the response fingerprint) are
attached to the returned record's provenance under ``model_manifest.endpoint_broker``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redsim.ml import errors as ml_errors
from redsim.ml.errors import (
    EnvelopeInvalid,
    MLError,
    ModelLoadRefused,
    SandboxKilled,
    SandboxTimeout,
)
from redsim.ml.schema import CampaignConfig, CampaignRecord, TargetInfo
from redsim.ml.scoring import settings_hash
from redsim.scanners.sandbox import (
    _NETWORK_ENV_KEYS,
    SandboxConfig,
    _child_env,
    _int_env,
    _kill_process_group,
    _rlimit_preexec,
)

if TYPE_CHECKING:
    from redsim.ml.campaign import ArtifactSink
    from redsim.ml.endpoint_broker import PredictBroker

logger = logging.getLogger(__name__)

#: Request key the child reads to build an ``EndpointTarget`` (``redsim.ml.targets.endpoint``).
TARGET_ENDPOINT_KEY = "target_endpoint"
# Keys a caller might put beside the URL that must never reach the request file; the credential
# travels only as the separate ``endpoint_auth`` argument, straight into the broker.
_ENDPOINT_SPEC_DROP = frozenset({"url", "auth", "secret", "credential", "token", "password", "allowlist"})

# Mirrors ``redsim.ml.targets.bundled.ASSETS_DIR_ENV`` / ``DEFAULT_ASSETS_DIR``.
# Declared here rather than imported so the Celery parent never pulls numpy or
# registers bundled targets as a side effect of building the envelope
# (``tests/test_review22_sandbox_assets.py`` pins the two pairs together).
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
DEFAULT_ASSETS_DIR = "./assets"

# Spec 9.4 / 20.3: resource ceilings of the ML sandbox child. There is no
# network switch; the ML child never receives proxy configuration.
ENV_TIMEOUT_S = "REDSIM_ML_SANDBOX_TIMEOUT_S"
ENV_CPU_SECONDS = "REDSIM_ML_SANDBOX_CPU_SECONDS"
ENV_MEMORY_MB = "REDSIM_ML_SANDBOX_MEMORY_MB"
ENV_FILESIZE_MB = "REDSIM_ML_SANDBOX_FILESIZE_MB"
ENV_THREADS = "REDSIM_ML_SANDBOX_THREADS"

# Spec 20.3: per-job work directories and the debugging keep switch.
WORK_DIR_ENV = "REDSIM_ML_WORK_DIR"
KEEP_WORK_DIR_ENV = "REDSIM_ML_KEEP_WORK_DIR"
DEFAULT_WORK_DIR_NAME = "redsim-ml"

#: Artifact-name prefix for files a killed/timed-out/cancelled child had written (spec 9.5, 10.6).
PARTIAL_PREFIX = "ml/partial/"

#: Celery soft limit the wall clock must stay under (spec 9.4).
CELERY_SOFT_LIMIT_S = 1800

#: Cap on the envelope the parent reads (spec 9.4).
ENVELOPE_MAX_BYTES = 16 * 1024 * 1024

#: Exit status ``sandbox_worker`` uses for an unreadable request (parent-side contract bug).
_EXIT_BAD_REQUEST = 2

# Mirrors ``redsim.llm.pythia.ENV_FILE_VAR``: the explicit ``.env`` override. Declared
# here as a literal so the parent never imports the gateway client (httpx) just to
# build the child env. ``tests/test_ml_sandbox.py`` pins the two names together.
ENV_FILE_VAR = "REDSIM_ENV_FILE"
#: The switch ``redsim.workers.tasks.ml_campaign`` honours for the LLM narrative.
DISABLE_LLM_ENV = "REDSIM_DISABLE_LLM"
#: Name of the guaranteed-absent ``.env`` the child is pointed at, inside its work dir.
NO_ENV_FILE_NAME = "no-env"

# Environment prefixes that must never appear in the child, whatever the allowlist grows into.
_FORBIDDEN_ENV_PREFIXES = ("REDSIM_", "PYTHIA_", "KAGGLE_", "AWS_", "HF_TOKEN", "HUGGING_FACE")
# The only REDSIM_* keys the child may carry: one resolved directory and three pins
# (plugins off, .env lookup pointed at an absent file, LLM narrative off). Never a secret.
_ALLOWED_REDSIM_KEYS = frozenset({ASSETS_DIR_ENV, "REDSIM_PLUGINS", ENV_FILE_VAR, DISABLE_LLM_ENV})

_JOB_DIR_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True)
class MlSandboxConfig:
    """Resource policy of the ML sandbox child (spec 9.4 table, right column).

    ``timeout_s`` is the parent's wall clock; ``cpu_seconds`` / ``memory_mb`` /
    ``file_size_mb`` become ``RLIMIT_CPU`` / ``RLIMIT_AS`` / ``RLIMIT_FSIZE`` in the
    child; ``threads`` is what ``OMP_NUM_THREADS`` and ``MKL_NUM_THREADS`` are
    pinned to. ``RLIMIT_AS`` caps virtual address space and CPU torch maps large
    regions at import, so the memory default sits well above resident need; the
    wall-clock and CPU limits are the operative caps.
    """

    timeout_s: int = 1200
    cpu_seconds: int = 900
    memory_mb: int = 4096
    file_size_mb: int = 1024
    threads: int = 2
    open_files: int = 256
    max_processes: int = 256

    @classmethod
    def from_env(cls) -> MlSandboxConfig:
        """Read ``REDSIM_ML_SANDBOX_*``; malformed or non-positive values keep the default."""
        base = cls()
        cfg = cls(
            timeout_s=_int_env(ENV_TIMEOUT_S, base.timeout_s),
            cpu_seconds=_int_env(ENV_CPU_SECONDS, base.cpu_seconds),
            memory_mb=_int_env(ENV_MEMORY_MB, base.memory_mb),
            file_size_mb=_int_env(ENV_FILESIZE_MB, base.file_size_mb),
            threads=_int_env(ENV_THREADS, base.threads),
        )
        if cfg.timeout_s >= CELERY_SOFT_LIMIT_S:
            logger.warning(
                "%s=%d is not below the Celery soft limit (%ds); the task may be "
                "interrupted before the sandbox timeout fires",
                ENV_TIMEOUT_S, cfg.timeout_s, CELERY_SOFT_LIMIT_S,
            )
        return cfg

    def rlimits(self) -> SandboxConfig:
        """The rlimit/env policy handed to the shared preexec and env builders. Network is never on."""
        return SandboxConfig(
            timeout_s=self.timeout_s,
            cpu_seconds=self.cpu_seconds,
            memory_mb=self.memory_mb,
            file_size_mb=self.file_size_mb,
            open_files=self.open_files,
            max_processes=self.max_processes,
            allow_network=False,
        )


def _assets_dir() -> Path:
    """The operator's bundled asset tree, anchored as an absolute path for the child.

    Reads ``REDSIM_ML_ASSETS_DIR`` (default ``./assets``) exactly as
    ``redsim.ml.targets.bundled.assets_dir`` does, then normalizes it (``~``,
    ``..``, symlinks, cwd) so the value the child receives no longer depends on
    the child's working directory or environment. Existence is deliberately not
    required here: a missing or malformed manifest surfaces inside the child as
    an explicit ``TargetUnavailable`` / ``UnsupportedArtifact`` with the path in
    the message, which is the evidence operators need.
    """
    raw = os.environ.get(ASSETS_DIR_ENV, "").strip() or DEFAULT_ASSETS_DIR
    return Path(raw).expanduser().resolve()


def work_dir_root() -> Path:
    """Root of the per-job work directories: ``REDSIM_ML_WORK_DIR`` or ``$TMPDIR/redsim-ml``."""
    raw = os.environ.get(WORK_DIR_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return Path(tempfile.gettempdir()).resolve() / DEFAULT_WORK_DIR_NAME


def keep_work_dir() -> bool:
    """``REDSIM_ML_KEEP_WORK_DIR=1`` keeps work directories after a job for debugging."""
    raw = os.environ.get(KEEP_WORK_DIR_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def job_work_dir(job_id: str) -> Path:
    """``<root>/<job_id>``, created mode 0700 (spec 9.4); ``ValueError`` for an unsafe id."""
    if not _JOB_DIR_NAME.match(job_id) or job_id in {".", ".."}:
        raise ValueError(f"job id {job_id!r} is not usable as a work directory name")
    root = work_dir_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / job_id
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)  # mkdir's mode is subject to umask; pin it
    return path


def _anonymous_work_dir() -> Path:
    """A fresh 0700 directory under the root for callers without a job id (tests, CLI)."""
    root = work_dir_root()
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="job-", dir=root))


def _clear_dir(path: Path) -> None:
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def no_env_file(work_dir: Path | None = None) -> Path:
    """The absent ``.env`` path the child's ``REDSIM_ENV_FILE`` is pinned to.

    Inside the per-job work directory when there is one: ``_run_child`` clears
    that directory right before spawning, so the path is guaranteed not to exist
    when the child starts, and nothing but the child itself could create it.
    Callers without a work directory (the doctor / adapter ``--help`` probes) get
    the same name under the work-dir root, which the parent never populates.
    ``redsim.llm.pythia.env_file_path`` treats an explicit value that is not a
    file as "no .env at all" and does not fall through to ``./.env``.
    """
    root = Path(work_dir) if work_dir is not None else work_dir_root()
    return root / NO_ENV_FILE_NAME


def _ml_child_env(
    cfg: MlSandboxConfig, *, assets: str, hash_seed: int, work_dir: Path | None = None,
) -> dict[str, str]:
    """The child's environment: interpreter allowlist + spec 9.4 additions, nothing else.

    ``_child_env`` starts from an empty dict and copies only ``_SAFE_ENV_KEYS``;
    ``allow_network`` is hard-wired off so proxy variables are never restored.
    ``REDSIM_ENV_FILE`` is pinned to :func:`no_env_file` so the gateway client's
    ``./.env`` / repo-root fallback cannot hand the child a key the environment
    sweep already removed, and ``REDSIM_DISABLE_LLM=1`` says the child never
    narrates. A final sweep drops anything under a secret-bearing prefix so a
    future widening of the shared allowlist cannot leak through this boundary.
    """
    env = _child_env(cfg.rlimits())
    env.update({
        "PYTHONUNBUFFERED": "1",
        "PYTHONHASHSEED": str(hash_seed),
        "OMP_NUM_THREADS": str(cfg.threads),
        "MKL_NUM_THREADS": str(cfg.threads),
        "OPENBLAS_NUM_THREADS": str(cfg.threads),
        "MPLBACKEND": "Agg",
        "HF_HUB_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        # The only REDSIM_* setting the child receives: a resolved directory,
        # never a credential.
        ASSETS_DIR_ENV: assets,
        # Pins: no .env fallback, no LLM narrative in the child.
        ENV_FILE_VAR: str(no_env_file(work_dir)),
        DISABLE_LLM_ENV: "1",
    })
    for key in list(env):
        if key in _NETWORK_ENV_KEYS:
            del env[key]
        elif key.startswith(_FORBIDDEN_ENV_PREFIXES) and key not in _ALLOWED_REDSIM_KEYS:
            del env[key]
    return env


def _safe_name(name: str) -> Path:
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise EnvelopeInvalid(f"sandbox returned unsafe artifact name {name!r}")
    return Path(*candidate.parts)


def _target_info(config: CampaignConfig) -> TargetInfo:
    snapshot = dict(config.target_snapshot or {})
    detail = snapshot.get("detail")
    detail = dict(detail) if isinstance(detail, dict) else {}
    manifest = detail.get("manifest")
    manifest = dict(manifest) if isinstance(manifest, dict) else {}
    metadata = detail.get("metadata")
    metadata = dict(metadata) if isinstance(metadata, dict) else manifest
    return TargetInfo(
        id=config.target_id,
        name=str(detail.get("name") or manifest.get("name") or config.target_id),
        domain=config.modality,
        status="available",
        metadata=metadata,
    )


def partial_campaign_record(
    config: CampaignConfig,
    *,
    status: str,
    error: str,
    stages_done: list[str],
    baseline_run_id: str | None,
    parent_run_id: str | None,
) -> CampaignRecord:
    """Create authoritative failure/cancellation evidence without loading a model."""
    detail = dict((config.target_snapshot or {}).get("detail") or {})
    manifest = dict(detail.get("manifest") or {})
    model_sha256 = detail.get("sha256") or manifest.get("sha256")
    return CampaignRecord.model_validate({
        "run_id": "sandbox-partial",
        "kind": "verify" if baseline_run_id else "attack",
        "status": status,
        "stage": stages_done[-1] if stages_done else None,
        "stages_done": stages_done,
        "error": error[:1000],
        "created_at": datetime.now(UTC),
        "completed_at": datetime.now(UTC),
        "config": config,
        "target": _target_info(config),
        "attacks": config.attacks,
        "score": None,
        "score_status": {
            "state": "unavailable",
            "reason": "campaign did not reach a complete score",
        },
        "settings_hash": settings_hash(config, model_sha256),
        "baseline_run_id": baseline_run_id,
        "parent_run_id": parent_run_id,
        "completeness": "partial",
        "missing": ["campaign did not reach a complete score"],
    })


def _events(path: Path) -> list[str]:
    if not path.is_file():
        return []
    stages: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        stage = value.get("stage") if isinstance(value, dict) else None
        if isinstance(stage, str) and stage not in stages:
            stages.append(stage)
    return stages


def _read_artifact_manifest(work_dir: Path) -> list[dict[str, Any]] | None:
    """The child's ``artifacts.json`` as a list of entries, or ``None`` when absent."""
    manifest_path = work_dir / "artifacts.json"
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EnvelopeInvalid(f"ML sandbox artifact manifest is not JSON: {exc}") from exc
    if not isinstance(manifest, list):
        raise EnvelopeInvalid("ML sandbox artifact manifest is malformed")
    entries: list[dict[str, Any]] = []
    for item in manifest:
        if not isinstance(item, dict):
            raise EnvelopeInvalid("ML sandbox artifact entry is malformed")
        entries.append(item)
    return entries


def _artifact_path(work_dir: Path, name: str) -> Path:
    relative = _safe_name(name)
    root = (work_dir / "artifacts").resolve()
    path = (root / relative).resolve()
    if root != path and root not in path.parents:
        raise EnvelopeInvalid("ML sandbox artifact escaped its work directory")
    return path


def _persist_child_artifacts(
    work_dir: Path,
    sink: ArtifactSink,
) -> dict[str, str]:
    """Verify and persist every artifact the child listed; any discrepancy is ``EnvelopeInvalid``."""
    entries = _read_artifact_manifest(work_dir)
    if entries is None:
        return {}
    persisted: dict[str, str] = {}
    for item in entries:
        name = str(item.get("name") or "")
        # ``path`` is where the child left the bytes (an earlier version of a re-written name sits at a
        # digest-qualified path); it is never the artifact's name.
        path = _artifact_path(work_dir, str(item.get("path") or name))
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise EnvelopeInvalid(f"ML sandbox artifact {name!r} is unreadable: {exc}") from exc
        expected = str(item.get("sha256") or "")
        if not expected or hashlib.sha256(data).hexdigest() != expected:
            raise EnvelopeInvalid(f"ML sandbox artifact digest mismatch for {name!r}")
        reference = str(item.get("reference") or "")
        if not reference:
            raise EnvelopeInvalid(f"ML sandbox artifact reference missing for {name!r}")
        artifact_id = sink.put(
            name,
            data,
            str(item.get("content_type") or "application/octet-stream"),
        )
        persisted[reference] = artifact_id
    return persisted


def _persist_partial_files(work_dir: Path, sink: ArtifactSink | None) -> dict[str, str]:
    """Keep what a killed, timed-out or cancelled child had written, under ``ml/partial/``.

    Lenient where the success path is strict: an entry whose file is missing or
    whose digest no longer matches (the kill landed mid-write) is skipped with a
    log line rather than failing the evidence pass. The stage event log is kept
    too. Returns ``{artifact name: sink id}`` for what was persisted.
    """
    if sink is None:
        return {}
    persisted: dict[str, str] = {}
    try:
        entries = _read_artifact_manifest(work_dir) or []
    except EnvelopeInvalid as exc:
        logger.warning("ML sandbox partial evidence: %s", exc)
        entries = []
    for item in entries:
        name = str(item.get("name") or "")
        try:
            path = _artifact_path(work_dir, str(item.get("path") or name))
            data = path.read_bytes()
        except (EnvelopeInvalid, OSError) as exc:
            logger.info("ML sandbox partial evidence skipped %r: %s", name, exc)
            continue
        if hashlib.sha256(data).hexdigest() != str(item.get("sha256") or ""):
            logger.info("ML sandbox partial evidence skipped %r: digest mismatch", name)
            continue
        partial_name = f"{PARTIAL_PREFIX}{name}"
        persisted[partial_name] = sink.put(
            partial_name, data, str(item.get("content_type") or "application/octet-stream"),
        )
    events_path = work_dir / "events.jsonl"
    if events_path.is_file():
        try:
            data = events_path.read_bytes()
        except OSError:
            data = b""
        if data:
            name = f"{PARTIAL_PREFIX}events.jsonl"
            persisted[name] = sink.put(name, data, "application/x-ndjson")
    return persisted


def _read_envelope(result_path: Path) -> dict[str, Any]:
    """Parse and shape-check ``result.json``; every defect is ``EnvelopeInvalid``.

    Accepted shapes: ``{"ok": true, "result": {...}}`` and ``{"ok": false,
    "error_class": str, "error": str}``. A bare object without an ``ok`` key is
    the pre-envelope child shape (``{"manifest": ...}`` / ``{"record": ...}``)
    and is read as a successful result so an older child still interoperates;
    the per-mode key checks in the callers still apply to it.
    """
    try:
        raw = result_path.read_bytes()
    except OSError as exc:
        raise EnvelopeInvalid(f"ML sandbox envelope is unreadable: {exc}") from exc
    if len(raw) > ENVELOPE_MAX_BYTES:
        raise EnvelopeInvalid(
            f"ML sandbox envelope is {len(raw)} bytes; the cap is {ENVELOPE_MAX_BYTES}"
        )
    try:
        envelope = json.loads(raw)
    except ValueError as exc:
        raise EnvelopeInvalid(f"ML sandbox envelope is not JSON: {exc}") from exc
    if not isinstance(envelope, dict):
        raise EnvelopeInvalid("ML sandbox envelope is not an object")
    if "ok" not in envelope:
        return {"ok": True, "result": envelope}
    ok = envelope.get("ok")
    if ok is True:
        if not isinstance(envelope.get("result"), dict):
            raise EnvelopeInvalid("ML sandbox envelope reports ok without a result object")
        return envelope
    if ok is False:
        if not isinstance(envelope.get("error_class"), str) or not isinstance(envelope.get("error"), str):
            raise EnvelopeInvalid(
                "ML sandbox envelope reports a failure without error_class and error strings"
            )
        return envelope
    raise EnvelopeInvalid(f"ML sandbox envelope ok must be a boolean, got {ok!r}")


def _typed_error(envelope: dict[str, Any], *, mode: str) -> MLError:
    """Rebuild the child's typed failure from ``error_class``.

    Names that resolve to a ``redsim.ml.errors`` class are raised as that class
    with the child's operator-safe message. Anything else (torch, onnx, OS
    errors) means the loader failed on the model bytes in validate mode, which
    is a load refusal; in campaign mode the child only reports ``ok: false``
    when the request itself was unusable, which is a contract failure.
    """
    name = str(envelope["error_class"])
    message = str(envelope["error"])
    cls = getattr(ml_errors, name, None)
    if isinstance(cls, type) and issubclass(cls, MLError):
        return cls(message)
    endpoint_cls = _endpoint_error_class(name)
    if endpoint_cls is not None:
        return endpoint_cls(message)
    if mode == "validate":
        return ModelLoadRefused(f"load_failed: {name}: {message}")
    return EnvelopeInvalid(f"ML sandbox child rejected the {mode} request: {name}: {message}")


def _endpoint_error_class(name: str) -> type[MLError] | None:
    """The endpoint transport failure named ``name`` (``redsim.ml.endpoint_broker``), imported lazily."""
    from redsim.ml.endpoint_broker import endpoint_error_class

    return endpoint_error_class(name)


def _child_endpoint_spec(endpoint: dict[str, Any], socket_path: Path, limits: dict[str, Any]) -> dict[str, Any]:
    """The credential-free ``target_endpoint`` block the child reads: host, scheme, socket, caps, binding."""
    url = str(endpoint.get("url") or "")
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    default_port = 443 if parts.scheme == "https" else 80
    url_host = host if port in (None, default_port) else f"{host}:{port}"
    spec = {k: v for k, v in endpoint.items() if k not in _ENDPOINT_SPEC_DROP}
    spec.update({"url_host": url_host, "scheme": parts.scheme or "https", "socket": str(socket_path),
                 "limits": dict(limits)})
    return spec


def _endpoint_manifest(endpoint: dict[str, Any]) -> dict[str, Any]:
    raw = endpoint.get("manifest")
    return dict(raw) if isinstance(raw, dict) else {}


def _endpoint_limits(endpoint: dict[str, Any]) -> Any:
    from redsim.ml.endpoint_broker import EndpointLimits

    manifest = _endpoint_manifest(endpoint)
    modality = str(manifest.get("modality") or endpoint.get("modality") or "image")
    raw_limits = endpoint.get("limits")
    overrides = dict(raw_limits) if isinstance(raw_limits, dict) else None
    return EndpointLimits.from_env(modality).merged(overrides)


def _start_broker(
    endpoint: dict[str, Any],
    auth: dict[str, Any] | None,
    *,
    work_dir: Path,
    socket_path: Path,
    allowlist: list[str] | None,
) -> PredictBroker:
    """Construct (egress checks run here, before any child exists) and start the predict broker."""
    from redsim.ml.endpoint_broker import PredictBroker

    manifest = _endpoint_manifest(endpoint)
    n_classes: int | None = None
    raw_n = manifest.get("n_classes")
    names = manifest.get("class_names")
    if isinstance(raw_n, int) and raw_n > 0:
        n_classes = raw_n
    elif isinstance(names, list) and names:
        n_classes = len(names)
    broker = PredictBroker(
        str(endpoint.get("url") or ""), auth, work_dir=work_dir, limits=_endpoint_limits(endpoint),
        n_classes=n_classes, allowlist=allowlist, socket_path=socket_path,
    )
    broker.start()
    return broker


def _exit_description(returncode: int) -> str:
    if returncode < 0:
        try:
            return f"signal {signal.Signals(-returncode).name}"
        except ValueError:
            return f"signal {-returncode}"
    return f"status {returncode}"


@dataclass
class _ChildOutcome:
    """What one child run produced; callers map ``status`` onto the typed classes."""

    status: str  # "ok" | "cancelled" | "timed_out" | "killed"
    stages: list[str]
    result: dict[str, Any] | None = None
    error: str | None = None
    exit_status: int | None = None
    partial_artifacts: dict[str, str] = field(default_factory=dict)
    broker_stats: dict[str, Any] | None = None   # endpoint jobs: the parent-side counters (never a credential)


def _run_child(
    request: dict[str, Any],
    *,
    sink: ArtifactSink | None,
    on_stage: Callable[[str], None] | None,
    is_cancelled: Callable[[], bool] | None,
    job_id: str | None = None,
    hash_seed: int = 0,
    endpoint: dict[str, Any] | None = None,
    endpoint_auth: dict[str, Any] | None = None,
    endpoint_allowlist: list[str] | None = None,
) -> _ChildOutcome:
    cfg = MlSandboxConfig.from_env()
    assets = str(_assets_dir())
    mode = str(request.get("mode") or "")
    work_dir = job_work_dir(job_id) if job_id else _anonymous_work_dir()
    broker: PredictBroker | None = None
    broker_stats: dict[str, Any] | None = None
    socket_path: Path | None = None
    try:
        if endpoint is not None:
            from redsim.ml.endpoint_broker import choose_socket_path

            # Decided before the request is serialised so a retry sees the same request JSON; the
            # socket itself is bound only after the work directory is cleared.
            socket_path = choose_socket_path(work_dir)
            request = {
                **request,
                TARGET_ENDPOINT_KEY: _child_endpoint_spec(endpoint, socket_path, _endpoint_limits(endpoint).as_dict()),
            }
        request_json = json.dumps({**request, "assets_dir": assets}, sort_keys=True)
        request_path = work_dir / "request.json"
        result_path = work_dir / "result.json"
        stderr = ""
        returncode = 0
        forced_status: str | None = None
        forced_error: str | None = None
        reported: set[str] = set()
        previous_request = request_path.read_text(encoding="utf-8") if request_path.is_file() else None
        if result_path.is_file() and previous_request == request_json:
            # Spec 10.6: a stage child that completed is not re-run on a retry;
            # the envelope is re-read instead.
            logger.info("ML sandbox reusing completed envelope in %s", work_dir)
        else:
            _clear_dir(work_dir)
            request_path.write_text(request_json, encoding="utf-8")
            if endpoint is not None and socket_path is not None:
                # Egress checks and the TLS client are built here, in the parent, before the child exists;
                # an EgressRefused / EndpointUnreachable propagates as the job's typed failure.
                broker = _start_broker(
                    endpoint, endpoint_auth, work_dir=work_dir, socket_path=socket_path, allowlist=endpoint_allowlist,
                )
            env = _ml_child_env(cfg, assets=assets, hash_seed=hash_seed, work_dir=work_dir)
            argv = [
                sys.executable,
                "-m",
                "redsim.ml.sandbox_worker",
                "--request",
                str(request_path),
                "--work-dir",
                str(work_dir),
            ]
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                preexec_fn=_rlimit_preexec(cfg.rlimits()),  # noqa: PLW1509 - required for POSIX rlimits
                start_new_session=True,
            )
            started = time.monotonic()
            while proc.poll() is None:
                for stage in _events(work_dir / "events.jsonl"):
                    if stage not in reported:
                        reported.add(stage)
                        if on_stage is not None:
                            on_stage(stage)
                if is_cancelled is not None:
                    try:
                        cancelled = is_cancelled()
                    except Exception:  # cancellation telemetry cannot fail execution
                        logger.debug("ML sandbox cancellation probe failed", exc_info=True)
                        cancelled = False
                    if cancelled:
                        forced_status = "cancelled"
                        forced_error = "campaign cancelled while sandbox child was running"
                        _kill_process_group(proc)
                        break
                if time.monotonic() - started > cfg.timeout_s:
                    forced_status = "timed_out"
                    forced_error = f"ML sandbox timed out after {cfg.timeout_s}s"
                    _kill_process_group(proc)
                    break
                time.sleep(0.2)
            _, stderr = proc.communicate()
            returncode = proc.returncode
            if broker is not None:
                # The child is gone (exited or killed): nothing can connect any more, so the socket
                # closes here and the counters are final.
                broker_stats = broker.stop().as_dict()
                broker = None
        stages = _events(work_dir / "events.jsonl")
        for stage in stages:
            if stage not in reported and on_stage is not None:
                on_stage(stage)
        if forced_status is not None:
            partial = _persist_partial_files(work_dir, sink)
            return _ChildOutcome(
                status=forced_status, stages=stages, error=forced_error,
                exit_status=returncode, partial_artifacts=partial, broker_stats=broker_stats,
            )
        if returncode == _EXIT_BAD_REQUEST:
            detail = (stderr or "").strip()[-1000:]
            raise EnvelopeInvalid(f"ML sandbox child could not read its request: {detail}")
        if returncode != 0:
            partial = _persist_partial_files(work_dir, sink)
            detail = (stderr or "").strip()[-1000:]
            error = f"ML sandbox child died with {_exit_description(returncode)}"
            if detail:
                error = f"{error}: {detail}"
            return _ChildOutcome(
                status="killed", stages=stages, error=error,
                exit_status=returncode, partial_artifacts=partial, broker_stats=broker_stats,
            )
        if not result_path.is_file():
            raise EnvelopeInvalid("ML sandbox child exited 0 without writing result.json")
        envelope = _read_envelope(result_path)
        if envelope["ok"] is False:
            raise _typed_error(envelope, mode=mode)
        result = dict(envelope["result"])
        result["artifact_ids"] = (
            _persist_child_artifacts(work_dir, sink) if sink is not None else {}
        )
        return _ChildOutcome(status="ok", stages=stages, result=result, exit_status=returncode,
                             broker_stats=broker_stats)
    finally:
        if broker is not None:
            # Reached only when something raised between start and the normal stop: still time-bounded.
            try:
                broker.stop()
            except Exception:  # noqa: BLE001 - the primary failure is already propagating
                logger.warning("ML sandbox could not stop the predict broker cleanly", exc_info=True)
        elif socket_path is not None and socket_path.parent != work_dir:
            # A fallback socket directory chosen for a reused envelope was never bound; remove it.
            shutil.rmtree(socket_path.parent, ignore_errors=True)
        if keep_work_dir():
            logger.info("ML sandbox keeping work directory %s (%s=1)", work_dir, KEEP_WORK_DIR_ENV)
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


def _persist_partial_record(
    sink: ArtifactSink,
    config: CampaignConfig,
    outcome: _ChildOutcome,
    *,
    error: str,
    baseline_run_id: str | None,
    parent_run_id: str | None,
) -> None:
    """Write the partial campaign record beside the child's partial files, best effort."""
    record = partial_campaign_record(
        config, status="failed", error=error, stages_done=outcome.stages,
        baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
    )
    try:
        sink.put(
            f"{PARTIAL_PREFIX}run_record.json",
            record.model_dump_json().encode("utf-8"),
            "application/json",
        )
    except Exception:  # noqa: BLE001 - the typed failure below is the primary evidence
        logger.warning("ML sandbox could not persist the partial campaign record", exc_info=True)


def run_campaign_sandboxed(
    config: CampaignConfig,
    sink: ArtifactSink,
    *,
    target_file: Path | None = None,
    target_detail: dict[str, Any] | None = None,
    baseline_run_id: str | None = None,
    parent_run_id: str | None = None,
    on_stage: Callable[[str], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
    job_id: str | None = None,
    target_endpoint: dict[str, Any] | None = None,
    endpoint_auth: dict[str, Any] | None = None,
    endpoint_allowlist: list[str] | None = None,
) -> CampaignRecord:
    """Execute a campaign in a bounded, credential-free process group.

    Returns the child's record (or a ``cancelled`` partial record). Raises
    :class:`SandboxTimeout` / :class:`SandboxKilled` after persisting what the
    child had written under ``ml/partial/`` plus a partial campaign record, and
    :class:`EnvelopeInvalid` when the child's output cannot be trusted.

    ``target_endpoint`` (spec 9.1 rule 4) names a remote predict endpoint: ``url``
    (parent-side only), ``auth_profile_id``, optional ``batch_rows`` / ``timeout_s`` /
    ``limits`` and ``manifest`` (``modality``, ``dataset_id``, ``dataset_split``,
    ``n_classes`` or ``class_names``, ``input_shape``, ``features``, ``name``). The
    parent brokers every query; ``endpoint_auth`` is the ``resolve_auth_for_scan``
    shape and reaches only the broker. An egress or transport refusal raised before
    or by the broker is re-raised after a partial record is persisted.
    """
    try:
        outcome = _run_child(
            {
                "mode": "campaign",
                "config": config.model_dump(mode="json"),
                "target_file": str(target_file) if target_file is not None else None,
                "target_detail": target_detail,
                "baseline_run_id": baseline_run_id,
                "parent_run_id": parent_run_id,
            },
            sink=sink,
            on_stage=on_stage,
            is_cancelled=is_cancelled,
            job_id=job_id,
            hash_seed=config.seed,
            endpoint=target_endpoint,
            endpoint_auth=endpoint_auth,
            endpoint_allowlist=endpoint_allowlist,
        )
    except MLError as exc:
        if target_endpoint is not None and _endpoint_error_class(type(exc).__name__) is not None:
            # Egress refused / unreachable / auth failed before the child ran: a job failure with the
            # evidence that exists (the config and target snapshot), never a model outcome.
            _persist_partial_record(
                sink, config, _ChildOutcome(status="failed", stages=[]), error=f"{type(exc).__name__}: {exc}",
                baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
            )
        raise
    if outcome.status == "cancelled":
        return partial_campaign_record(
            config,
            status="cancelled",
            error=str(outcome.error or "campaign cancelled while sandbox child was running"),
            stages_done=outcome.stages,
            baseline_run_id=baseline_run_id,
            parent_run_id=parent_run_id,
        )
    if outcome.status in {"timed_out", "killed"}:
        failure: type[MLError] = SandboxTimeout if outcome.status == "timed_out" else SandboxKilled
        message = str(outcome.error or "ML sandbox failed")
        if outcome.partial_artifacts:
            message = f"{message}; {len(outcome.partial_artifacts)} partial file(s) kept under {PARTIAL_PREFIX}"
        if outcome.broker_stats:
            message = (f"{message}; endpoint broker served {outcome.broker_stats.get('rows', 0)} rows in "
                       f"{outcome.broker_stats.get('requests', 0)} requests")
        _persist_partial_record(
            sink, config, outcome, error=f"{failure.__name__}: {message}",
            baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
        )
        raise failure(message)
    assert outcome.result is not None
    try:
        record = CampaignRecord.model_validate(outcome.result["record"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EnvelopeInvalid(f"ML sandbox campaign envelope has no valid record: {exc}") from exc
    mapping = outcome.result.get("artifact_ids")
    if not isinstance(mapping, dict):
        raise EnvelopeInvalid("ML sandbox artifact mapping is malformed")
    observations = []
    for observation in record.observations:
        artifacts: dict[str, str] = {}
        for name, reference in observation.artifacts.items():
            artifact_id = mapping.get(reference)
            if not isinstance(artifact_id, str):
                raise EnvelopeInvalid(
                    f"ML sandbox did not persist observation artifact {name!r}"
                )
            artifacts[name] = artifact_id
        observations.append(observation.model_copy(update={"artifacts": artifacts}))
    payload = {
        **record.model_dump(mode="json"),
        "observations": [
            item.model_dump(mode="json") for item in observations
        ],
    }
    if outcome.broker_stats is not None and isinstance(payload.get("provenance"), dict):
        # The parent's counters are authoritative for what left the worker (ENDPOINT-05, -08); the child's
        # own client-side counts stay under ``endpoint_queries``.
        manifest = dict(payload["provenance"].get("model_manifest") or {})
        manifest["endpoint_broker"] = outcome.broker_stats
        payload["provenance"] = {**payload["provenance"], "model_manifest": manifest}
    return CampaignRecord.model_validate(payload)


def probe_endpoint_sandboxed(
    target_id: str,
    target_endpoint: dict[str, Any],
    endpoint_auth: dict[str, Any] | None,
    *,
    endpoint_allowlist: list[str] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """The endpoint variant of ``validate`` (ENDPOINT-09): probe the endpoint through the broker.

    The child binds the bundled slice, sends a seeded 8-row probe, checks the response against the
    contract and returns the manifest (``endpoint`` block, probe latency and status, fingerprint,
    counters); the parent adds its broker counters under ``endpoint_broker``. Refusals come back as
    the typed classes the child named (``EndpointSchemaMismatch``, ``EndpointAuthFailed``,
    ``EndpointUnreachable``, ``EgressRefused``, ``UnsupportedArtifact`` for a binding problem);
    the wall clock raises :class:`SandboxTimeout`, a dead child :class:`SandboxKilled`.
    """
    outcome = _run_child(
        {
            "mode": "validate",
            "target_id": target_id,
            "target_file": None,
            "target_detail": dict(target_endpoint.get("manifest") or {}),
        },
        sink=None,
        on_stage=None,
        is_cancelled=is_cancelled,
        job_id=job_id,
        endpoint=target_endpoint,
        endpoint_auth=endpoint_auth,
        endpoint_allowlist=endpoint_allowlist,
    )
    if outcome.status == "cancelled":
        raise RuntimeError(str(outcome.error or "campaign cancelled while sandbox child was running"))
    if outcome.status == "timed_out":
        raise SandboxTimeout(str(outcome.error or "ML sandbox timed out"))
    if outcome.status == "killed":
        raise SandboxKilled(str(outcome.error or "ML sandbox child died"))
    assert outcome.result is not None
    manifest = outcome.result.get("manifest")
    if not isinstance(manifest, dict):
        raise EnvelopeInvalid("ML sandbox endpoint probe did not return a manifest")
    if outcome.broker_stats is not None:
        manifest = {**manifest, "endpoint_broker": outcome.broker_stats}
    return manifest


def validate_model_sandboxed(
    target_id: str,
    target_file: Path,
    target_detail: dict[str, Any],
    *,
    is_cancelled: Callable[[], bool] | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Load and probe uploaded bytes without deserializing in the Celery process.

    Returns the manifest from the child's typed envelope. A refusal inside the
    child comes back as the ``redsim.ml.errors`` class it named
    (``ModelLoadRefused`` and friends, ``UnsupportedArtifact`` for the loader's
    current wording); the wall clock raises :class:`SandboxTimeout`, a dead
    child :class:`SandboxKilled`, a bad envelope :class:`EnvelopeInvalid`.
    Cancellation stays a ``RuntimeError`` carrying "cancelled while sandbox
    child" so the validate task keeps recognising it.
    """
    outcome = _run_child(
        {
            "mode": "validate",
            "target_id": target_id,
            "target_file": str(target_file),
            "target_detail": target_detail,
        },
        sink=None,
        on_stage=None,
        is_cancelled=is_cancelled,
        job_id=job_id,
    )
    if outcome.status == "cancelled":
        raise RuntimeError(str(outcome.error or "campaign cancelled while sandbox child was running"))
    if outcome.status == "timed_out":
        raise SandboxTimeout(str(outcome.error or "ML sandbox timed out"))
    if outcome.status == "killed":
        raise SandboxKilled(str(outcome.error or "ML sandbox child died"))
    assert outcome.result is not None
    manifest = outcome.result.get("manifest")
    if not isinstance(manifest, dict):
        raise EnvelopeInvalid("ML sandbox validation did not return a manifest")
    return manifest


__all__ = [
    "ASSETS_DIR_ENV",
    "CELERY_SOFT_LIMIT_S",
    "DEFAULT_ASSETS_DIR",
    "DISABLE_LLM_ENV",
    "ENV_CPU_SECONDS",
    "ENV_FILESIZE_MB",
    "ENV_FILE_VAR",
    "ENV_MEMORY_MB",
    "ENV_THREADS",
    "ENV_TIMEOUT_S",
    "KEEP_WORK_DIR_ENV",
    "NO_ENV_FILE_NAME",
    "PARTIAL_PREFIX",
    "TARGET_ENDPOINT_KEY",
    "WORK_DIR_ENV",
    "MlSandboxConfig",
    "job_work_dir",
    "keep_work_dir",
    "no_env_file",
    "partial_campaign_record",
    "probe_endpoint_sandboxed",
    "run_campaign_sandboxed",
    "validate_model_sandboxed",
    "work_dir_root",
]
