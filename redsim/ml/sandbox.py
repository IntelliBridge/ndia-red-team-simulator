"""Credential-free child-process envelope for adversarial-ML execution.

The child inherits the generic plugin-sandbox allowlist (``_SAFE_ENV_KEYS``),
which strips every ``REDSIM_*`` variable so credentials never reach it. The one
operator setting the child legitimately needs is the bundled asset tree
(``REDSIM_ML_ASSETS_DIR``): bundled targets, tabular targets and the evaluation
split of uploaded models all resolve ``MANIFEST.json`` from it. The parent
therefore resolves that directory once, to an absolute path, and hands it to the
child explicitly, both as the ``assets_dir`` field of the request JSON (which
``sandbox_worker`` applies before any ML import) and as the single non-secret
``REDSIM_*`` variable in the child env. No other ``REDSIM_*`` value, proxy
setting or API token crosses the boundary.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from redsim.ml.schema import CampaignConfig, CampaignRecord, TargetInfo
from redsim.ml.scoring import settings_hash
from redsim.scanners.sandbox import (
    SandboxConfig,
    _child_env,
    _kill_process_group,
    _rlimit_preexec,
)

if TYPE_CHECKING:
    from redsim.ml.campaign import ArtifactSink

logger = logging.getLogger(__name__)

# Mirrors ``redsim.ml.targets.bundled.ASSETS_DIR_ENV`` / ``DEFAULT_ASSETS_DIR``.
# Declared here rather than imported so the Celery parent never pulls numpy or
# registers bundled targets as a side effect of building the envelope
# (``tests/test_review22_sandbox_assets.py`` pins the two pairs together).
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
DEFAULT_ASSETS_DIR = "./assets"


def _timeout_seconds() -> int:
    raw = os.environ.get("REDSIM_ML_SANDBOX_TIMEOUT_S", "1800")
    try:
        return max(1, int(raw))
    except ValueError:
        return 1800


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


def _safe_name(name: str) -> Path:
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise RuntimeError(f"sandbox returned unsafe artifact name {name!r}")
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


def _persist_child_artifacts(
    work_dir: Path,
    sink: ArtifactSink,
) -> dict[str, str]:
    manifest_path = work_dir / "artifacts.json"
    if not manifest_path.is_file():
        return {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, list):
        raise TypeError("ML sandbox artifact manifest is malformed")
    persisted: dict[str, str] = {}
    for item in manifest:
        if not isinstance(item, dict):
            raise TypeError("ML sandbox artifact entry is malformed")
        name = str(item.get("name") or "")
        relative = _safe_name(name)
        path = (work_dir / "artifacts" / relative).resolve()
        root = (work_dir / "artifacts").resolve()
        if root != path and root not in path.parents:
            raise RuntimeError("ML sandbox artifact escaped its work directory")
        data = path.read_bytes()
        expected = str(item.get("sha256") or "")
        if not expected or hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"ML sandbox artifact digest mismatch for {name!r}")
        artifact_id = sink.put(
            name,
            data,
            str(item.get("content_type") or "application/octet-stream"),
        )
        reference = str(item.get("reference") or "")
        if not reference:
            raise RuntimeError(f"ML sandbox artifact reference missing for {name!r}")
        persisted[reference] = artifact_id
    return persisted


def _run_child(
    request: dict[str, Any],
    *,
    sink: ArtifactSink | None,
    on_stage: Callable[[str], None] | None,
    is_cancelled: Callable[[], bool] | None,
) -> dict[str, Any]:
    assets = str(_assets_dir())
    with tempfile.TemporaryDirectory(prefix="redsim-ml-sandbox-") as raw_dir:
        work_dir = Path(raw_dir)
        request_path = work_dir / "request.json"
        request_path.write_text(
            json.dumps({**request, "assets_dir": assets}), encoding="utf-8"
        )
        cfg = SandboxConfig.from_env(timeout_s=_timeout_seconds())
        env = _child_env(cfg)
        env.update({
            "PYTHONUNBUFFERED": "1",
            "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            # The only REDSIM_* value the child receives: a resolved directory,
            # never a credential. Every other REDSIM_*, KAGGLE_*, PYTHIA_* and
            # proxy variable stays behind with the allowlist in _child_env.
            ASSETS_DIR_ENV: assets,
        })
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
            preexec_fn=_rlimit_preexec(cfg),  # noqa: PLW1509 - required for POSIX rlimits
            start_new_session=True,
        )
        started = time.monotonic()
        reported: set[str] = set()
        forced_status: str | None = None
        forced_error: str | None = None
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
                forced_status = "failed"
                forced_error = f"ML sandbox timed out after {cfg.timeout_s}s"
                _kill_process_group(proc)
                break
            time.sleep(0.2)
        _, stderr = proc.communicate()
        stages = _events(work_dir / "events.jsonl")
        for stage in stages:
            if stage not in reported and on_stage is not None:
                on_stage(stage)
        artifact_ids = (
            _persist_child_artifacts(work_dir, sink)
            if sink is not None else {}
        )
        result_path = work_dir / "result.json"
        if forced_status is not None:
            return {
                "forced_status": forced_status,
                "error": forced_error,
                "stages_done": stages,
            }
        if proc.returncode != 0 or not result_path.is_file():
            detail = (stderr or "").strip()[-1000:]
            return {
                "forced_status": "failed",
                "error": (
                    f"ML sandbox exited with status {proc.returncode}: {detail}"
                ),
                "stages_done": stages,
            }
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("ML sandbox result is malformed")
        payload["artifact_ids"] = artifact_ids
        return payload


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
) -> CampaignRecord:
    """Execute a campaign in a bounded, credential-free process group."""
    payload = _run_child(
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
    )
    forced_status = payload.get("forced_status")
    if forced_status:
        return partial_campaign_record(
            config,
            status=str(forced_status),
            error=str(payload.get("error") or "ML sandbox failed"),
            stages_done=list(payload.get("stages_done") or []),
            baseline_run_id=baseline_run_id,
            parent_run_id=parent_run_id,
        )
    record = CampaignRecord.model_validate(payload["record"])
    mapping = payload.get("artifact_ids")
    if not isinstance(mapping, dict):
        raise TypeError("ML sandbox artifact mapping is malformed")
    observations = []
    for observation in record.observations:
        artifacts: dict[str, str] = {}
        for name, reference in observation.artifacts.items():
            artifact_id = mapping.get(reference)
            if not isinstance(artifact_id, str):
                raise TypeError(
                    f"ML sandbox did not persist observation artifact {name!r}"
                )
            artifacts[name] = artifact_id
        observations.append(observation.model_copy(update={"artifacts": artifacts}))
    return CampaignRecord.model_validate({
        **record.model_dump(mode="json"),
        "observations": [
            item.model_dump(mode="json") for item in observations
        ],
    })


def validate_model_sandboxed(
    target_id: str,
    target_file: Path,
    target_detail: dict[str, Any],
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Load and probe uploaded bytes without deserializing in the Celery process."""
    payload = _run_child(
        {
            "mode": "validate",
            "target_id": target_id,
            "target_file": str(target_file),
            "target_detail": target_detail,
        },
        sink=None,
        on_stage=None,
        is_cancelled=is_cancelled,
    )
    if payload.get("forced_status"):
        raise RuntimeError(str(payload.get("error") or "ML sandbox validation failed"))
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise TypeError("ML sandbox validation did not return a manifest")
    return manifest


__all__ = [
    "ASSETS_DIR_ENV",
    "DEFAULT_ASSETS_DIR",
    "partial_campaign_record",
    "run_campaign_sandboxed",
    "validate_model_sandboxed",
]