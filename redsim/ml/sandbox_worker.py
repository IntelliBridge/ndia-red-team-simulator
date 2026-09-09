"""Child entry point for bounded adversarial-ML execution.

The child writes one typed envelope to ``<work_dir>/result.json`` (spec 9.4)::

    {"ok": true,  "result": {"manifest": {...}}}            # validate
    {"ok": true,  "result": {"record": <CampaignRecord>}}   # campaign
    {"ok": false, "error_class": "<redsim.ml.errors name>",
                  "error": "<operator-safe message>", "code": "<errors.<cls>.code>"}

Exit status 0 means "an envelope was written" (success *or* a structured
refusal); 2 means the request itself was unreadable; any other non-zero status
means the process died before writing, which the parent reports as
``SandboxKilled``. Refusals therefore never travel as stderr text: the parent
rebuilds the typed class from ``error_class`` (``redsim.ml.sandbox``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from redsim.ml.schema import CampaignConfig

# Same name ``redsim.ml.targets.bundled.assets_dir`` reads; kept as a literal so
# applying it needs no ML import (numpy, torch) before the request is trusted.
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"

# Spec 10.8 / 16.1: the Pythia writer runs in the worker parent, never here. The
# parent already strips these from the child env; scrubbing them again in-process
# means a widened allowlist can never turn the child into an LLM caller.
_LLM_ENV_PREFIXES = ("PYTHIA_",)
_LLM_ENV_KEYS = frozenset({"REDSIM_ML_LLM_MODEL", "AEGIS_ML_LLM_MODEL", "REDSIM_LLM_MODEL"})

#: Exit status for a request the child could not even read (mirrors the plugin worker).
EXIT_BAD_REQUEST = 2

#: Cap on the envelope the parent will read (spec 9.4: large arrays go to files).
ENVELOPE_MAX_BYTES = 16 * 1024 * 1024


def scrub_llm_env(environ: dict[str, str] | None = None) -> list[str]:
    """Drop every Pythia / LLM-model variable from ``environ`` (default ``os.environ``).

    Returns the names removed. The child holds no gateway key and never talks to
    Pythia; the narrative, when requested, is the worker parent's job after the
    envelope returns (``redsim.workers.tasks.ml_campaign``).
    """
    env = os.environ if environ is None else environ
    removed = sorted(
        key for key in env
        if key.startswith(_LLM_ENV_PREFIXES) or key in _LLM_ENV_KEYS
    )
    for key in removed:
        del env[key]
    return removed


def _apply_assets_dir(request: dict[str, Any]) -> Path | None:
    """Point every asset lookup in this process at the parent's resolved tree.

    The parent strips the whole ``REDSIM_*`` namespace from the child env and
    hands the bundled asset directory over explicitly as ``request["assets_dir"]``
    (see ``redsim.ml.sandbox._run_child``). Bundled targets, tabular targets and
    ``services.ml_models._evaluation_binding`` all read ``REDSIM_ML_ASSETS_DIR``
    at call time, so setting it here, before any of them is imported, is what
    makes a non-default assets mount work inside the child.

    Only an absolute path string is accepted: a relative value would silently
    re-anchor on the child's working directory, which is exactly the ambiguity
    the explicit hand-off exists to remove. A request without the field leaves
    the environment untouched (the parent's env copy, when present, still wins).
    """
    raw = request.get("assets_dir")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            f"sandbox request assets_dir must be a non-empty path string, got {raw!r}"
        )
    path = Path(raw)
    if not path.is_absolute():
        raise ValueError(
            f"sandbox request assets_dir must be absolute, got {raw!r}"
        )
    os.environ[ASSETS_DIR_ENV] = str(path)
    return path


class DirectoryArtifactSink:
    """Write child artifacts into one parent-owned work directory."""

    def __init__(self, work_dir: Path) -> None:
        self.work_dir = work_dir.resolve()
        self.root = (self.work_dir / "artifacts").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest: list[dict[str, str]] = []
        self.hashes: dict[str, str] = {}

    def put(
        self,
        name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError(f"unsafe artifact name {name!r}")
        path = (self.root / Path(*relative.parts)).resolve()
        if self.root != path and self.root not in path.parents:
            raise ValueError(f"artifact escaped sandbox directory: {name!r}")
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()
        reference = f"sandbox:{name}:{digest}"
        # The same name may be written twice with different bytes (one explainer per attack reuses
        # ``obs_<i>/adv.png``); every distinct reference must survive for the parent to persist, so the
        # earlier version moves to a digest-qualified path and its manifest entry records where it went.
        for item in self.manifest:
            if item["name"] == name and item["sha256"] != digest and item.get("path", name) == name:
                kept = path.with_name(f"{path.stem}.{item['sha256'][:16]}{path.suffix}")
                os.replace(path, kept)
                item["path"] = str(PurePosixPath(*relative.parts[:-1], kept.name))
        path.write_bytes(data)
        # Key by both the bare name and the returned reference: the explainers digest through the value
        # put() returned, exactly as they do against the filesystem and database sinks (ArtifactSink protocol).
        self.hashes[name] = digest
        self.hashes[reference] = digest
        self.manifest = [item for item in self.manifest if item["reference"] != reference]
        self.manifest.append({
            "name": name,
            "content_type": content_type,
            "sha256": digest,
            "reference": reference,
            "path": name,
        })
        # Write-then-rename so a kill mid-write never leaves a truncated manifest
        # for the parent's partial-evidence pass to misread.
        tmp = self.work_dir / "artifacts.json.tmp"
        tmp.write_text(json.dumps(self.manifest), encoding="utf-8")
        os.replace(tmp, self.work_dir / "artifacts.json")
        return reference

    def sha256(self, name: str) -> str:
        return self.hashes[name]


def _write_envelope(work_dir: Path, envelope: dict[str, Any]) -> None:
    """Atomically publish the typed envelope; a partial ``result.json`` is never visible."""
    data = json.dumps(envelope)
    if len(data.encode("utf-8")) > ENVELOPE_MAX_BYTES:
        envelope = _error_envelope(
            "EnvelopeInvalid",
            f"sandbox envelope exceeds {ENVELOPE_MAX_BYTES} bytes; large arrays belong in artifact files",
            code="envelope_invalid",
        )
        data = json.dumps(envelope)
    tmp = work_dir / "result.json.tmp"
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, work_dir / "result.json")


def _ok_envelope(result: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "result": result}


def _error_envelope(error_class: str, error: str, *, code: str | None = None) -> dict[str, Any]:
    envelope: dict[str, Any] = {"ok": False, "error_class": error_class, "error": error[:4000]}
    if code:
        envelope["code"] = code
    return envelope


def _envelope_for_exception(exc: BaseException) -> dict[str, Any]:
    """Structured refusal for ``exc``: class name, operator-safe text, spec 10.6 code when any."""
    code = getattr(exc, "code", None)
    return _error_envelope(
        type(exc).__name__,
        str(exc) or type(exc).__name__,
        code=code if isinstance(code, str) else None,
    )


def _campaign(request: dict[str, Any], work_dir: Path) -> None:
    from redsim.ml.campaign import run_campaign
    from redsim.ml.sandbox import partial_campaign_record
    from redsim.services.ml_models import artifact_target_from_path

    try:
        config = CampaignConfig.model_validate(request["config"])
    except Exception as exc:  # noqa: BLE001 - a bad request is reported, not a crash
        _write_envelope(work_dir, _envelope_for_exception(exc))
        return
    sink = DirectoryArtifactSink(work_dir)
    stages: list[str] = []

    def on_stage(stage: str) -> None:
        stages.append(stage)
        with (work_dir / "events.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"stage": stage}) + "\n")
            fh.flush()

    try:
        # Building the uploaded target performs the sniff/digest/architecture
        # checks, so a refused model is campaign failure evidence (a partial
        # record naming ``ModelLoadRefused``/``UnsupportedArtifact``), not a crash.
        target = None
        target_file = request.get("target_file")
        if isinstance(target_file, str) and target_file:
            target = artifact_target_from_path(
                config.target_id,
                Path(target_file),
                dict(request.get("target_detail") or {}),
            )
        record = run_campaign(
            config,
            sink,
            explain=config.explain_k > 0,
            baseline_run_id=request.get("baseline_run_id"),
            parent_run_id=request.get("parent_run_id"),
            on_stage=on_stage,
            target_override=target,
        )
    except Exception as exc:  # noqa: BLE001 - child returns structured failure evidence
        message = f"{type(exc).__name__}: {exc}"
        record = partial_campaign_record(
            config,
            status="failed",
            error=message,
            stages_done=stages,
            baseline_run_id=request.get("baseline_run_id"),
            parent_run_id=request.get("parent_run_id"),
        )
    _write_envelope(work_dir, _ok_envelope({"record": record.model_dump(mode="json")}))


def _validate(request: dict[str, Any], work_dir: Path) -> None:
    """Load and probe the uploaded bytes; every outcome is a typed envelope."""
    try:
        from redsim.services.ml_models import artifact_target_from_path

        target = artifact_target_from_path(
            str(request["target_id"]),
            Path(str(request["target_file"])),
            dict(request.get("target_detail") or {}),
        )
        target.load()
        manifest = target.manifest()
    except Exception as exc:  # noqa: BLE001 - refusals travel as data, never as stderr text
        _write_envelope(work_dir, _envelope_for_exception(exc))
        return
    if not isinstance(manifest, dict):
        _write_envelope(work_dir, _error_envelope(
            "EnvelopeInvalid", "target.manifest() did not return an object", code="envelope_invalid",
        ))
        return
    _write_envelope(work_dir, _ok_envelope({"manifest": manifest}))


def main() -> int:
    parser = argparse.ArgumentParser(prog="redsim.ml.sandbox_worker")
    parser.add_argument("--request", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    work_dir = Path(args.work_dir).resolve()
    try:
        request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"sandbox request unreadable: {exc}", file=sys.stderr)
        return EXIT_BAD_REQUEST
    if not isinstance(request, dict):
        print("sandbox request must be an object", file=sys.stderr)
        return EXIT_BAD_REQUEST
    # The child never narrates: whatever the parent allowlist forwarded, no
    # Pythia key or model id survives into the campaign code path.
    scrub_llm_env()
    # Must precede the lazy ML imports in _campaign/_validate: they resolve the
    # manifest from REDSIM_ML_ASSETS_DIR the moment a target is built or loaded.
    _apply_assets_dir(request)
    mode = request.get("mode")
    if mode == "campaign":
        _campaign(request, work_dir)
    elif mode == "validate":
        _validate(request, work_dir)
    else:
        print(f"unknown sandbox mode {mode!r}", file=sys.stderr)
        return EXIT_BAD_REQUEST
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through parent
    raise SystemExit(main())
