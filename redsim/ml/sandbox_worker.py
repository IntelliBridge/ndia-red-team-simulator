"""Child entry point for bounded adversarial-ML execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from redsim.ml.schema import CampaignConfig

# Same name ``redsim.ml.targets.bundled.assets_dir`` reads; kept as a literal so
# applying it needs no ML import (numpy, torch) before the request is trusted.
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"


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
    """Write child artifacts into one parent-owned temporary directory."""

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
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        reference = f"sandbox:{name}:{digest}"
        self.hashes[name] = digest
        self.manifest = [item for item in self.manifest if item["name"] != name]
        self.manifest.append({
            "name": name,
            "content_type": content_type,
            "sha256": digest,
            "reference": reference,
        })
        (self.work_dir / "artifacts.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )
        return reference

    def sha256(self, name: str) -> str:
        return self.hashes[name]


def _write_result(work_dir: Path, payload: dict[str, Any]) -> None:
    (work_dir / "result.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _campaign(request: dict[str, Any], work_dir: Path) -> None:
    from redsim.ml.campaign import run_campaign
    from redsim.ml.sandbox import partial_campaign_record
    from redsim.services.ml_models import artifact_target_from_path

    config = CampaignConfig.model_validate(request["config"])
    target_file = request.get("target_file")
    target = None
    if isinstance(target_file, str) and target_file:
        target = artifact_target_from_path(
            config.target_id,
            Path(target_file),
            dict(request.get("target_detail") or {}),
        )
    sink = DirectoryArtifactSink(work_dir)
    stages: list[str] = []

    def on_stage(stage: str) -> None:
        stages.append(stage)
        with (work_dir / "events.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"stage": stage}) + "\n")
            fh.flush()

    try:
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
    _write_result(work_dir, {"record": record.model_dump(mode="json")})


def _validate(request: dict[str, Any], work_dir: Path) -> None:
    from redsim.services.ml_models import artifact_target_from_path

    target = artifact_target_from_path(
        str(request["target_id"]),
        Path(str(request["target_file"])),
        dict(request.get("target_detail") or {}),
    )
    target.load()
    _write_result(work_dir, {"manifest": target.manifest()})


def main() -> int:
    parser = argparse.ArgumentParser(prog="redsim.ml.sandbox_worker")
    parser.add_argument("--request", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    work_dir = Path(args.work_dir).resolve()
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise TypeError("sandbox request must be an object")
    # Must precede the lazy ML imports in _campaign/_validate: they resolve the
    # manifest from REDSIM_ML_ASSETS_DIR the moment a target is built or loaded.
    _apply_assets_dir(request)
    if request.get("mode") == "campaign":
        _campaign(request, work_dir)
    elif request.get("mode") == "validate":
        _validate(request, work_dir)
    else:
        raise ValueError("unknown sandbox mode")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through parent
    raise SystemExit(main())