"""Read-only catalog of the bundled evaluation datasets."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/datasets", tags=["ml-datasets"])


def _manifest_path() -> Path:
    return Path(os.environ.get("REDSIM_ML_ASSETS_DIR", "").strip() or "./assets") / "MANIFEST.json"


def _rows() -> list[dict[str, Any]]:
    path = _manifest_path()
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    datasets: object = (
        document.get("datasets", {}) if isinstance(document, dict) else {}
    )
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(datasets, dict):
        entries = [
            (str(key), value)
            for key, value in datasets.items()
            if isinstance(value, dict)
        ]
    elif isinstance(datasets, list):
        entries = [
            (str(value.get("id", "")), value)
            for value in datasets
            if isinstance(value, dict)
        ]
    rows: list[dict[str, Any]] = []
    for dataset_id, raw in entries:
        if not dataset_id or not isinstance(raw, dict):
            continue
        splits_value = raw.get("splits")
        splits: dict[str, Any] = (
            splits_value if isinstance(splits_value, dict) else {}
        )
        size = raw.get("n_rows")
        if size is None:
            size = 0
            for split in splits.values():
                if isinstance(split, dict):
                    size += int(split.get("n", 0))
        source = str(raw.get("source", "local"))
        classes = list(raw.get("class_names") or [])
        preprocessing_value = raw.get("preprocessing")
        preprocessing: dict[str, Any] = (
            preprocessing_value if isinstance(preprocessing_value, dict) else {}
        )
        modality = str(preprocessing.get("modality") or ("image" if classes else "tabular"))
        rows.append({
            "id": dataset_id,
            "name": str(raw.get("name") or dataset_id),
            "license": str(raw.get("license") or "not declared"),
            "source_url": str(raw.get("url") or ""),
            "classes": classes,
            "size": int(size or 0),
            "format": str(raw.get("format") or source),
            "revision": str(raw.get("revision") or raw.get("source_file_sha256") or ""),
            "role": "ci_fixture" if raw.get("fixture_only") else "demo",
            "reachability": "bundled" if any(
                isinstance(s, dict) and s.get("file") for s in splits.values()
            ) else "manifest_only",
            "compatible_modalities": [modality] if modality in {"image", "tabular", "llm"} else [],
        })
    return rows


@router.get("")
def list_datasets(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    datasets = _rows()
    return {"datasets": datasets, "count": len(datasets)}