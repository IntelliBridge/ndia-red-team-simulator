"""Read-only catalog of the bundled evaluation datasets (spec 17.2 ``GET /v1/datasets``).

Rows come from ``assets/MANIFEST.json`` as ``redsim ml build-assets`` writes it,
read through the same plain-JSON reader the upload binding uses
(``redsim.services.ml_models.read_asset_manifest``). When no manifest is built
the response says so (``assets.status``) instead of presenting an empty list as
a healthy catalog. CI fixture datasets are listed with ``role: "ci_fixture"``
so the UI can show them honestly; they are never demo evidence (spec 11.1).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from redsim.api.auth import CurrentUser, get_current_user
from redsim.services.ml_models import (
    DatasetBindingError,
    assets_root_path,
    dataset_entries,
    dataset_modality,
    read_asset_manifest,
)

router = APIRouter(prefix="/datasets", tags=["ml-datasets"])

_MODALITIES = ("image", "tabular", "llm")


def _split_items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [value for value in raw.values() if isinstance(value, dict)]
    if isinstance(raw, list):
        return [value for value in raw if isinstance(value, dict)]
    return []


def _row(dataset_id: str, raw: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    splits = _split_items(raw.get("splits"))
    size = raw.get("n_rows")
    if size is None:
        size = sum(int(split.get("n", 0) or 0) for split in splits)
    bundled = [split for split in splits if isinstance(split.get("file"), dict) and split["file"].get("path")]
    source = str(raw.get("source", "local"))
    modality = dataset_modality(raw, dataset_id, document)
    return {
        "id": dataset_id,
        "name": str(raw.get("name") or dataset_id),
        "license": str(raw.get("license") or "not declared"),
        "source_url": str(raw.get("url") or ""),
        "classes": [str(value) for value in (raw.get("class_names") or [])],
        "size": int(size or 0),
        "format": str(raw.get("format") or source),
        "revision": str(raw.get("revision") or raw.get("source_file_sha256") or ""),
        "role": "ci_fixture" if raw.get("fixture_only") else "demo",
        "fixture_only": bool(raw.get("fixture_only", False)),
        "reachability": "bundled" if bundled else "manifest_only",
        "bundled_splits": sorted(str(split.get("name") or "") for split in bundled),
        "compatible_modalities": [modality] if modality in _MODALITIES else [],
    }


def dataset_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """``(rows, assets)``: the catalog and the recorded state of the asset manifest."""
    root = assets_root_path()
    try:
        document = read_asset_manifest(root)
    except DatasetBindingError as exc:
        return [], {"status": "missing", "assets_dir": str(root), "reason": str(exc)}
    rows = [
        _row(dataset_id, raw, document)
        for dataset_id, raw in dataset_entries(document).items()
    ]
    # ``dataset_entries`` maps both the mapping key and the entry's own id; list each entry once.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        key = f"{row['id']}|{row['revision']}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique, {"status": "built", "assets_dir": str(root), "built_at": document.get("built_at")}


@router.get("")
def list_datasets(_user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    datasets, assets = dataset_rows()
    return {"datasets": datasets, "count": len(datasets), "assets": assets}
