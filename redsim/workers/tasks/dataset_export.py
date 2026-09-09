"""``redsim.dataset_export`` — build the Croissant + Parquet export of a campaign run (INTEROP-08, -12).

The task runs on the ``scans`` pool (declared at enqueue in
:func:`redsim.services.ml_datasets_export.admit_export`). Its follow-up ``Job``
carries the source run id in ``Job.detail``; the body loads that run's persisted
slices (``ml.adv_slice`` / ``ml.clean_slice`` / ``ml.control_slice``) and its
``ml.flip_matrix``, builds one deterministic Parquet shard per slice, checks the
projection-equality guard against the flip_matrix, builds the Croissant manifest
and (by default) the dataset card, and writes them into the export prefix
``datasets/<source-run-id>/`` as ``Artifact`` rows on the **source** run with
kinds ``ml.dataset.manifest`` / ``ml.dataset.parquet`` / ``ml.dataset.card``.

Audit: one ``dataset.export.execute`` row (manifest sha256, file count, byte
total, prefix, digests and counts only — never a URL, key or model bytes) and a
``job.complete`` row on the follow-up run chain. A projection mismatch or an
invalid manifest is a ``success=False`` ``dataset.export.execute`` row and a
failed job — the export refuses to ship labels that are not the record's. The
shards are content-addressed, so a re-export of an unchanged run reuses the rows
and yields the same manifest sha256 (one export per run).

pyarrow is imported only through :mod:`redsim.ml.interop` inside the body, so
importing this module keeps the API-process ML tripwire green.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from redsim.workers.celery_app import app

if TYPE_CHECKING:  # pragma: no cover - typing only
    from celery import Task
    from sqlalchemy.orm import Session

    from redsim.storage import BlobStore
    from redsim.workers.bootstrap import TaskContext

logger = logging.getLogger(__name__)

_SLICE_KINDS = ("ml.adv_slice", "ml.clean_slice", "ml.control_slice")
_MANIFEST_KIND = "ml.dataset.manifest"
_PARQUET_KIND = "ml.dataset.parquet"
_CARD_KIND = "ml.dataset.card"
_MANIFEST_NAME = "croissant.json"
_CARD_NAME = "README.md"


def _read_blob(blob_store: BlobStore, location: str, sha256: str) -> bytes:
    data = blob_store.get(str(location))
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if hashlib.sha256(raw).hexdigest() != str(sha256):
        raise ValueError(f"artifact bytes at {location} do not match the recorded digest")
    return raw


def _load_flip_matrix(session: Session, blob_store: BlobStore, source_run_id: str) -> dict[str, Any]:
    from sqlalchemy import select

    from redsim.db.models import Artifact

    row = session.execute(
        select(Artifact).where(Artifact.run_id == source_run_id, Artifact.kind == "ml.flip_matrix")
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().first()
    if row is None:
        return {}
    raw = _read_blob(blob_store, str(row.location), str(row.sha256))
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


def _load_slices(session: Session, blob_store: BlobStore, source_run_id: str) -> tuple[list[Any], list[str]]:
    """Return ``(loaded_slices, caveats)`` from the source run's persisted slice artifacts."""
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.ml.interop import LoadedSlice, parse_npz, slice_descriptor_from_location

    rows = session.execute(
        select(Artifact).where(Artifact.run_id == source_run_id, Artifact.kind.in_(_SLICE_KINDS))
        .order_by(Artifact.created_at.asc(), Artifact.id.asc())
    ).scalars().all()
    loaded: list[Any] = []
    caveats: list[str] = []
    seen: set[str] = set()
    for row in rows:
        descriptor = slice_descriptor_from_location(str(row.location))
        if descriptor is None:
            caveats.append(f"a {row.kind} artifact could not be labelled from its storage location and was skipped")
            continue
        family, attack, eps = descriptor
        key = f"{family}|{attack}|{eps}"
        if key in seen:
            continue
        seen.add(key)
        arrays = parse_npz(_read_blob(blob_store, str(row.location), str(row.sha256)))
        loaded.append(LoadedSlice(family=family, attack=attack, eps=eps, arrays=arrays))
    return loaded, caveats


def _dataset_license(session: Session, source_run: Any, record: Any) -> str:
    from redsim.db.models import Target

    if source_run.target_id:
        target = session.get(Target, source_run.target_id)
        detail = getattr(target, "detail", None) if target is not None else None
        if isinstance(detail, dict):
            raw_manifest = detail.get("manifest")
            manifest = raw_manifest if isinstance(raw_manifest, dict) else {}
            for candidate in (detail.get("license"), manifest.get("license")):
                if isinstance(candidate, str) and candidate.strip():
                    return candidate
    manifest = (record.provenance.model_manifest if record.provenance else None) or {}
    candidate = manifest.get("license")
    return candidate if isinstance(candidate, str) and candidate.strip() else "unknown"


def _write_export_artifact(ctx: TaskContext, *, source_run_id: str, name: str, kind: str,
                           data: bytes, content_type: str) -> tuple[str, str]:
    """Content-addressed put under ``datasets/<run>/<name>`` + an Artifact row on the source run.

    Returns ``(artifact_id, sha256)``. A re-export of unchanged bytes reuses the row.
    """
    from uuid import uuid4

    from sqlalchemy import select

    from redsim.db.models import Artifact

    digest = hashlib.sha256(data).hexdigest()
    existing = ctx.session.execute(select(Artifact).where(
        Artifact.run_id == source_run_id, Artifact.kind == kind, Artifact.sha256 == digest,
    )).scalar_one_or_none()
    if existing is not None:
        return str(existing.id), digest
    key = f"datasets/{source_run_id}/{name}"
    ref = ctx.blob_store.put(key, data, content_type=content_type)
    row = Artifact(
        id=str(uuid4()), run_id=source_run_id, project_id=ctx.project_id, kind=kind,
        sha256=digest, location=ref.location, content_type=content_type, size_bytes=len(data),
    )
    ctx.session.add(row)
    ctx.session.flush()
    return str(row.id), digest


@app.task(name="redsim.dataset_export", bind=True, max_retries=2)
def dataset_export(self: Task, job_id: str) -> dict[str, Any]:
    from redsim.db.models import Job, Run
    from redsim.ml.interop import (
        build_manifest,
        build_shards,
        check_projection,
        croissant_validate,
        render_card,
    )
    from redsim.ml.schema import CampaignRecord
    from redsim.services.reports import load_run_record
    from redsim.workers.bootstrap import task_context

    logger.info("dataset_export begin job_id=%s", job_id)
    with task_context(job_id, task=self, commit_running=True) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        if ctx.audit_writer is None:
            raise RuntimeError("dataset_export needs an audit writer")
        writer = ctx.audit_writer

        job = ctx.session.get(Job, job_id)
        detail = dict(getattr(job, "detail", None) or {})
        source_run_id = str(detail.get("source_run_id") or "")
        include_card = bool(detail.get("include_card", True))
        prefix = f"datasets/{source_run_id}/"

        source_run = ctx.session.get(Run, source_run_id)
        if source_run is None:
            raise RuntimeError(f"source run {source_run_id!r} not found for export")

        def _refuse(reason: str) -> None:
            writer.append(
                action="dataset.export.execute", actor=ctx.worker_actor, target=None,
                allowlist_check="n/a", override=False, success=False,
                detail={"source_run_id": source_run_id, "reason": reason, "job_id": job_id},
                run_id=ctx.run_id, project_id=ctx.project_id,
            )

        record_dict, record_sha = load_run_record(ctx.session, ctx.blob_store, source_run_id)
        record = CampaignRecord.model_validate(record_dict)
        flip_matrix = _load_flip_matrix(ctx.session, ctx.blob_store, source_run_id)
        loaded, caveats = _load_slices(ctx.session, ctx.blob_store, source_run_id)
        if not loaded:
            _refuse("no labelled slices were available to export")
            raise RuntimeError(f"run {source_run_id} has no labelled slices to export")

        dataset_license = _dataset_license(ctx.session, source_run, record)

        try:
            shards = build_shards(record, loaded, flip_matrix=flip_matrix)
            if not shards:
                raise RuntimeError("no shards were produced from the retained slices")
            checked_against = check_projection(shards, flip_matrix)
            manifest, manifest_bytes, manifest_sha = build_manifest(
                record, shards, dataset_license=dataset_license, regenerated=False,
                checked_against=checked_against)
            croissant_validate(manifest)
        except Exception as exc:  # noqa: BLE001 - a mismatch/invalid manifest is a refusal, not a crash
            _refuse(f"{type(exc).__name__}: {exc}")
            raise

        total_rows = sum(shard.n_rows for shard in shards)
        card_text = render_card(manifest, limitations=list(record.limitations),
                                license=dataset_license, total_rows=total_rows) if include_card else None

        artifact_ids: dict[str, str] = {}
        bytes_total = 0
        for shard in shards:
            aid, _ = _write_export_artifact(
                ctx, source_run_id=source_run_id, name=f"data/{shard.name}", kind=_PARQUET_KIND,
                data=shard.data, content_type="application/vnd.apache.parquet")
            artifact_ids[shard.name] = aid
            bytes_total += shard.size
        manifest_id, _ = _write_export_artifact(
            ctx, source_run_id=source_run_id, name=_MANIFEST_NAME, kind=_MANIFEST_KIND,
            data=manifest_bytes, content_type="application/ld+json")
        bytes_total += len(manifest_bytes)
        card_id: str | None = None
        if card_text is not None:
            card_bytes = card_text.encode("utf-8")
            card_id, _ = _write_export_artifact(
                ctx, source_run_id=source_run_id, name=_CARD_NAME, kind=_CARD_KIND,
                data=card_bytes, content_type="text/markdown; charset=utf-8")
            bytes_total += len(card_bytes)

        n_files = len(shards) + 1 + (1 if card_id else 0)
        from redsim.safety import authorize

        authorize(
            "dataset.export.execute", None, allowlist=[], actor=ctx.worker_actor,
            writer=writer, run_id=ctx.run_id, project_id=ctx.project_id,
            detail={
                "source_run_id": source_run_id, "manifest_sha256": manifest_sha,
                "record_sha256": record_sha, "n_files": n_files, "bytes_total": bytes_total,
                "prefix": prefix, "n_shards": len(shards), "n_rows": total_rows,
                "regenerated": False, "projection_checked_against": checked_against,
                "caveats": caveats, "include_card": bool(card_id),
            },
        )
        writer.append(
            action="job.complete", actor=ctx.worker_actor, target=None, allowlist_check="n/a",
            override=False, success=True,
            detail={"job_type": "dataset.export", "status": "succeeded", "job_id": job_id,
                    "run_id": ctx.run_id, "source_run_id": source_run_id,
                    "manifest_sha256": manifest_sha, "n_files": n_files, "bytes_total": bytes_total},
            run_id=ctx.run_id, project_id=ctx.project_id,
        )
        logger.info("dataset_export finished job_id=%s source_run=%s files=%d", job_id, source_run_id, n_files)
        return {
            "job_id": job_id, "run_id": ctx.run_id, "source_run_id": source_run_id,
            "dataset_id": source_run_id, "manifest_sha256": manifest_sha,
            "manifest_artifact_id": manifest_id, "card_artifact_id": card_id,
            "prefix": prefix, "n_files": n_files, "n_shards": len(shards), "n_rows": total_rows,
            "bytes_total": bytes_total, "artifacts": artifact_ids, "caveats": caveats,
        }


__all__ = ["dataset_export"]
