"""Authoritative ML campaign reads, comparisons, and reviewer annotations."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check, ensure_run_access

router = APIRouter(tags=["ml-campaigns"])


def _error(
    code: str,
    message: str,
    *,
    status_code: int = 404,
    **extra: Any,
) -> HTTPException:
    """Build the structured error envelope used by new ML endpoints."""
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message, **extra},
    )


def _campaign_table(session: Any) -> Any:
    # The migration owns this table. Reflection prevents the API schema from
    # drifting into a second ORM declaration.
    from sqlalchemy import MetaData, Table

    return Table("ml_campaigns", MetaData(), autoload_with=session.get_bind())


def _campaign_row(session: Any, run_id: str) -> Any:
    table = _campaign_table(session)
    return session.execute(
        table.select().where(table.c.run_id == run_id)
    ).mappings().one_or_none()


def _load_campaign(run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read the immutable record bytes and the mutable campaign overlay.

    Projections deliberately are not used to reconstruct the campaign: the
    ``ml.run_record`` artifact is the record of execution.
    """
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.db.session import get_session
    from redsim.storage.blobs import open_blob_store

    with get_session() as sess:
        campaign = _campaign_row(sess, run_id)
        artifact = sess.execute(
            select(Artifact).where(
                Artifact.run_id == run_id, Artifact.kind == "ml.run_record"
            )
        ).scalar_one_or_none()
        if campaign is None or artifact is None:
            raise _error("campaign_not_found", "campaign record not found")
        location = str(artifact.location)
        expected_sha256 = str(artifact.sha256)

    try:
        data = open_blob_store().get(location)
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise _error(
                "campaign_artifact_digest_mismatch",
                "campaign record bytes do not match the recorded digest",
                status_code=409,
            )
        payload = json.loads(raw)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 - storage and JSON failures share one evidence error
        # A missing or malformed immutable record cannot be represented by
        # projections without violating the evidence-read contract.
        raise _error("campaign_not_found", "campaign record not found") from None
    if not isinstance(payload, dict):
        raise _error("campaign_not_found", "campaign record not found")
    return payload, dict(campaign)


def _sample_hash(record: dict[str, Any]) -> Any:
    provenance = record.get("provenance")
    return provenance.get("sample_indices_sha256") if isinstance(provenance, dict) else None


def _settings_hash(record: dict[str, Any]) -> Any:
    # CampaignRecord owns this at top level; score/provenance fallbacks retain
    # compatibility with records written by earlier workers.
    score = record.get("score")
    provenance = record.get("provenance")
    return (record.get("settings_hash")
            or (score.get("settings_hash") if isinstance(score, dict) else None)
            or (provenance.get("settings_hash") if isinstance(provenance, dict) else None))


def _score(record: dict[str, Any]) -> dict[str, Any] | None:
    value = record.get("score")
    return value if isinstance(value, dict) else None


def _changed_variables(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    left_provenance = left.get("provenance") or {}
    right_provenance = right.get("provenance") or {}
    if left_provenance.get("model_sha256") != right_provenance.get("model_sha256"):
        changed.append("model")
    left_config = left.get("config") or {}
    right_config = right.get("config") or {}
    if left_config.get("defense") != right_config.get("defense"):
        changed.append("defense")
    if left_config.get("llm_narrative") != right_config.get("llm_narrative"):
        changed.append("llm_narrative")
    if not changed and (
        left.get("parent_run_id") == right.get("run_id")
        or right.get("parent_run_id") == left.get("run_id")
    ):
        changed.append("rerun")
    return changed


def _scorecard(record: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
    return {
        **score,
        "run_id": record.get("run_id"),
        "measurements": record.get("measurements", []),
        "curve": record.get("curve", []),
    }


def _comparison_families(delta: dict[str, Any]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for item in delta.get("delta_families", []):
        if not isinstance(item, dict):
            continue
        before_value = item.get("before")
        after_value = item.get("after")
        before: dict[str, Any] = (
            before_value if isinstance(before_value, dict) else {}
        )
        after: dict[str, Any] = (
            after_value if isinstance(after_value, dict) else {}
        )
        flattened.append({
            "family": item.get("measurement_id"),
            "before": before.get("accuracy"),
            "after": after.get("accuracy"),
            "n_before": before.get("n"),
            "n_after": after.get("n"),
            "delta": item.get("delta"),
        })
    return flattened


@router.get("/runs/{run_id}/campaign")
def get_campaign(
    run_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from sqlalchemy import select

    from redsim.api.v1.findings import _finding_to_dict
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    ensure_run_access(user, run_id)
    record, campaign = _load_campaign(run_id)
    with get_session() as sess:
        findings = sess.execute(
            select(Finding).where(Finding.run_id == run_id)
        ).scalars().all()
    # Mutable projections are appended without altering the authoritative
    # ml.run_record bytes.
    record["reviewer_notes"] = campaign.get("reviewer_notes")
    record["project_id"] = str(campaign["project_id"])
    record["findings"] = [
        _finding_to_dict(row, source_tool=True, dedup_key=True)
        for row in findings
    ]
    return record


@router.get("/runs/{run_id}/compare")
def compare_campaigns(
    run_id: str,
    with_: str = Query(alias="with"),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    # Gate both before revealing either record or compatibility details.
    ensure_run_access(user, run_id)
    ensure_run_access(user, with_)
    left, left_campaign = _load_campaign(run_id)
    right, right_campaign = _load_campaign(with_)

    left_settings, right_settings = _settings_hash(left), _settings_hash(right)
    left_sample, right_sample = _sample_hash(left), _sample_hash(right)
    mismatched: list[str] = []
    if not left_settings or not right_settings or left_settings != right_settings:
        mismatched.append("settings_hash")
    if not left_sample or not right_sample or left_sample != right_sample:
        mismatched.append("sample_indices_sha256")
    if mismatched:
        raise HTTPException(status_code=409, detail={
            "code": "incompatible_campaigns",
            "message": "campaign settings or sampled inputs differ",
            "reasons": mismatched,
        })

    left_score, right_score = _score(left), _score(right)
    if left_score is None or right_score is None:
        raise HTTPException(status_code=409, detail={
            "code": "score_unavailable",
            "message": "both campaigns require an available score",
        })

    left_baseline = left.get("baseline_run_id") or left_campaign.get("baseline_run_id")
    right_baseline = right.get("baseline_run_id") or right_campaign.get("baseline_run_id")
    left_model = (left.get("provenance") or {}).get("model_sha256")
    right_model = (right.get("provenance") or {}).get("model_sha256")
    is_pair = ((left_baseline == with_) or (right_baseline == run_id)) and left_model == right_model
    if is_pair:
        verify_score = left_score if left_baseline == with_ else right_score
        delta = verify_score.get("delta")
        if not isinstance(delta, dict):
            raise HTTPException(status_code=409, detail={
                "code": "score_unavailable",
                "message": "the verify campaign has no persisted score delta",
            })
        return {
            "compatible": True, "mode": "verify_delta",
            "delta_mri": delta.get("delta"),
            "delta_dimensions": delta.get("delta_subscores"),
            "delta_acc_clean": delta.get("delta_acc_clean"),
            "delta_families": _comparison_families(delta),
            "changed_variables": ["defense"],
            "unchanged_variables": ["settings_hash", "sample_indices_sha256"],
            "caveats": list((left if left_baseline == with_ else right).get("limitations", [])),
        }
    return {
        "compatible": True, "mode": "side_by_side", "delta": None,
        "scorecards": [_scorecard(left, left_score), _scorecard(right, right_score)],
        "changed_variables": _changed_variables(left, right),
        "unchanged_variables": ["settings_hash", "sample_indices_sha256"],
        "caveats": sorted(set(left.get("limitations", []) + right.get("limitations", []))),
    }


@router.patch("/runs/{run_id}/reviewer-notes")
def update_reviewer_notes(
    run_id: str,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    project_id = ensure_run_access(user, run_id)
    notes = body.get("reviewer_notes")
    if not isinstance(notes, str):
        raise HTTPException(status_code=422, detail={
            "code": "reviewer_notes_invalid", "message": "reviewer_notes must be a string",
            "field": "reviewer_notes",
        })
    if len(notes) > 8192:
        raise HTTPException(status_code=422, detail={
            "code": "reviewer_notes_too_long",
            "message": "reviewer_notes must not exceed 8192 characters",
            "field": "reviewer_notes",
        })

    from redsim.db.session import get_session

    # Establish that this is a campaign before writing its audit event.
    with get_session() as sess:
        if _campaign_row(sess, run_id) is None:
            raise _error("campaign_not_found", "campaign record not found")

    check(user, Action.FINDING_ANNOTATE, project_id)
    encoded = notes.encode("utf-8")
    # Audit before mutation: an unavailable audit backend must never allow an
    # unaccounted-for annotation.
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.safety import authorize

    authorize(
        "finding.annotate", None, allowlist=[],
        actor=f"user:{user.sub}", writer=resolve_writer(load_config()),
        project_id=project_id, run_id=run_id,
        detail={"author": user.sub, "byte_length": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest()},
    )
    with get_session() as sess:
        table = _campaign_table(sess)
        sess.execute(
            table.update().where(table.c.run_id == run_id).values(reviewer_notes=notes)
        )
    return {"run_id": run_id, "reviewer_notes": notes}