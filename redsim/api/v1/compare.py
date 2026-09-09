"""Authoritative ML campaign reads, comparisons, and reviewer annotations.

``GET /v1/runs/{id}/compare?with=`` implements spec 17.2 under D9(i) (F007):

* compatibility is decided variable by variable on the frozen campaign config
  (the fields the settings hash of spec 5.6 covers, except the model identity)
  plus ``sample_indices_sha256``; every mismatched variable is named in the
  ``409 incompatible_campaigns`` envelope so the UI can say "not comparable:
  seed, n_samples";
* a run whose score is absent or partial (``mri`` is ``None``) is refused with
  ``409 score_unavailable``, never compared on the subscores that do exist;
* a verify pairing (same ``model_sha256``, one run's ``baseline_run_id`` is the
  other) answers ``mode: "verify_delta"`` with the measured ΔMRI: the delta the
  worker persisted on the verify run, or, when it did not persist one, the same
  ``redsim.ml.scoring.delta`` computation over the two stored records (its
  ``IncompatibleCampaigns`` is the 409 above);
* the same settings on a different model answers ``mode: "side_by_side"`` with
  two full scorecards and ``delta: null`` (spec 15.6): two scorecards, never one
  delta.

Both runs are membership-gated before either record is read, so a non-member
learns nothing about the other campaign.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS, SCORE_UNAVAILABLE, api_error
from redsim.api.policy import Action, check, ensure_run_access

router = APIRouter(tags=["ml-campaigns"])

# Config fields outside the comparison. ``target_id`` is the Target row, whose model
# identity is compared through ``provenance.model_sha256`` instead (a side-by-side
# comparison is exactly "same settings, different model"); ``defense`` is the variable
# a verify run changes; the rest do not affect a measurement.
_IGNORED_CONFIG_FIELDS: tuple[str, ...] = (
    "target_id", "defense", "llm_narrative", "auto_recommend", "target_snapshot", "attacks",
)
IGNORED_VARIABLES: tuple[str, ...] = (
    "llm_narrative", "auto_recommend", "target_snapshot", "attacks", "reviewer_notes",
)
SAMPLE_VARIABLE = "sample_indices_sha256"
MODEL_VARIABLE = "model_sha256"


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
    ``ml.run_record`` artifact is the record of execution. When several record
    rows exist (a re-render, a retried finalisation) the newest one is served.
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
            ).order_by(Artifact.created_at.desc(), Artifact.id.desc())
        ).scalars().first()
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


def _provenance(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("provenance")
    return value if isinstance(value, dict) else {}


def _config(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("config")
    return value if isinstance(value, dict) else {}


def _sample_hash(record: dict[str, Any]) -> Any:
    return _provenance(record).get(SAMPLE_VARIABLE)


def _model_hash(record: dict[str, Any]) -> Any:
    return _provenance(record).get(MODEL_VARIABLE)


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


def _compared_config(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in _config(record).items() if k not in _IGNORED_CONFIG_FIELDS}


def _compatibility(left: dict[str, Any], right: dict[str, Any]) -> tuple[list[str], list[str]]:
    """``(mismatched, unchanged)`` variable names, config field by config field plus the
    sampled-input digest. The model digest is reported separately: a different model
    with equal settings is the side-by-side case, not an incompatibility."""
    lc, rc = _compared_config(left), _compared_config(right)
    mismatched = [k for k in sorted(set(lc) | set(rc)) if lc.get(k) != rc.get(k)]
    unchanged = [k for k in sorted(lc) if k in rc and lc[k] == rc[k]]
    left_sample, right_sample = _sample_hash(left), _sample_hash(right)
    if not left_sample or not right_sample:
        mismatched.append(f"{SAMPLE_VARIABLE} (not recorded on both runs)")
    elif left_sample != right_sample:
        mismatched.append(SAMPLE_VARIABLE)
    else:
        unchanged.append(SAMPLE_VARIABLE)
    left_settings, right_settings = _settings_hash(left), _settings_hash(right)
    same_model = _model_hash(left) is not None and _model_hash(left) == _model_hash(right)
    if same_model and not mismatched and left_settings and right_settings and left_settings != right_settings:
        # Same model, same compared config, different hash: the records disagree with
        # themselves, which is a refusal, not something to paper over.
        mismatched.append("settings_hash")
    if same_model:
        unchanged.append(MODEL_VARIABLE)
        if left_settings and left_settings == right_settings:
            unchanged.append("settings_hash")
    return mismatched, unchanged


def _require_complete_score(run_id: str, record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The score record of ``record`` when it is complete, else the reasons it is not."""
    score = _score(record)
    if score is None:
        status = record.get("score_status")
        reason = status.get("reason") if isinstance(status, dict) else None
        return {}, [f"{run_id}: no score" + (f" ({reason})" if reason else "")]
    if score.get("mri") is None:
        missing = score.get("missing") or []
        detail = "; ".join(str(m) for m in missing) if isinstance(missing, list) and missing else "partial score"
        return score, [f"{run_id}: MRI not computed ({detail})"]
    return score, []


def _changed_variables(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    if _model_hash(left) != _model_hash(right):
        changed.append("model")
    if _config(left).get("target_id") != _config(right).get("target_id"):
        changed.append("target")
    if _config(left).get("defense") != _config(right).get("defense"):
        changed.append("defense")
    if not changed and (
        left.get("parent_run_id") == right.get("run_id")
        or right.get("parent_run_id") == left.get("run_id")
    ):
        changed.append("rerun")
    return changed


def _scorecard(record: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
    """A full MRIRecord with the tables it must never be shown without (spec 15.7, 15.8)."""
    target = record.get("target")
    return {
        **score,
        "run_id": record.get("run_id"),
        "model_sha256": _model_hash(record),
        "target": target if isinstance(target, dict) else None,
        "measurements": record.get("measurements", []),
        "curve": record.get("curve", []),
        "limitations": record.get("limitations", []),
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


def _measured_delta(
    *, verify: dict[str, Any], verify_score: dict[str, Any], baseline: dict[str, Any],
    baseline_score: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """The verify run's ΔMRI as a JSON dict and where it came from.

    Prefers the delta the worker persisted on the verify run's score record. Without
    one, the same ``redsim.ml.scoring.delta`` runs over the two stored records: it is a
    deterministic function of measured rows, so the result is still a measured delta,
    and its typed refusals map onto the 17.3 codes.
    """
    persisted = verify_score.get("delta")
    if isinstance(persisted, dict):
        return persisted, "persisted"
    from redsim.ml.schema import Measurement, MRIRecord
    from redsim.ml.scoring import IncompatibleCampaigns, delta

    try:
        before = MRIRecord.model_validate(baseline_score)
        after = MRIRecord.model_validate(verify_score)
        measured = delta(
            before, after, baseline_run_id=str(baseline.get("run_id")),
            measurements_before=[Measurement.model_validate(m) for m in baseline.get("measurements", [])],
            measurements_after=[Measurement.model_validate(m) for m in verify.get("measurements", [])],
            modality_before=_config(baseline).get("modality"),
            modality_after=_config(verify).get("modality"),
        )
    except IncompatibleCampaigns as exc:
        raise api_error(INCOMPATIBLE_CAMPAIGNS, str(exc), reasons=list(exc.reasons)) from exc
    except ValueError as exc:
        raise api_error(SCORE_UNAVAILABLE, f"the verify delta could not be measured: {exc}",
                        reasons=[str(exc)]) from exc
    return measured.model_dump(mode="json"), "computed"


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

    left_baseline = left.get("baseline_run_id") or left_campaign.get("baseline_run_id")
    right_baseline = right.get("baseline_run_id") or right_campaign.get("baseline_run_id")
    is_pairing = left_baseline == with_ or right_baseline == run_id
    same_model = _model_hash(left) is not None and _model_hash(left) == _model_hash(right)

    mismatched, unchanged = _compatibility(left, right)
    if is_pairing and not same_model:
        mismatched.append(f"{MODEL_VARIABLE} (a verify run and its baseline must share the model)")
    if mismatched:
        raise api_error(
            INCOMPATIBLE_CAMPAIGNS,
            "campaigns differ in " + ", ".join(mismatched) + "; scores are not compared across settings",
            reasons=mismatched,
        )

    left_score, left_reasons = _require_complete_score(run_id, left)
    right_score, right_reasons = _require_complete_score(with_, right)
    if left_reasons or right_reasons:
        raise api_error(
            SCORE_UNAVAILABLE,
            "both campaigns need a complete score (MRI computed) to be compared",
            reasons=left_reasons + right_reasons,
        )

    if is_pairing:
        verify, baseline = (left, right) if left_baseline == with_ else (right, left)
        verify_score, baseline_score = (left_score, right_score) if verify is left else (right_score, left_score)
        delta, source = _measured_delta(
            verify=verify, verify_score=verify_score, baseline=baseline, baseline_score=baseline_score,
        )
        defense = _config(verify).get("defense")
        return {
            "compatible": True, "mode": "verify_delta",
            "verify_run_id": verify.get("run_id"), "baseline_run_id": baseline.get("run_id"),
            "defense": defense,
            "delta_source": source,
            "mri_before": delta.get("mri_before"), "mri_after": delta.get("mri_after"),
            "delta_mri": delta.get("delta"),
            "delta_dimensions": delta.get("delta_subscores"),
            "delta_acc_clean": delta.get("delta_acc_clean"),
            "delta_families": _comparison_families(delta),
            "changed_variables": ["defense"],
            "unchanged_variables": unchanged,
            "ignored_variables": list(IGNORED_VARIABLES),
            "caveats": list(verify.get("limitations", [])),
        }
    return {
        "compatible": True, "mode": "side_by_side", "delta": None,
        "scorecards": [_scorecard(left, left_score), _scorecard(right, right_score)],
        "changed_variables": _changed_variables(left, right),
        "unchanged_variables": unchanged,
        "ignored_variables": list(IGNORED_VARIABLES),
        "caveats": sorted(set(left.get("limitations", []) + right.get("limitations", []))),
    }


@router.patch("/runs/{run_id}/reviewer-notes")
def update_reviewer_notes(
    run_id: str,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Reviewer notes on a campaign (spec 17.2, 5.11 ``finding.annotate``).

    Gate order: membership (404 for an unknown run), then the ``FINDING_ANNOTATE``
    role check, then body validation, then the campaign lookup, then the audit row
    (digest and length only, never the text), then the write.
    """
    project_id = ensure_run_access(user, run_id)
    check(user, Action.FINDING_ANNOTATE, project_id)
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

    encoded = notes.encode("utf-8")
    # Audit before mutation: an unavailable audit backend must never allow an
    # unaccounted-for annotation. The row carries the digest, never the text.
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.safety import authorize

    authorize(
        "finding.annotate", None, allowlist=[],
        actor=f"user:{user.sub}", writer=resolve_writer(load_config()),
        project_id=project_id, run_id=run_id,
        detail={"run_id": run_id, "author": user.sub, "length": len(notes),
                "byte_length": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()},
    )
    with get_session() as sess:
        table = _campaign_table(sess)
        sess.execute(
            table.update().where(table.c.run_id == run_id).values(reviewer_notes=notes)
        )
    return {"run_id": run_id, "reviewer_notes": notes}
