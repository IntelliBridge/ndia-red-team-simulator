"""Authoritative ML campaign reads, comparisons, and reviewer annotations.

``GET /v1/runs/{id}/compare?with=`` implements spec 17.2 under D9(i) (F007) and
``GET /v1/runs/compare?ids=a,b,c`` the N-run table of F007 US3 (REVIEW_REPORTS-26).
Both are thin over the pure ``redsim.ml.compare`` module, which owns the rules:

* compatibility is decided variable by variable on the frozen campaign config
  (the fields the settings hash of spec 5.6 covers, except the model identity)
  plus ``sample_indices_sha256``; every mismatched variable is named in the
  ``409 incompatible_campaigns`` envelope so the UI can say "not comparable:
  seed, n_samples"; a differing weight vector is named ``scoring.weights``;
* a run whose score is absent or partial (``mri`` is ``None``) is refused with
  ``409 score_unavailable``, never compared on the subscores that do exist;
* a compatible pair answers ``mode: "side_by_side"`` with two full scorecards
  (spec 15.6): two measurements read next to each other, never one number
  derived from both;
* the N-run table lists rows in request order and has no mean, rank or
  aggregate.

Every run is membership-gated before any record is read, so a non-member
learns nothing about the other campaigns. ``/campaign`` carries
``non_default_weights`` (spec 15.3 badge; REVIEW_REPORTS-30) and, since wave
B4, ``batch_id`` overlaid from the ``ml_campaigns`` row (BULK-02).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS, PARAMS_OUT_OF_RANGE, SCORE_UNAVAILABLE, api_error
from redsim.api.policy import Action, check, ensure_run_access
from redsim.ml import compare as cmp
from redsim.ml.compare import (
    IGNORED_CONFIG_FIELDS as _IGNORED_CONFIG_FIELDS,
)
from redsim.ml.compare import (
    IGNORED_VARIABLES,
    MAX_TABLE_RUNS,
    MIN_TABLE_RUNS,
    MODEL_VARIABLE,
    SAMPLE_VARIABLE,
)

router = APIRouter(tags=["ml-campaigns"])

__all__ = [
    "IGNORED_VARIABLES", "MODEL_VARIABLE", "SAMPLE_VARIABLE", "_IGNORED_CONFIG_FIELDS", "router",
]


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


# Thin aliases kept for the tests and modules that imported the pairwise helpers
# from this module before the pure module existed.
_config = cmp.config
_model_hash = cmp.model_hash
_compatibility = cmp.compatibility
_require_complete_score = cmp.require_complete_score
_changed_variables = cmp.changed_variables
_scorecard = cmp.scorecard_projection


# --------------------------------------------------------------------------- N-run table
# Declared before ``/runs/{run_id}/...`` so ``compare`` is never captured as a run id;
# this router is also mounted before ``runs.router`` in ``redsim.api.app``.


def _parse_ids(ids: str) -> list[str]:
    values = [part.strip() for part in ids.split(",")]
    values = [v for v in values if v]
    if len(values) < MIN_TABLE_RUNS or len(values) > MAX_TABLE_RUNS:
        raise api_error(PARAMS_OUT_OF_RANGE,
                        f"ids must name between {MIN_TABLE_RUNS} and {MAX_TABLE_RUNS} runs", field="ids",
                        reasons=[f"{len(values)} ids given"])
    if len(set(values)) != len(values):
        raise api_error(PARAMS_OUT_OF_RANGE, "ids must not repeat a run", field="ids")
    return values


@router.get("/runs/compare")
def compare_many(
    ids: str = Query(..., description="comma-separated run ids, 2 to 10, in the order the rows should appear"),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """The N-run comparison table (REVIEW_REPORTS-26): request order, no mean, rank or aggregate."""
    run_ids = _parse_ids(ids)
    # Membership on every run before any record is read.
    for run_id in run_ids:
        ensure_run_access(user, run_id)
    runs: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []
    for run_id in run_ids:
        record, campaign = _load_campaign(run_id)
        runs.append((run_id, record, campaign))
    try:
        table = cmp.comparison_table(runs)
    except cmp.Incompatible as exc:
        raise api_error(
            INCOMPATIBLE_CAMPAIGNS,
            "campaigns differ in " + ", ".join(exc.reasons) + "; scores are not compared across settings",
            reasons=list(exc.reasons), pairs=list(exc.pairs),
        ) from exc
    except cmp.ScoreUnavailable as exc:
        raise api_error(
            SCORE_UNAVAILABLE,
            "every compared campaign needs a complete score (MRI computed)",
            reasons=list(exc.reasons),
        ) from exc
    except ValueError as exc:
        raise api_error(PARAMS_OUT_OF_RANGE, str(exc), field="ids") from exc
    return table


# --------------------------------------------------------------------------- single run reads


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
    # Spec 15.3 badge (REVIEW_REPORTS-30): the vector that scored the run is not the default one.
    record["non_default_weights"] = cmp.non_default_weights(record)
    record["weights"] = cmp.record_weights(record)
    # BULK-02 (owner default: no frozen-schema change): the batch a run was admitted in is an overlay from
    # ``ml_campaigns.batch_id``, like ``reviewer_notes`` and ``project_id``; ``None`` for a single-run
    # admission and on a tree whose campaign table predates migration 0011.
    batch_id = campaign.get("batch_id")
    record["batch_id"] = str(batch_id) if isinstance(batch_id, str) and batch_id else None
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

    mismatched, unchanged = cmp.pair_reasons(run_id, left, left_campaign, with_, right, right_campaign)
    if mismatched:
        raise api_error(
            INCOMPATIBLE_CAMPAIGNS,
            "campaigns differ in " + ", ".join(mismatched) + "; scores are not compared across settings",
            reasons=mismatched,
        )

    left_score, left_reasons = cmp.require_complete_score(run_id, left)
    right_score, right_reasons = cmp.require_complete_score(with_, right)
    if left_reasons or right_reasons:
        raise api_error(
            SCORE_UNAVAILABLE,
            "both campaigns need a complete score (MRI computed) to be compared",
            reasons=left_reasons + right_reasons,
        )

    return {
        "compatible": True, "mode": "side_by_side",
        "scorecards": [cmp.scorecard_projection(left, left_score), cmp.scorecard_projection(right, right_score)],
        "changed_variables": cmp.changed_variables(left, right),
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
