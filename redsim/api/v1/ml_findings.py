"""ML finding action admissions and the Phase B review workflow routes.

Phase A routes (explain, harden and the ``PATCH /status`` dismissal) are kept;
Phase B (plan 12 wave B2, review-workflow track) adds:

* ``PATCH /v1/findings/{id}/status`` accepts every review decision through
  ``status`` (``false_positive`` = dismiss, ``open`` = reopen) or an explicit
  ``decision``, always with ``expected_status`` (compare-and-set) and an
  optional ``expected_review_state``.
* ``POST /v1/findings/{id}/review/{transition}`` is the explicit form of the
  same table (``submit``, ``confirm``, ``request_changes``, ``dismiss``,
  ``reopen``, ``resolve``); ``POST /v1/findings/{id}/review`` takes the
  decision in the body (spec 17.4 shape).
* ``GET /v1/findings`` and ``GET /v1/findings/{id}`` carry additive
  ``review_state`` and ``review`` keys and the list filters on
  ``status``, ``review_state`` and ``source_tool`` (REVIEW_REPORTS-07). The
  routes are supersets of the core findings routes and reuse their serializer.
* ``GET /v1/findings/{id}/retests`` lists the linked retests with their
  compatibility against the baseline (REVIEW_REPORTS-09).
* ``POST /v1/findings`` creates an analyst-authored draft and
  ``PATCH /v1/findings/{id}/draft`` appends a revision (REVIEW_REPORTS-05,
  gate ``finding.author``).

Gates: ``FINDING_REVIEW`` (approver) for every reviewer decision,
``FINDING_AUTHOR`` (remediator) for ``submit``, drafts and revisions. The
independence rule (spec 7.7) lives in the service and is an identity check the
``admin`` role never bypasses. Every decision writes its audit row before the
finding changes; refusals write ``success=False`` rows.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import ApiError
from redsim.api.policy import Action, check, ensure_project_access, has_project_access
from redsim.api.v1.findings import _finding_to_dict
from redsim.audit.chain import resolve_writer
from redsim.config import load_config
from redsim.safety import AuthorizationError
from redsim.services.finding_review import (
    DECISIONS,
    REVIEW_STATES,
    TRANSITIONS,
    create_draft_finding,
    decide,
    list_retests,
    review_state_of,
    review_summary,
    revise_draft,
)
from redsim.services.ml_findings import (
    MLFindingAdmissionError,
    create_finding_action_job,
)

router = APIRouter(prefix="/findings", tags=["ml-findings"])

Decision = Literal["submit", "confirm", "request_changes", "dismiss", "reopen", "resolve"]
_STATUS_DECISION: dict[str, str] = {"false_positive": "dismiss", "open": "reopen"}


class ExplainBody(BaseModel):
    explain_k: int | None = Field(default=None, ge=0, le=32)
    seed: int | None = None


class HardenBody(BaseModel):
    llm_narrative: bool = False


class ReviewBody(BaseModel):
    """``PATCH /status``: the Phase A dismissal shape plus the Phase B decisions.

    ``status="false_positive"`` is ``dismiss`` and ``status="open"`` is ``reopen``
    (the only two decisions that move ``Finding.status``); any other decision is
    named through ``decision``. Both may be given when they agree.
    """

    status: Literal["false_positive", "open"] | None = None
    decision: Decision | None = None
    expected_status: str
    expected_review_state: str | None = None
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def _one_decision(self) -> ReviewBody:
        implied = _STATUS_DECISION.get(self.status or "")
        if self.decision is None and implied is None:
            raise ValueError("one of status (false_positive | open) or decision is required")
        if self.decision is not None and implied is not None and implied != self.decision:
            raise ValueError(f"status {self.status!r} implies decision {implied!r}, not {self.decision!r}")
        if self.expected_review_state is not None and self.expected_review_state not in REVIEW_STATES:
            raise ValueError(f"expected_review_state must be one of {sorted(REVIEW_STATES)}")
        return self

    @property
    def resolved_decision(self) -> str:
        return self.decision or _STATUS_DECISION[self.status or ""]


class TransitionBody(BaseModel):
    """``POST /review/{transition}``: reason plus the compare-and-set expectations."""

    reason: str = Field(min_length=1)
    expected_status: str
    expected_review_state: str | None = None

    @model_validator(mode="after")
    def _known_state(self) -> TransitionBody:
        if self.expected_review_state is not None and self.expected_review_state not in REVIEW_STATES:
            raise ValueError(f"expected_review_state must be one of {sorted(REVIEW_STATES)}")
        return self


class DecisionBody(TransitionBody):
    """``POST /review``: spec 17.4 shape with the decision in the body."""

    decision: Decision


class DraftBody(BaseModel):
    """``POST /findings``: an analyst-authored draft against a terminal campaign run."""

    run_id: str = Field(min_length=1)
    attack_id: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=512)
    severity: Literal["critical", "high", "medium", "low"]
    observation: str = Field(min_length=1, max_length=8192)
    interpretation: str | None = Field(default=None, max_length=8192)
    candidate: str | None = Field(default=None, max_length=8192)
    evidence_ids: list[str] = Field(min_length=1, max_length=256)


class RevisionBody(BaseModel):
    """``PATCH /findings/{id}/draft``: fields left out are carried over."""

    observation: str | None = Field(default=None, min_length=1, max_length=8192)
    interpretation: str | None = Field(default=None, max_length=8192)
    candidate: str | None = Field(default=None, max_length=8192)
    evidence_ids: list[str] | None = Field(default=None, min_length=1, max_length=256)


def _finding_project(finding_id: str) -> str:
    from redsim.db.models import Finding
    from redsim.db.session import get_session
    with get_session() as session:
        row = session.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return row.project_id


def _error(exc: MLFindingAdmissionError) -> HTTPException:
    detail: dict[str, Any] = {"code": exc.code, "message": str(exc)}
    if exc.phase:
        detail["phase"] = exc.phase
    return HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED
                         if exc.code == "not_implemented" else status.HTTP_409_CONFLICT,
                         detail=detail)


def _with_review(row: Any, **flags: bool) -> dict[str, Any]:
    """The core wire shape plus the additive ``review_state`` and ``review`` keys."""
    out = _finding_to_dict(row, **flags)
    out["review_state"] = review_state_of(row.schema_blob)
    out["review"] = review_summary(row.schema_blob)
    return out


# ---------------------------------------------------------------------------
# Read side (supersets of the core findings routes; REVIEW_REPORTS-07)
# ---------------------------------------------------------------------------


@router.get("")
def list_findings(
    run: str | None = None,
    project: str | None = None,
    severity: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    review_state: str | None = None,
    source_tool: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """The findings list with the Phase B filters and the additive review keys.

    ``review_state`` is read from ``schema_blob.<ml|llm>.review.state`` in Python
    (findings without a review block never match a state filter, and
    ``unreviewed`` is the default state of a projected finding, never rendered
    as anything else).
    """
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    if review_state is not None and review_state not in REVIEW_STATES:
        raise HTTPException(status_code=422, detail=f"review_state must be one of {sorted(REVIEW_STATES)}")
    with get_session() as sess:
        stmt = select(Finding)
        if run:
            stmt = stmt.where(Finding.run_id == run)
        if project:
            stmt = stmt.where(Finding.project_id == project)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status_:
            stmt = stmt.where(Finding.status == status_)
        if source_tool:
            stmt = stmt.where(Finding.source_tool == source_tool)
        if review_state is None:
            stmt = stmt.limit(limit)
        rows = sess.execute(stmt).scalars().all()
        out: list[dict[str, Any]] = []
        for row in rows:
            if not has_project_access(user, row.project_id):
                continue
            item = _with_review(row, source_tool=True, dedup_key=True)
            if review_state is not None and item["review_state"] != review_state:
                continue
            out.append(item)
            if len(out) >= limit:
                break
        return {"findings": out, "count": len(out)}


@router.get("/{finding_id}")
def get_finding(finding_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"finding {finding_id} not found")
        ensure_project_access(user, row.project_id)
        return _with_review(row, validated_at=True, dedup_key=True)


@router.get("/{finding_id}/retests")
def retests(finding_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Linked retests with compatibility (equal ``settings_hash``) and a delta only when compatible."""
    from redsim.db.models import Finding
    from redsim.db.session import get_session

    with get_session() as sess:
        row = sess.get(Finding, finding_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        ensure_project_access(user, row.project_id)
        return list_retests(sess, row)


# ---------------------------------------------------------------------------
# Follow-up actions (Phase A)
# ---------------------------------------------------------------------------


@router.post("/{finding_id}/explain", status_code=status.HTTP_202_ACCEPTED)
def explain(finding_id: str, body: ExplainBody, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    project_id = _finding_project(finding_id)
    check(user, Action.EXPLAIN_RUN, project_id)
    config = load_config()
    try:
        return create_finding_action_job(finding_id=finding_id, action="explain",
                                         body=body.model_dump(exclude_none=True),
                                         actor=f"user:{user.sub}", config=config,
                                         audit_writer=resolve_writer(config)).to_response()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except (MLFindingAdmissionError, AuthorizationError) as exc:
        raise _error(exc) if isinstance(exc, MLFindingAdmissionError) else HTTPException(403, detail=str(exc))


@router.post("/{finding_id}/harden", status_code=status.HTTP_202_ACCEPTED)
def harden(finding_id: str, body: HardenBody, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    project_id = _finding_project(finding_id)
    check(user, Action.HARDEN_RECOMMEND, project_id)
    config = load_config()
    try:
        return create_finding_action_job(finding_id=finding_id, action="harden",
                                         body=body.model_dump(), actor=f"user:{user.sub}",
                                         config=config, audit_writer=resolve_writer(config)).to_response()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except (MLFindingAdmissionError, AuthorizationError) as exc:
        raise _error(exc) if isinstance(exc, MLFindingAdmissionError) else HTTPException(403, detail=str(exc))


# ---------------------------------------------------------------------------
# Review decisions
# ---------------------------------------------------------------------------


def _gate_for(decision: str) -> Action:
    """``submit`` is the author's act (``finding.author``); every verdict is ``finding.review``."""
    return Action.FINDING_AUTHOR if TRANSITIONS[decision].action == "finding.author" else Action.FINDING_REVIEW


def _decide(finding_id: str, *, decision: str, reason: str, expected_status: str,
            expected_review_state: str | None, user: CurrentUser) -> dict[str, Any]:
    project_id = _finding_project(finding_id)
    check(user, _gate_for(decision), project_id)
    config = load_config()
    try:
        return decide(finding_id=finding_id, decision=decision, reason=reason, expected_status=expected_status,
                      expected_review_state=expected_review_state, actor=f"user:{user.sub}", config=config,
                      audit_writer=resolve_writer(config), reviewer_is_system=bool(user.is_system))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.patch("/{finding_id}/status")
def dismiss(finding_id: str, body: ReviewBody,
            user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Review decisions through the Phase A status route (spec 6.4, 7.7, 17.1).

    ``status="false_positive"`` dismisses (Phase A rules unchanged: ``open | failed``
    only, stale ``expected_status`` and a disallowed source are ``409 run_terminal``),
    ``status="open"`` reopens a dismissed finding, and ``decision`` names any other
    transition. The gate is ``FINDING_REVIEW`` (``FINDING_AUTHOR`` for ``submit``);
    the campaign creator, the draft author, the retest requester and system principals
    are refused with 403; ``resolve`` answers ``409 resolution_blocked`` with the
    unmet conditions. The audit row precedes the write; refusals write
    ``success=False`` rows.
    """
    return _decide(finding_id, decision=body.resolved_decision, reason=body.reason,
                   expected_status=body.expected_status, expected_review_state=body.expected_review_state,
                   user=user)


@router.post("/{finding_id}/review/{transition}")
def review_transition(finding_id: str, transition: str, body: TransitionBody,
                      user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """The explicit form: one route per decision of the transition table."""
    if transition not in DECISIONS:
        raise HTTPException(status_code=404, detail=f"unknown review transition {transition!r}; "
                                                    f"one of {list(DECISIONS)}")
    return _decide(finding_id, decision=transition, reason=body.reason, expected_status=body.expected_status,
                   expected_review_state=body.expected_review_state, user=user)


@router.post("/{finding_id}/review")
def review_decision(finding_id: str, body: DecisionBody,
                    user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Spec 17.4 shape: the decision in the body."""
    return _decide(finding_id, decision=body.decision, reason=body.reason, expected_status=body.expected_status,
                   expected_review_state=body.expected_review_state, user=user)


# ---------------------------------------------------------------------------
# Analyst-authored drafts (REVIEW_REPORTS-05)
# ---------------------------------------------------------------------------


def _run_project(run_id: str) -> str:
    from redsim.db.models import Run
    from redsim.db.session import get_session
    with get_session() as session:
        row = session.get(Run, run_id)
        if row is None:
            raise HTTPException(status_code=404, detail="run not found")
        return row.project_id


@router.post("", status_code=status.HTTP_201_CREATED)
def create_draft(body: DraftBody, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """An analyst draft against a terminal campaign run, citing ids of its immutable record.

    Gate ``FINDING_AUTHOR`` on the run's project. Unknown evidence ids or an attack
    outside the run's set are ``422 params_out_of_range``; a run without a record is
    404; a non-terminal run is ``409 campaign_not_terminal``. The ``finding.author``
    audit row (``op=create``) is written before the finding row.
    """
    project_id = _run_project(body.run_id)
    check(user, Action.FINDING_AUTHOR, project_id)
    config = load_config()
    try:
        return create_draft_finding(
            run_id=body.run_id, attack_id=body.attack_id, title=body.title, severity=body.severity,
            observation=body.observation, interpretation=body.interpretation, candidate=body.candidate,
            evidence_ids=body.evidence_ids, actor=f"user:{user.sub}", config=config,
            audit_writer=resolve_writer(config), reviewer_is_system=bool(user.is_system),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.patch("/{finding_id}/draft")
def revise(finding_id: str, body: RevisionBody, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Append a revision to a draft (author only, ``draft`` state only); audit ``finding.author`` first."""
    project_id = _finding_project(finding_id)
    check(user, Action.FINDING_AUTHOR, project_id)
    config = load_config()
    try:
        return revise_draft(
            finding_id=finding_id, observation=body.observation, interpretation=body.interpretation,
            candidate=body.candidate, evidence_ids=body.evidence_ids, actor=f"user:{user.sub}", config=config,
            audit_writer=resolve_writer(config), reviewer_is_system=bool(user.is_system),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
