"""Finding review workflow: one transition table over the widened ``ReviewState``.

Phase B (plan 12 wave B2, review-workflow track; REVIEW_REPORTS-02..07, -09,
-11, -12 and -05). This module generalises the Phase A dismissal in
:func:`redsim.services.ml_findings.review_finding` into a table of decisions
over ``(Finding.status, schema_blob.<block>.review.state)`` without inventing a
``Finding.status`` value:

======================  ==============================  ============================
decision                from                            to
======================  ==============================  ============================
``submit``              review ``draft``                review ``in_review``
``confirm``             review ``unreviewed|in_review`` review ``confirmed`` (status kept)
``request_changes``     review ``in_review``            review ``draft`` + new revision
``dismiss``             status ``open|failed``          status ``false_positive``, review ``dismissed``
``reopen``              status ``false_positive``       status ``open``, review ``unreviewed``
``resolve``             review ``confirmed``            review ``resolved`` (status stays ``fixed``)
======================  ==============================  ============================

``resolve`` is additionally gated on the measured record: ``validation_state ==
poc_passed`` and ``Finding.status == fixed`` (both written by the verify worker,
never here), a linked retest whose ``settings_hash`` equals the baseline
campaign's, and a reviewer who is neither the campaign creator, the draft author,
the retest requester nor a system principal. Anything unmet is a ``409
resolution_blocked`` naming every unmet condition.

Every decision is audit-first (spec 6.7 invariant 4): the ``finding.review``
(or ``finding.author`` for analyst operations) row carries ``decision``,
``from_status``/``to_status``, ``from_review_state``/``to_review_state``,
``reason``, ``reviewer``, ``author``, ``campaign_creator``, ``revision`` and
``verify_run_id``; refusals after lookup append a ``success=False`` row with
``refusal`` and ``message``. The transition history is appended to
``schema_blob.<block>.review.history`` and analyst revisions to
``schema_blob.<block>.review.revisions``; the rows stay readable through the
frozen ``FindingReview`` schema. Retest links are read from
``MLFindingDetail.retests`` (the worker appends them) with ``verify`` as the
Phase A fallback.

The review block is ``schema_blob["ml"]`` for campaign findings and
``schema_blob["llm"]`` for LLM probe findings (both carry a ``FindingReview`` at
``review``); a finding with neither accepts only the status-level ``dismiss``
and ``reopen`` decisions, exactly as the Phase A route did.

Error codes come from :mod:`redsim.api.errors`. ``review_state_conflict`` and
``reviewer_not_independent`` are named in the wave brief but not yet in the
table, so they are resolved with a ``getattr`` fallback to ``run_terminal`` and
``forbidden``; ``dismiss`` keeps ``run_terminal`` for its stale and
disallowed-source refusals so the Phase A contract is unchanged.

Nothing here imports FastAPI, torch, ART or any ML library.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal, cast, get_args
from uuid import uuid4

from redsim.ml.schema import (
    CampaignConfig,
    FindingReview,
    FindingRevision,
    FindingVerify,
    Measurement,
    MLFindingDetail,
    Observation,
    ReviewEvent,
    ReviewState,
)
from redsim.safety import authorize
from redsim.services.ml_findings import DISMISSABLE_FROM, DISMISSED_STATUS, read_finding_detail

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)

Decision = Literal["submit", "confirm", "request_changes", "dismiss", "reopen", "resolve"]
DECISIONS: tuple[str, ...] = get_args(Decision)
REVIEW_STATES: frozenset[str] = frozenset(get_args(ReviewState))

#: Audit action names (spec 5.11; the Phase B ``finding.author`` gate mirrors it).
REVIEW_ACTION = "finding.review"
AUTHOR_ACTION = "finding.author"

#: The ``finding_type`` an analyst draft carries when the core schema knows it;
#: otherwise ``adversarial_ml`` with ``source_tool="manual"`` (REVIEW_REPORTS-05).
MANUAL_FINDING_TYPE = "adversarial_ml_manual"
MANUAL_SOURCE_TOOL = "manual"
MANUAL_CONFIDENCE = "low"
_MANUAL_NOTE = ("analyst-authored draft: severity declared by the author, not derived from "
                "measurements; evidence cited by id from the immutable run record")

_TERMINAL_RUN = frozenset({"succeeded", "failed", "cancelled"})
_REVIEW_BLOCKS: tuple[str, ...] = ("ml", "llm")
_CONFIRMABLE_STATUSES: frozenset[str] = frozenset({"open", "failed", "fixed"})


@dataclass(frozen=True)
class Transition:
    """One row of the review transition table."""

    decision: str
    from_review_states: frozenset[str] | None   # ``None``: any (status decides), incl. no review block
    from_statuses: frozenset[str] | None        # ``None``: any
    to_review_state: str
    to_status: str | None                       # ``None``: ``Finding.status`` is unchanged
    action: str                                 # audit action and RBAC gate name
    author_only: bool = False                   # the actor must be the latest revision's author


TRANSITIONS: dict[str, Transition] = {
    "submit": Transition("submit", frozenset({"draft"}), None, "in_review", None,
                         AUTHOR_ACTION, author_only=True),
    "confirm": Transition("confirm", frozenset({"unreviewed", "in_review"}), _CONFIRMABLE_STATUSES,
                          "confirmed", None, REVIEW_ACTION),
    "request_changes": Transition("request_changes", frozenset({"in_review"}), None, "draft", None,
                                  REVIEW_ACTION),
    # Spec 6.4 Phase A rule, unchanged: only ``open | failed`` may be dismissed.
    "dismiss": Transition("dismiss", None, DISMISSABLE_FROM, "dismissed", DISMISSED_STATUS, REVIEW_ACTION),
    "reopen": Transition("reopen", frozenset({"dismissed"}), frozenset({"false_positive"}), "unreviewed",
                         "open", REVIEW_ACTION),
    "resolve": Transition("resolve", frozenset({"confirmed"}), frozenset({"fixed"}), "resolved", None,
                          REVIEW_ACTION),
}

#: Decisions a finding without a review block (no ``ml`` / ``llm`` detail) still accepts.
STATUS_ONLY_DECISIONS: frozenset[str] = frozenset({"dismiss", "reopen"})


# ---------------------------------------------------------------------------
# Error codes (lazy: ``redsim.api`` imports every router at package import)
# ---------------------------------------------------------------------------


def _codes() -> SimpleNamespace:
    from redsim.api import errors

    return SimpleNamespace(
        ApiError=errors.ApiError,
        TRANSITION_INVALID=errors.REVIEW_TRANSITION_INVALID,
        STATE_CONFLICT=getattr(errors, "REVIEW_STATE_CONFLICT", errors.RUN_TERMINAL),
        NOT_INDEPENDENT=getattr(errors, "REVIEWER_NOT_INDEPENDENT", errors.FORBIDDEN),
        RESOLUTION_BLOCKED=errors.RESOLUTION_BLOCKED,
        RUN_TERMINAL=errors.RUN_TERMINAL,
        FORBIDDEN=errors.FORBIDDEN,
        NOT_FOUND=errors.NOT_FOUND,
        PARAMS_OUT_OF_RANGE=errors.PARAMS_OUT_OF_RANGE,
        CAMPAIGN_NOT_TERMINAL=errors.CAMPAIGN_NOT_TERMINAL,
        SCORE_UNAVAILABLE=errors.SCORE_UNAVAILABLE,
    )


# ---------------------------------------------------------------------------
# Reading the review block (pure functions over ``schema_blob``)
# ---------------------------------------------------------------------------


@dataclass
class ReviewCarrier:
    """Where a finding keeps its ``FindingReview`` and how to write it back."""

    key: str | None                       # ``"ml"``, ``"llm"`` or ``None`` (no review block)
    review: FindingReview
    detail: MLFindingDetail | None        # validated ``ml`` block when ``key == "ml"``

    @property
    def state(self) -> str | None:
        return None if self.key is None else str(self.review.state)

    def latest_revision(self) -> FindingRevision | None:
        return self.review.revisions[-1] if self.review.revisions else None

    def write(self, blob: dict[str, Any]) -> None:
        """Write the review back into ``blob`` through the frozen schema."""
        if self.key is None:
            return
        if self.key == "ml" and self.detail is not None:
            self.detail.review = self.review
            blob["ml"] = MLFindingDetail.model_validate(self.detail.model_dump(mode="json")).model_dump(mode="json")
            return
        block = dict(blob.get(self.key) or {})
        block["review"] = FindingReview.model_validate(self.review.model_dump(mode="json")).model_dump(mode="json")
        blob[self.key] = block


def review_carrier(schema_blob: dict[str, Any] | None) -> ReviewCarrier:
    """The review block of a stored finding: ``ml`` first, then ``llm``, else none."""
    blob = schema_blob or {}
    ml_block = blob.get("ml")
    if isinstance(ml_block, dict) and ml_block:
        detail = read_finding_detail(blob)
        if detail is not None:
            return ReviewCarrier("ml", detail.review, detail)
    llm_block = blob.get("llm")
    if isinstance(llm_block, dict) and llm_block:
        raw = llm_block.get("review")
        review = FindingReview.model_validate(raw) if isinstance(raw, dict) else FindingReview()
        return ReviewCarrier("llm", review, None)
    return ReviewCarrier(None, FindingReview(), None)


def review_state_of(schema_blob: dict[str, Any] | None) -> str | None:
    """``schema_blob.<block>.review.state`` or ``None`` when the finding has no review block.

    Cheap and tolerant: a malformed block reads as ``None`` rather than raising in a
    list route.
    """
    try:
        return review_carrier(schema_blob).state
    except Exception:  # noqa: BLE001 - a list row must never 500 on one bad blob
        return None


def review_summary(schema_blob: dict[str, Any] | None) -> dict[str, Any] | None:
    """The additive ``review`` key of a findings row: state, reviewer, at, counts."""
    try:
        carrier = review_carrier(schema_blob)
    except Exception:  # noqa: BLE001
        return None
    if carrier.key is None:
        return None
    review = carrier.review
    latest = carrier.latest_revision()
    return {
        "state": str(review.state), "reviewer": review.reviewer,
        "at": review.at.isoformat() if review.at is not None else None,
        "n_history": len(review.history), "n_revisions": len(review.revisions),
        "revision": latest.revision if latest is not None else None,
    }


def latest_retest(detail: MLFindingDetail | None) -> FindingVerify | None:
    """The newest retest link: ``retests[-1]`` (Phase B) or ``verify`` (Phase A)."""
    if detail is None:
        return None
    if detail.retests:
        return detail.retests[-1]
    return detail.verify


def revision_digest(*, observation: str | None, interpretation: str | None, candidate: str | None,
                    evidence_ids: Sequence[str]) -> str:
    """sha256 over the three texts and the cited ids, frozen on a revision at submission."""
    payload = json.dumps({"observation": observation, "interpretation": interpretation, "candidate": candidate,
                          "evidence_ids": list(evidence_ids)}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Independence and resolution conditions
# ---------------------------------------------------------------------------


def independence_violations(*, actor: str, reviewer_is_system: bool, campaign_creator: str | None,
                            revision_author: str | None, verify_requesters: Sequence[str] = ()) -> list[str]:
    """Spec 7.7, Phase B bullet (REVIEW_REPORTS-12): identity comparison, never role rank.

    ``system_principal``: the caller is a worker or service account. ``campaign_creator``:
    ``runs.created_by`` of the finding's run. ``revision_author``: the latest analyst
    revision's author. ``verify_requester``: the actor who admitted the retest a
    ``resolve`` rests on.
    """
    violations: list[str] = []
    if reviewer_is_system:
        violations.append("system_principal")
    if campaign_creator is not None and campaign_creator == actor:
        violations.append("campaign_creator")
    if revision_author is not None and revision_author == actor:
        violations.append("revision_author")
    if actor in set(verify_requesters):
        violations.append("verify_requester")
    return violations


def _campaign_table(session: Session) -> Any:
    from sqlalchemy import MetaData, Table

    return Table("ml_campaigns", MetaData(), autoload_with=session.get_bind())


def _campaign_row(session: Session, table: Any, run_id: str | None) -> dict[str, Any] | None:
    if not run_id:
        return None
    row = session.execute(table.select().where(table.c.run_id == run_id)).mappings().one_or_none()
    return None if row is None else dict(row)


def verify_requesters(session: Session, verify_run_id: str | None) -> list[str]:
    """Actors who admitted the retest: the verify run's creator and its ``verify.replay`` job creators."""
    from sqlalchemy import select

    from redsim.db.models import Job, Run

    if not verify_run_id:
        return []
    out: list[str] = []
    run = session.get(Run, verify_run_id)
    if run is not None and run.created_by:
        out.append(str(run.created_by))
    jobs = session.execute(select(Job).where(Job.run_id == verify_run_id, Job.type == "verify.replay")).scalars()
    for job in jobs:
        if job.created_by and str(job.created_by) not in out:
            out.append(str(job.created_by))
    return out


@dataclass(frozen=True)
class ResolutionCheck:
    """The measured conditions a ``resolve`` rests on (spec 6.4 resolved row, 15.6)."""

    unmet: list[str]
    verify_run_id: str | None
    baseline_settings_hash: str | None
    verify_settings_hash: str | None
    verify_requesters: list[str]

    @property
    def ok(self) -> bool:
        return not self.unmet


def resolution_conditions(session: Session, *, finding: Any, carrier: ReviewCarrier) -> ResolutionCheck:
    """Every condition ``resolve`` needs, evaluated independently of the transition table.

    ``validation_state_not_poc_passed`` and ``status_not_fixed`` read the worker-written
    columns; ``review_state_not_confirmed`` the review block; ``no_retest_linked``,
    ``retest_outcome_not_verified`` and ``settings_hash_mismatch`` the latest retest link
    against the two ``ml_campaigns`` rows. Nothing labels ``fixed`` as resolved without
    all of them.
    """
    unmet: list[str] = []
    if finding.validation_state != "poc_passed":
        unmet.append("validation_state_not_poc_passed")
    if finding.status != "fixed":
        unmet.append("status_not_fixed")
    if carrier.state != "confirmed":
        unmet.append("review_state_not_confirmed")
    retest = latest_retest(carrier.detail)
    if retest is None:
        unmet.append("no_retest_linked")
        return ResolutionCheck(unmet, None, None, None, [])
    if retest.outcome != "verified":
        unmet.append("retest_outcome_not_verified")
    table = _campaign_table(session)
    baseline = _campaign_row(session, table, finding.run_id)
    verify_row = _campaign_row(session, table, retest.run_id)
    baseline_hash = baseline.get("settings_hash") if baseline else None
    verify_hash = retest.settings_hash or (verify_row.get("settings_hash") if verify_row else None)
    if not baseline_hash or not verify_hash or str(baseline_hash) != str(verify_hash):
        unmet.append("settings_hash_mismatch")
    if verify_row is not None and verify_row.get("baseline_run_id") not in (None, finding.run_id):
        unmet.append("retest_baseline_mismatch")
    requesters = verify_requesters(session, retest.run_id)
    return ResolutionCheck(unmet, retest.run_id, str(baseline_hash) if baseline_hash else None,
                           str(verify_hash) if verify_hash else None, requesters)


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


def _refuse(audit_writer: AuditWriter, *, action: str, actor: str, finding: Any, detail: dict[str, Any],
            refusal: str, message: str) -> None:
    """A refused decision is still on the chain, as a ``success=False`` row."""
    audit_writer.append(
        action=action, actor=actor, target=None, allowlist_check="n/a", override=False, success=False,
        detail={**detail, "refusal": refusal, "message": message},
        run_id=finding.run_id, project_id=finding.project_id,
    )


def _locked_finding(session: Session, finding_id: str) -> Any:
    """The finding row under ``SELECT ... FOR UPDATE`` (a no-op on sqlite)."""
    from sqlalchemy import select

    from redsim.db.models import Finding

    return session.execute(select(Finding).where(Finding.id == finding_id).with_for_update()).scalar_one_or_none()


def decide(*, finding_id: str, decision: str, reason: str, expected_status: str, actor: str,
           config: RedsimConfig, audit_writer: AuditWriter, expected_review_state: str | None = None,
           reviewer_is_system: bool = False) -> dict[str, Any]:
    """Apply one review decision to a finding, audit-first, compare-and-set.

    Order: lookup (``LookupError``), review-block presence for review-level decisions,
    system principal and independence (``ApiError`` 403), stale ``expected_status`` /
    ``expected_review_state`` (409), the transition table (409), the ``resolve``
    conditions (``409 resolution_blocked`` with ``unmet``), then the audit row, then the
    write. Every refusal after lookup appends a ``success=False`` row first.
    """
    from redsim.db.models import Run
    from redsim.db.session import get_session

    codes = _codes()
    if decision not in TRANSITIONS:
        raise ValueError(f"unknown review decision {decision!r}; one of {sorted(TRANSITIONS)}")
    if not reason.strip():
        raise ValueError("reason is required")
    if expected_review_state is not None and expected_review_state not in REVIEW_STATES:
        raise ValueError(f"expected_review_state must be one of {sorted(REVIEW_STATES)}")
    transition = TRANSITIONS[decision]
    with get_session() as session:
        finding = _locked_finding(session, finding_id)
        if finding is None:
            raise LookupError("finding not found")
        parent = session.get(Run, finding.run_id)
        creator = str(parent.created_by) if parent is not None and parent.created_by else None
        carrier = review_carrier(finding.schema_blob)
        latest = carrier.latest_revision()
        author = latest.author if latest is not None else None
        from_state = carrier.state
        detail: dict[str, Any] = {
            "finding_id": finding_id, "decision": decision,
            "from_status": finding.status, "to_status": transition.to_status or finding.status,
            "from_review_state": from_state, "to_review_state": transition.to_review_state,
            "expected_status": expected_status, "expected_review_state": expected_review_state,
            "reason": reason, "reviewer": actor, "author": author, "campaign_creator": creator,
            "revision": latest.revision if latest is not None else None, "verify_run_id": None,
        }

        def refuse(refusal: str, message: str) -> None:
            _refuse(audit_writer, action=transition.action, actor=actor, finding=finding, detail=detail,
                    refusal=refusal, message=message)

        # A review-level decision needs a review block to record into.
        if carrier.key is None and decision not in STATUS_ONLY_DECISIONS:
            message = f"{decision!r} needs a finding with an ml or llm review block; this finding carries none"
            refuse(codes.TRANSITION_INVALID, message)
            raise codes.ApiError(codes.TRANSITION_INVALID, message, decision=decision, status=finding.status,
                                 review_state=from_state)

        # Independence (spec 7.7): identity, never rank. ``submit`` is the author's own act.
        # ``dismiss`` keeps the Phase A ``forbidden`` string detail; the Phase B decisions
        # carry the ``reviewer_not_independent`` envelope with the relation that failed.
        independence_code = codes.FORBIDDEN if decision == "dismiss" else codes.NOT_INDEPENDENT
        if reviewer_is_system:
            message = (f"system principals cannot {decision.replace('_', ' ')} findings; a review decision "
                       "needs an independent human reviewer")
            detail["independence_violations"] = ["system_principal"]
            refuse(independence_code, message)
            if decision == "dismiss":
                raise codes.ApiError(codes.FORBIDDEN, message)
            raise codes.ApiError(independence_code, message, relation="system_principal",
                                 relations=["system_principal"])
        resolution: ResolutionCheck | None = None
        if decision == "resolve":
            resolution = resolution_conditions(session, finding=finding, carrier=carrier)
            detail["verify_run_id"] = resolution.verify_run_id
            detail["verify_requesters"] = list(resolution.verify_requesters)
        if transition.author_only:
            if author is None or author != actor:
                message = "only the latest revision's author can submit the draft"
                refuse(codes.FORBIDDEN, message)
                raise codes.ApiError(codes.FORBIDDEN, message)
        else:
            violations = independence_violations(
                actor=actor, reviewer_is_system=False, campaign_creator=creator, revision_author=author,
                verify_requesters=resolution.verify_requesters if resolution is not None else (),
            )
            if violations:
                message = _independence_message(violations)
                detail["independence_violations"] = violations
                refuse(independence_code, message)
                if decision == "dismiss":
                    raise codes.ApiError(codes.FORBIDDEN, message)
                raise codes.ApiError(independence_code, message, relation=violations[0], relations=violations)

        # Compare-and-set (REVIEW_REPORTS-06): the loser of a race sees the current state.
        stale_code = codes.RUN_TERMINAL if decision == "dismiss" else codes.STATE_CONFLICT
        if finding.status != expected_status:
            message = "finding status no longer matches expected_status"
            refuse(stale_code, message)
            raise codes.ApiError(stale_code, message, status=finding.status, expected_status=expected_status,
                                 review_state=from_state)
        if expected_review_state is not None and from_state != expected_review_state:
            message = "finding review state no longer matches expected_review_state"
            refuse(stale_code, message)
            raise codes.ApiError(stale_code, message, status=finding.status, review_state=from_state,
                                 expected_review_state=expected_review_state)

        # The transition table. ``resolve`` is judged by its conditions below, which name
        # the status and review-state misses among the unmet list instead of a bare refusal.
        table_checked = decision != "resolve"
        if table_checked and transition.from_statuses is not None and finding.status not in transition.from_statuses:
            allowed = sorted(transition.from_statuses)
            if decision == "dismiss":
                message = (f"only {' or '.join(allowed)} findings can be dismissed; "
                           f"this finding is {finding.status!r}")
                refuse(codes.RUN_TERMINAL, message)
                raise codes.ApiError(codes.RUN_TERMINAL, message, status=finding.status, allowed_from=allowed)
            message = f"{decision!r} is not valid from status {finding.status!r}"
            refuse(codes.TRANSITION_INVALID, message)
            raise codes.ApiError(codes.TRANSITION_INVALID, message, decision=decision, status=finding.status,
                                 review_state=from_state, allowed_from=allowed)
        if table_checked and transition.from_review_states is not None and (
            carrier.key is not None or decision not in STATUS_ONLY_DECISIONS
        ) and from_state not in transition.from_review_states:
            allowed_states = sorted(transition.from_review_states)
            message = f"{decision!r} is not valid from review state {from_state!r}"
            refuse(codes.TRANSITION_INVALID, message)
            raise codes.ApiError(codes.TRANSITION_INVALID, message, decision=decision, status=finding.status,
                                 review_state=from_state, allowed_from_review_states=allowed_states)
        if decision == "submit" and (latest is None or latest.submitted_at is not None):
            message = "the draft has no unsubmitted revision to submit"
            refuse(codes.TRANSITION_INVALID, message)
            raise codes.ApiError(codes.TRANSITION_INVALID, message, decision=decision,
                                 revision=latest.revision if latest is not None else None)
        if decision == "submit" and latest is not None and not latest.evidence_ids:
            message = "a revision cites at least one evidence id before it can be submitted"
            refuse(codes.TRANSITION_INVALID, message)
            raise codes.ApiError(codes.TRANSITION_INVALID, message, decision=decision, revision=latest.revision)
        if resolution is not None and not resolution.ok:
            message = "the finding does not meet every resolution condition: " + ", ".join(resolution.unmet)
            detail["unmet"] = list(resolution.unmet)
            refuse(codes.RESOLUTION_BLOCKED, message)
            raise codes.ApiError(codes.RESOLUTION_BLOCKED, message, unmet=list(resolution.unmet),
                                 verify_run_id=resolution.verify_run_id, status=finding.status,
                                 review_state=from_state, validation_state=finding.validation_state)

        # Audit before the row changes (spec 6.7 invariant 4).
        authorize(transition.action, None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
                  project_id=finding.project_id, run_id=finding.run_id, detail=detail)

        now = datetime.now(UTC)
        blob = dict(finding.schema_blob or {})
        new_revision: FindingRevision | None = None
        if carrier.key is not None:
            review = carrier.review
            if decision == "submit" and latest is not None:
                frozen = latest.model_copy(update={
                    "submitted_at": now,
                    "sha256": revision_digest(observation=latest.observation, interpretation=latest.interpretation,
                                              candidate=latest.candidate, evidence_ids=latest.evidence_ids),
                })
                review.revisions = [*review.revisions[:-1], frozen]
            elif decision == "request_changes" and latest is not None:
                new_revision = FindingRevision(
                    revision=latest.revision + 1, author=latest.author, created_at=now,
                    evidence_ids=list(latest.evidence_ids), observation=latest.observation,
                    interpretation=latest.interpretation, candidate=latest.candidate,
                )
                review.revisions = [*review.revisions, new_revision]
            to_state = cast("ReviewState", transition.to_review_state)
            event = ReviewEvent(
                action=decision, to_state=to_state, actor=actor, at=now,
                from_state=cast("ReviewState | None", from_state), reason=reason,
                revision=latest.revision if latest is not None else None,
                verify_run_id=resolution.verify_run_id if resolution is not None else None,
            )
            review.history = [*review.history, event]
            review.state = to_state
            review.at = now
            review.reason = reason
            if not transition.author_only:
                review.reviewer = actor
            carrier.write(blob)
        if transition.to_status is not None:
            blob["status"] = transition.to_status
            finding.status = transition.to_status
        blob["updated_at"] = now.isoformat()
        finding.schema_blob, finding.updated_at = blob, now
        session.flush()
        review_out = carrier.review.model_dump(mode="json") if carrier.key is not None else None
        return {
            "id": finding_id, "decision": decision,
            "status": finding.status, "from_status": expected_status,
            "review_state": carrier.state, "from_review_state": from_state,
            "validation_state": finding.validation_state,
            "review": review_out,
            "revision": new_revision.revision if new_revision is not None else (
                latest.revision if latest is not None else None),
            "verify_run_id": resolution.verify_run_id if resolution is not None else None,
        }


def _independence_message(violations: Sequence[str]) -> str:
    parts = {
        "campaign_creator": "campaign creator cannot review their own finding",
        "revision_author": "the draft's author cannot review their own revision",
        "verify_requester": "the actor who requested the retest cannot resolve on it",
        "system_principal": "system principals cannot review findings",
    }
    return "; ".join(parts.get(v, v) for v in violations) + " (spec 7.7: an independent reviewer is required)"


# ---------------------------------------------------------------------------
# Retest links (REVIEW_REPORTS-09)
# ---------------------------------------------------------------------------


def list_retests(session: Session, finding: Any) -> dict[str, Any]:
    """Every retest linked to a finding with its compatibility against the baseline.

    Compatibility is equal ``settings_hash`` between the retest and the finding's
    campaign; the MRI delta is reported only for a compatible retest whose outcome is
    measured (not ``inconclusive``). An incompatible or partial retest carries no delta.
    """
    from sqlalchemy import select

    from redsim.db.models import Job, Run

    carrier = review_carrier(finding.schema_blob)
    detail = carrier.detail
    links: list[FindingVerify] = []
    if detail is not None:
        links = list(detail.retests) if detail.retests else ([detail.verify] if detail.verify is not None else [])
    table = _campaign_table(session)
    baseline = _campaign_row(session, table, finding.run_id)
    baseline_hash = str(baseline["settings_hash"]) if baseline and baseline.get("settings_hash") else None
    rows: list[dict[str, Any]] = []
    for link in links:
        verify_row = _campaign_row(session, table, link.run_id)
        verify_hash = link.settings_hash or (
            str(verify_row["settings_hash"]) if verify_row and verify_row.get("settings_hash") else None)
        run = session.get(Run, link.run_id)
        job = session.execute(select(Job).where(Job.run_id == link.run_id, Job.type == "verify.replay")
                              .order_by(Job.created_at.desc())).scalars().first()
        mismatched: list[str] = []
        if not baseline_hash or not verify_hash or baseline_hash != verify_hash:
            mismatched.append("settings_hash")
        if verify_row is not None and verify_row.get("baseline_run_id") not in (None, finding.run_id):
            mismatched.append("baseline_run_id")
        compatible = not mismatched
        measured = compatible and link.outcome != "inconclusive" and link.delta is not None
        rows.append({
            "run_id": link.run_id,
            "defense": link.defense.model_dump(mode="json"),
            "outcome": link.outcome,
            "run_status": run.status if run is not None else None,
            "job_status": job.status if job is not None else None,
            "requested_by": (str(run.created_by) if run is not None and run.created_by else None),
            "settings_hash": verify_hash,
            "baseline_run_id": link.baseline_run_id or (verify_row.get("baseline_run_id") if verify_row else None),
            "compatible": compatible,
            "mismatched": mismatched,
            "delta_mri": link.delta.delta if measured and link.delta is not None else None,
            "delta": link.delta.model_dump(mode="json") if measured and link.delta is not None else None,
        })
    return {
        "finding_id": finding.id, "baseline_run_id": finding.run_id, "baseline_settings_hash": baseline_hash,
        "validation_state": finding.validation_state, "status": finding.status, "review_state": carrier.state,
        "retests": rows, "count": len(rows),
    }


# ---------------------------------------------------------------------------
# Analyst-authored drafts (REVIEW_REPORTS-05)
# ---------------------------------------------------------------------------


def manual_finding_type() -> str:
    """``adversarial_ml_manual`` when the core schema lists it, else ``adversarial_ml``."""
    from redsim.schema import FindingType

    return MANUAL_FINDING_TYPE if MANUAL_FINDING_TYPE in get_args(FindingType) else "adversarial_ml"


@dataclass(frozen=True)
class _RunEvidence:
    """The immutable run record's citable ids and the rows a draft cites."""

    record: dict[str, Any]
    record_artifact_id: str | None
    known_ids: frozenset[str]

    def measurements(self, ids: Sequence[str]) -> list[Measurement]:
        wanted = set(ids)
        return [Measurement.model_validate(m) for m in self.record.get("measurements", []) if m.get("id") in wanted]

    def observations(self, ids: Sequence[str]) -> list[Observation]:
        wanted = set(ids)
        return [Observation.model_validate(o) for o in self.record.get("observations", []) if o.get("id") in wanted]

    def attack_name(self, attack_id: str) -> str:
        for attack in self.record.get("attacks", []):
            if attack.get("id") == attack_id:
                return str(attack.get("name") or attack_id)
        return attack_id


def _load_run_evidence(session: Session, run_id: str) -> _RunEvidence:
    """The run's ``ml.run_record`` (digest-checked) as the only source of citable ids."""
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.services.reports import load_run_record
    from redsim.storage.blobs import open_blob_store

    codes = _codes()
    try:
        record, _digest = load_run_record(session, open_blob_store(), run_id)
    except LookupError as exc:
        raise codes.ApiError(codes.NOT_FOUND, f"run {run_id} has no ml.run_record to cite") from exc
    except ValueError as exc:
        raise codes.ApiError(codes.SCORE_UNAVAILABLE, "run record digest mismatch: the recorded ml.run_record "
                             "does not match its sha256", reasons=["artifact_digest_mismatch"]) from exc
    artifact = session.execute(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.kind == "ml.run_record")
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().first()
    known = {str(m.get("id")) for m in record.get("measurements", []) if isinstance(m, dict)}
    known |= {str(o.get("id")) for o in record.get("observations", []) if isinstance(o, dict)}
    known |= {str(i.get("id")) for i in record.get("interpretation", []) if isinstance(i, dict)}
    return _RunEvidence(record, None if artifact is None else str(artifact.id), frozenset(known))


def _check_evidence_ids(evidence: _RunEvidence, evidence_ids: Sequence[str]) -> list[str]:
    codes = _codes()
    ids = list(dict.fromkeys(str(e) for e in evidence_ids))
    if not ids:
        raise codes.ApiError(codes.PARAMS_OUT_OF_RANGE, "a draft cites at least one measurement or observation id",
                             field="evidence_ids")
    unknown = [e for e in ids if e not in evidence.known_ids]
    if unknown:
        raise codes.ApiError(codes.PARAMS_OUT_OF_RANGE,
                             "evidence_ids must name measurement, observation or interpretation ids of the run's "
                             "immutable record", field="evidence_ids", reasons=unknown)
    return ids


def draft_description(*, revision: FindingRevision, attack_name: str, run_id: str) -> str:
    """The analyst text, labelled as such, never presented as a measured projection."""
    parts = [f"Analyst-authored draft (revision {revision.revision}, author {revision.author}) on {attack_name} "
             f"from run {run_id}; severity declared by the author, not derived from measurements."]
    if revision.observation:
        parts.append(f"Observation: {revision.observation}")
    if revision.interpretation:
        parts.append(f"Interpretation: {revision.interpretation}")
    if revision.candidate:
        parts.append(f"Candidate (not evaluated): {revision.candidate}")
    parts.append("Cites: " + ", ".join(f"[{e}]" for e in revision.evidence_ids) + ".")
    return " ".join(parts)


def _author_refuse(audit_writer: AuditWriter, *, actor: str, project_id: str | None, run_id: str | None,
                   detail: dict[str, Any], exc: Any) -> None:
    audit_writer.append(
        action=AUTHOR_ACTION, actor=actor, target=None, allowlist_check="n/a", override=False, success=False,
        detail={**detail, "refusal": exc.code, "message": str(exc)}, run_id=run_id, project_id=project_id,
    )


def create_draft_finding(*, run_id: str, attack_id: str, title: str, severity: str, observation: str,
                         interpretation: str | None, candidate: str | None, evidence_ids: Sequence[str],
                         actor: str, config: RedsimConfig, audit_writer: AuditWriter,
                         reviewer_is_system: bool = False) -> dict[str, Any]:
    """Create an analyst-authored draft finding against a terminal campaign run.

    The draft cites evidence ids that must exist in the run's digest-checked
    ``ml.run_record``; it carries ``finding_type`` :func:`manual_finding_type`,
    ``source_tool="manual"``, ``status="open"``, ``review.state="draft"`` and
    ``review.revisions[0]`` authored by ``actor``. The ``finding.author`` audit row
    (``op=create``, ids and digests only) is written before the row.
    """
    from redsim.db.models import Finding, Run, Target
    from redsim.db.session import get_session
    from redsim.schema import FindingType, RedsimFinding, Severity

    codes = _codes()
    if reviewer_is_system:
        raise codes.ApiError(codes.FORBIDDEN, "system principals cannot author findings")
    if not title.strip() or not observation.strip():
        raise ValueError("title and observation are required")
    with get_session() as session:
        run = session.get(Run, run_id)
        if run is None:
            raise LookupError("run not found")
        project_id = str(run.project_id)
        audit_detail: dict[str, Any] = {"op": "create", "run_id": run_id, "attack_id": attack_id, "author": actor,
                                        "n_evidence": len(evidence_ids), "severity": severity}
        try:
            if run.status not in _TERMINAL_RUN:
                raise codes.ApiError(codes.CAMPAIGN_NOT_TERMINAL, "the campaign has not reached a terminal status",
                                     status=run.status)
            row = _campaign_row(session, _campaign_table(session), run_id)
            if row is None:
                raise codes.ApiError(codes.NOT_FOUND, "campaign record not found for this run")
            campaign_config = CampaignConfig.model_validate(row["config"])
            if attack_id not in campaign_config.attack_ids:
                raise codes.ApiError(codes.PARAMS_OUT_OF_RANGE, "attack_id is not in the run's attack set",
                                     field="attack_id", allowed=list(campaign_config.attack_ids))
            evidence = _load_run_evidence(session, run_id)
            ids = _check_evidence_ids(evidence, evidence_ids)
        except codes.ApiError as exc:
            _author_refuse(audit_writer, actor=actor, project_id=project_id, run_id=run_id, detail=audit_detail,
                           exc=exc)
            raise
        now = datetime.now(UTC)
        revision = FindingRevision(revision=1, author=actor, created_at=now, evidence_ids=ids,
                                   observation=observation, interpretation=interpretation, candidate=candidate)
        digest = revision_digest(observation=observation, interpretation=interpretation, candidate=candidate,
                                 evidence_ids=ids)
        attack_name = evidence.attack_name(attack_id)
        measurements = evidence.measurements(ids)
        observations = evidence.observations(ids)
        detail = MLFindingDetail(
            attack_id=attack_id, attack_name=attack_name, norm=campaign_config.norm,
            eps_grid=list(campaign_config.eps_grid), reference_eps=campaign_config.reference_eps,
            threshold=float(campaign_config.finding_asr_threshold),
            measurements=measurements, observations=observations,
            limitations=[*[str(x) for x in evidence.record.get("limitations", [])],
                         "Analyst-authored draft: the observation, interpretation and candidate texts are the "
                         "author's; only the cited ids are measured."],
            review=FindingReview(state="draft", notes=_MANUAL_NOTE, revisions=[revision]),
        )
        finding_type = manual_finding_type()
        scanner_id = f"manual.{attack_id}.{uuid4().hex[:8]}"
        target = session.get(Target, run.target_id) if run.target_id else None
        evidence_json = {
            "measurements": [m.id for m in measurements], "observations": [o.id for o in observations],
            "interpretation": [e for e in ids if e.startswith("i.")],
        }
        blob = RedsimFinding(
            id=scanner_id, title=title.strip(), severity=cast("Severity", severity),
            finding_type=cast("FindingType", finding_type),
            description=draft_description(revision=revision, attack_name=attack_name, run_id=run_id),
            source_tool=MANUAL_SOURCE_TOOL, source_run_id=run_id,
            affected_component=str(run.target_id or campaign_config.target_id),
            target=str(target.value) if target is not None else None,
            confidence=MANUAL_CONFIDENCE, status="open", created_at=now.isoformat(), updated_at=now.isoformat(),
            evidence=json.dumps(evidence_json, sort_keys=True), artifact_path=evidence.record_artifact_id,
            remediation_steps=f"CANDIDATE (not evaluated): {candidate}" if candidate else None,
        ).model_dump(mode="json")
        blob["ml"] = detail.model_dump(mode="json")
        audit_detail.update({"evidence_ids": ids, "revision": 1, "revision_sha256": digest,
                             "title_sha256": hashlib.sha256(title.strip().encode("utf-8")).hexdigest(),
                             "finding_type": finding_type, "scanner_finding_id": scanner_id})
        # The audit event is intentionally before the durable row.
        authorize(AUTHOR_ACTION, None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
                  project_id=project_id, run_id=run_id, detail=audit_detail)
        finding = Finding(
            id=str(uuid4()), scanner_finding_id=scanner_id, run_id=run_id, project_id=project_id,
            schema_blob=blob, status="open", severity=severity, source_tool=MANUAL_SOURCE_TOOL,
            validation_state="unvalidated", dedup_key=f"manual:{run_id}:{attack_id}:{digest[:16]}",
        )
        session.add(finding)
        session.flush()
        return {
            "id": finding.id, "run_id": run_id, "project_id": project_id, "scanner_finding_id": scanner_id,
            "status": "open", "review_state": "draft", "revision": 1, "revision_sha256": digest,
            "finding_type": finding_type, "severity": severity, "validation_state": "unvalidated",
            "schema_blob": blob,
        }


def revise_draft(*, finding_id: str, observation: str | None, interpretation: str | None, candidate: str | None,
                 evidence_ids: Sequence[str] | None, actor: str, config: RedsimConfig, audit_writer: AuditWriter,
                 reviewer_is_system: bool = False) -> dict[str, Any]:
    """Append a new editable revision to a draft (author only, ``draft`` state only).

    Revisions are append-only: a submitted revision is never edited. Fields left
    ``None`` are carried over from the latest revision; ``evidence_ids`` are checked
    against the run record again. Audit ``finding.author`` (``op=revise``) first.
    """
    from redsim.db.session import get_session

    codes = _codes()
    with get_session() as session:
        finding = _locked_finding(session, finding_id)
        if finding is None:
            raise LookupError("finding not found")
        carrier = review_carrier(finding.schema_blob)
        latest = carrier.latest_revision()
        audit_detail: dict[str, Any] = {
            "op": "revise", "finding_id": finding_id, "run_id": finding.run_id, "author": actor,
            "revision": latest.revision if latest is not None else None, "review_state": carrier.state,
        }

        def refuse(exc: Any) -> None:
            _author_refuse(audit_writer, actor=actor, project_id=finding.project_id, run_id=finding.run_id,
                           detail=audit_detail, exc=exc)

        try:
            if reviewer_is_system:
                raise codes.ApiError(codes.FORBIDDEN, "system principals cannot author findings")
            if carrier.key != "ml" or carrier.detail is None or latest is None:
                raise codes.ApiError(codes.TRANSITION_INVALID, "only an analyst draft with revisions can be revised",
                                     review_state=carrier.state)
            if latest.author != actor:
                raise codes.ApiError(codes.FORBIDDEN, "only the draft's author can revise it")
            if carrier.state != "draft":
                raise codes.ApiError(codes.TRANSITION_INVALID,
                                     f"a revision can be added only in review state 'draft'; this finding is "
                                     f"{carrier.state!r}", review_state=carrier.state, allowed_from_review_states=["draft"])
            ids = list(latest.evidence_ids)
            if evidence_ids is not None:
                ids = _check_evidence_ids(_load_run_evidence(session, finding.run_id), evidence_ids)
        except codes.ApiError as exc:
            refuse(exc)
            raise
        now = datetime.now(UTC)
        revision = FindingRevision(
            revision=latest.revision + 1, author=actor, created_at=now, evidence_ids=ids,
            observation=observation if observation is not None else latest.observation,
            interpretation=interpretation if interpretation is not None else latest.interpretation,
            candidate=candidate if candidate is not None else latest.candidate,
        )
        digest = revision_digest(observation=revision.observation, interpretation=revision.interpretation,
                                 candidate=revision.candidate, evidence_ids=ids)
        audit_detail.update({"new_revision": revision.revision, "revision_sha256": digest, "n_evidence": len(ids),
                             "evidence_ids": ids})
        authorize(AUTHOR_ACTION, None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
                  project_id=finding.project_id, run_id=finding.run_id, detail=audit_detail)
        detail = carrier.detail
        evidence = _load_run_evidence(session, finding.run_id) if evidence_ids is not None else None
        if evidence is not None:
            detail.measurements = evidence.measurements(ids)
            detail.observations = evidence.observations(ids)
        carrier.review.revisions = [*carrier.review.revisions, revision]
        carrier.review.at = now
        blob = dict(finding.schema_blob or {})
        carrier.write(blob)
        blob["description"] = draft_description(revision=revision, attack_name=detail.attack_name, run_id=finding.run_id)
        blob["evidence"] = json.dumps({
            "measurements": [m.id for m in detail.measurements], "observations": [o.id for o in detail.observations],
            "interpretation": [e for e in ids if e.startswith("i.")],
        }, sort_keys=True)
        if revision.candidate:
            blob["remediation_steps"] = f"CANDIDATE (not evaluated): {revision.candidate}"
        blob["updated_at"] = now.isoformat()
        finding.schema_blob, finding.updated_at = blob, now
        session.flush()
        return {"id": finding_id, "status": finding.status, "review_state": carrier.state,
                "revision": revision.revision, "revision_sha256": digest,
                "review": carrier.review.model_dump(mode="json")}


__all__ = [
    "AUTHOR_ACTION", "DECISIONS", "MANUAL_FINDING_TYPE", "MANUAL_SOURCE_TOOL", "REVIEW_ACTION", "REVIEW_STATES",
    "STATUS_ONLY_DECISIONS", "TRANSITIONS", "Decision", "ResolutionCheck", "ReviewCarrier", "Transition",
    "create_draft_finding", "decide", "draft_description", "independence_violations", "latest_retest",
    "list_retests", "manual_finding_type", "resolution_conditions", "review_carrier", "review_state_of",
    "review_summary", "revise_draft", "revision_digest", "verify_requesters",
]
