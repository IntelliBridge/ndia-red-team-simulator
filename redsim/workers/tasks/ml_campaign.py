"""Celery wrapper for one complete adversarial-ML campaign (spec 10.3 to 10.8).

The task validates the frozen admission snapshot, runs the pure campaign inside
the credential-free sandbox child (``redsim.ml.sandbox``), and turns the
returned envelope into durable evidence:

* **Artifacts** through :class:`DatabaseArtifactSink`, whose explicit
  name-to-kind table is the spec 5.8 vocabulary (``ml.curve``, ``ml.shap.*``,
  ``ml.feature_diff``, ``ml.harden.*``, ``report.md`` / ``report.json`` /
  ``report.html``; a killed child's files under ``ml/partial/`` become
  ``ml.partial.*``). Phase B adds the text modality's ``ml.text.diff`` /
  ``ml.shap.text``, the detection modality's ``ml.detection.boxes`` /
  ``ml.detection.scorecard`` (its drawn images stay ``ml.input.clean`` /
  ``ml.input.adv``) and the training defenses' ``ml.derived_model`` /
  ``ml.training_report`` (MODALITIES-44, ATTACKS_HARDEN-15).
* **Run.stage_table** in the spec 6.5 shape: ``stage``, ``stages_done``, a
  ``stages`` map with per-stage ``status`` (``queued | running | succeeded |
  failed | skipped | cancelled | timed_out``), ``started_at`` / ``finished_at``
  and ``job_id``, the ``jobs`` map and ``completeness``; every transition is
  also published as a ``{"type": "stage", "name": ..., "status": ...}`` frame.
  ``defense_apply`` is expected right after ``load_target`` when the campaign
  applies a ``kind: training`` defense (``redsim.ml.defenses``); a
  preprocessing defense wraps the target inside ``load_target`` and adds no
  stage.
* **Audit rows** in the spec 10.5 order through ``redsim.safety.authorize``:
  ``model.load``, ``attack.execute.<attack_id>``, ``explain.execute``,
  ``campaign.score``, ``harden.execute``, ``verify.execute``, ``report.render``
  (with ``formats``) and ``job.complete``, actor ``worker:<job type>`` with the
  requesting principal in ``detail.requested_by``; refused or failed steps are
  ``success=False`` rows. Details carry ids, digests and counts only.
* **The Pythia narrative** (spec 10.8, 16.3) in this parent process, after the
  envelope returns: model through ``redsim.llm.router.route("ml.harden_narrative")``
  with the ``DbBudgetChecker``, transport ``redsim.llm.pythia.chat_text`` wrapped
  in the guardrails, prompt and completion stored as ``ml.harden.prompt`` /
  ``ml.harden.completion`` artifacts with digests on the ``harden.execute`` row,
  and one ``LLMUsage(task="ml.harden_narrative")`` row. Every failure keeps the
  rule output with ``narrative_source="rules"`` and the skip reason; nothing
  here fails the job.
* **Findings**: ``attack.run`` projects threshold crossings; ``explain.run`` and
  ``harden.recommend`` merge the child's observations, interpretation and
  candidates back into the parent finding's ``schema_blob["ml"]``;
  ``verify.replay`` attaches the ``MeasuredDelta`` to the recommendation naming
  the defense, maps the outcome through ``verify._STATE_MAP`` and spec 6.4
  (``inconclusive`` -> ``open``), writes the ``RemediationAttempt`` row and the
  ``verify.execute`` audit row.

``SandboxTimeout`` / ``SandboxKilled`` / ``EnvelopeInvalid`` from the child are
Job failures with the stage marked ``timed_out`` / ``failed``, completeness
``partial``, the files the child had written kept under ``ml/partial/``, a
``job.complete`` row with ``success=False`` and the error class, and, for a
verify job, the finding left ``inconclusive`` / ``open``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from redsim.workers.celery_app import app

if TYPE_CHECKING:
    from celery import Task
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.ml.schema import CampaignConfig, CampaignRecord, MRIRecord
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

# Recorded on a verify run whose MRI delta could not be measured. The outcome
# (verified / still_vulnerable / inconclusive) does not depend on the delta, so
# the run still completes and the reason travels with the record.
DELTA_UNAVAILABLE_LIMITATION = (
    "MRI delta not computed: {reason}. The verification outcome is projected from "
    "the recorded attack measurements only, and the recommendation keeps "
    "validation 'not evaluated' because no delta was measured."
)

#: Router task of the hardening narrative (spec 5.12, 10.8); mirrors ``redsim.llm.router``.
NARRATIVE_TASK = "ml.harden_narrative"
#: Report formats ``render_campaign_reports`` writes; the ``report.render`` audit row lists them.
REPORT_FORMATS: tuple[str, ...] = ("md", "json", "html")
#: Prefix of files a killed / timed-out child had written (mirrors ``redsim.ml.sandbox.PARTIAL_PREFIX``).
PARTIAL_PREFIX = "ml/partial/"
#: Spec 6.5 per-stage status vocabulary.
STAGE_STATUSES: tuple[str, ...] = (
    "queued", "running", "succeeded", "failed", "skipped", "cancelled", "timed_out",
)
# Spec 6.4 / 16.5: verify outcome -> Finding.status. validation_state comes from verify._STATE_MAP.
VERIFY_STATUS_MAP: dict[str, str] = {
    "verified": "fixed",
    "still_vulnerable": "failed",
    "inconclusive": "open",
}
# Artifact names the parent writes for the narrative (spec 5.8 ``ml.harden.*``).
HARDEN_PROMPT_NAME = "harden/prompt.txt"
HARDEN_COMPLETION_NAME = "harden/completion.txt"
HARDEN_NARRATIVE_NAME = "harden/narrative.md"
SHAP_SUMMARY_TEXT_NAME = "shap_summary.txt"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_LOAD_ERROR_CLASSES = (
    "ModelLoadRefused", "UnsupportedArtifact", "ArtifactDigestMismatch", "TargetUnavailable",
    "DatasetUnavailable", "MlExtraUnavailable",
)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in _TRUE_VALUES


def _error_class(message: str | None) -> str | None:
    """``"ModelLoadRefused"`` from ``"ModelLoadRefused: ..."``; ``None`` when the text has no class prefix."""
    if not message:
        return None
    head, sep, _rest = message.partition(":")
    head = head.strip()
    return head if sep and head.isidentifier() else None


# ---------------------------------------------------------------------------
# Verify delta (unchanged helpers, tested by tests/test_review22_partial_delta.py)
# ---------------------------------------------------------------------------


def _partial_score_reason(label: str, score: MRIRecord) -> str | None:
    """Why ``score`` cannot enter a delta, or ``None`` when it carries an MRI."""
    if score.mri is not None:
        return None
    missing = ", ".join(score.missing) or "reason not recorded"
    return f"the {label} score record is partial and carries no MRI ({missing})"


def _attach_verify_delta(
    record: CampaignRecord,
    baseline_record: CampaignRecord,
    *,
    baseline_run_id: str,
) -> CampaignRecord:
    """Attach the measured MRI delta when both scores are complete and comparable.

    ``redsim.ml.scoring.delta`` refuses a partial score (``mri`` is ``None`` on
    either side, for example because a subscore such as the explanation shift
    was unavailable) and an incompatible pair. Neither refusal invalidates the
    verify run itself: its outcome is projected from the recorded attack
    measurements. So the delta is recorded as unavailable in the run's
    limitations, with the reason, and the record is otherwise left intact.
    """
    from redsim.ml.scoring import delta

    before = baseline_record.score
    after = record.score
    if before is None or after is None:
        raise RuntimeError("verify delta needs a score on both the baseline and the verify record")
    reasons = [
        reason
        for reason in (
            _partial_score_reason("baseline", before),
            _partial_score_reason("verify", after),
        )
        if reason is not None
    ]
    if not reasons:
        try:
            measured = delta(
                before,
                after,
                baseline_run_id=baseline_run_id,
                measurements_before=baseline_record.measurements,
                measurements_after=record.measurements,
            )
        except ValueError as exc:
            reasons.append(str(exc))
        else:
            return record.model_copy(update={
                "score": after.model_copy(update={"delta": measured}),
            })
    limitation = DELTA_UNAVAILABLE_LIMITATION.format(reason="; ".join(reasons))
    logger.warning("verify run %s: %s", record.run_id, limitation)
    limitations = list(record.limitations)
    if limitation not in limitations:
        limitations.append(limitation)
    return record.model_copy(update={"limitations": limitations})


# ---------------------------------------------------------------------------
# Artifact kinds (spec 5.8) and the database sink
# ---------------------------------------------------------------------------

# Exact artifact names -> kind. Observation-level files are matched on their
# basename (the explainers write them under ``obs_<i>/``), campaign-level files
# on their full name.
_EXACT_KINDS: dict[str, str] = {
    "run_record.json": "ml.run_record",
    "score.json": "ml.score",
    "flip_matrix.json": "ml.flip_matrix",
    "validation_report.json": "ml.validation_report",
    "shap_summary.json": "ml.shap.summary",
    SHAP_SUMMARY_TEXT_NAME: "ml.shap.summary_text",
    "shap_bar_clean.png": "ml.shap.bar",
    "shap_bar_adv.png": "ml.shap.bar",
    "shap_beeswarm_clean.png": "ml.shap.beeswarm",
    "shap_beeswarm_adv.png": "ml.shap.beeswarm",
    HARDEN_PROMPT_NAME: "ml.harden.prompt",
    HARDEN_COMPLETION_NAME: "ml.harden.completion",
    HARDEN_NARRATIVE_NAME: "ml.harden.narrative",
    # Phase B (INTEROP-04): one per-run clean slice with per-sample keys the export projects from.
    # ``ml.clean_slice`` / ``ml.control_slice`` are this track's names (announced in the cross-track
    # notes); the modality runner writes the npz bytes, this table only names their kind.
    "clean_slice.npz": "ml.clean_slice",
    # Training defenses (redsim.ml.harden.apply.WEIGHTS_ARTIFACT / REPORT_ARTIFACT): the derived state_dict
    # and the training record of a defense_apply stage (ATTACKS_HARDEN-12/-13/-15). The derived model is
    # registered as a new Target through the register-then-validate path.
    "derived_model/weights.pt": "ml.derived_model",
    "derived_model/training_report.json": "ml.training_report",
    # Detection modality (redsim.ml.runners.detection.SCORECARD_NAME): the campaign-level box scorecard.
    "detection_scorecard.json": "ml.detection.scorecard",
    "report.md": "report.md",
    "report.json": "report.json",
    "report.html": "report.html",
}
_BASENAME_KINDS: dict[str, str] = {
    "clean.png": "ml.input.clean",
    "adv.png": "ml.input.adv",
    "diff.png": "ml.perturbation",
    "shap_clean.png": "ml.shap.image",
    "shap_adv.png": "ml.shap.image",
    "shap_adv_predclass.png": "ml.shap.image",
    "shap_values.npz": "ml.shap.values",
    "shap_meta.json": "ml.shap.meta",
    "feature_diff.json": "ml.feature_diff",
    # Pre-rename tabular names (redsim.ml.explain.base.LEGACY_ARTIFACT_NAMES) keep their kinds.
    "top_features.json": "ml.feature_diff",
    "shap_pair.png": "ml.shap.force",
    "events.jsonl": "ml.events",
    # Text modality (redsim.ml.explain.shap_text.TEXT_DIFF_NAME / TEXT_PLOT_NAME): the escaped word diff of
    # one observation and its token-attribution bars (MODALITIES-19/-44). shap_values.npz keeps ml.shap.values.
    "text_diff.json": "ml.text.diff",
    "shap_text.png": "ml.shap.text",
    # Detection modality (redsim.ml.runners.detection.BOXES_JSON_NAME / CLEAN_PNG_NAME / ADV_PNG_NAME): the
    # per-observation box record (GT, clean and adversarial predictions, matches, patch location) and the drawn
    # clean / patched inputs (MODALITIES-35/-44).
    "boxes.json": "ml.detection.boxes",
    "clean_boxes.png": "ml.input.clean",
    "adv_boxes.png": "ml.input.adv",
}
_PREFIX_KINDS: tuple[tuple[str, str], ...] = (
    ("curve/", "ml.curve"),
    ("adv_slice/", "ml.adv_slice"),
    # Phase B (INTEROP-04): per-(family, eps) export slices; the runner writes control_slice/<eps>.npz
    # and clean_slice/<...>.npz when a run keeps them under the size cap.
    ("control_slice/", "ml.control_slice"),
    ("clean_slice/", "ml.clean_slice"),
)


def artifact_kind(name: str) -> str:
    """The spec 5.8 ``Artifact.kind`` for a run-relative artifact ``name``.

    A file the child had written before it was killed (``ml/partial/<name>``)
    is ``ml.partial.<kind minus its ml. prefix>`` so the run's evidence keeps
    its provenance while never masquerading as a completed artifact. Unknown
    names fall back to ``ml.<stem>`` so nothing is dropped.
    """
    if name.startswith(PARTIAL_PREFIX):
        inner = artifact_kind(name[len(PARTIAL_PREFIX):])
        return f"ml.partial.{inner[3:] if inner.startswith('ml.') else inner}"
    if name in _EXACT_KINDS:
        return _EXACT_KINDS[name]
    for prefix, kind in _PREFIX_KINDS:
        if name.startswith(prefix):
            return kind
    base = name.rsplit("/", 1)[-1]
    if base in _BASENAME_KINDS:
        return _BASENAME_KINDS[base]
    if base.startswith("shap_force_") and base.endswith(".png"):
        return "ml.shap.force"
    if base.startswith("report."):
        return f"report.{base.rsplit('.', 1)[-1]}"
    return f"ml.{base.rsplit('.', 1)[0]}"


class DatabaseArtifactSink:
    """ArtifactSink backed by content-addressed BlobStore and Artifact rows.

    Rows are unique on ``(run_id, kind, sha256)``; a second put of identical
    bytes under the same kind reuses the row. ``ids`` maps every name written
    to its ``Artifact.id`` and ``get`` reads a named artifact back, digest
    checked, for the parent-side steps (the narrative payload).
    """

    def __init__(self, session: Session, blob_store: BlobStore, *,
                 run_id: str, project_id: str) -> None:
        self.session = session
        self.blob_store = blob_store
        self.run_id = run_id
        self.project_id = project_id
        self._hashes: dict[str, str] = {}
        self._locations: dict[str, str] = {}
        self.ids: dict[str, str] = {}
        self.kinds: dict[str, str] = {}
        self.finalizing_run_record = False

    @staticmethod
    def _kind(name: str) -> str:
        return artifact_kind(name)

    def put(self, name: str, data: bytes,
            content_type: str = "application/octet-stream") -> str:
        from sqlalchemy import select

        from redsim.db.models import Artifact

        digest = hashlib.sha256(data).hexdigest()
        # The pure runner necessarily creates its own local run id. Defer that
        # one record until the worker replaces it with the authoritative DB id.
        if name == "run_record.json" and not self.finalizing_run_record:
            self._hashes[name] = digest
            return "deferred:ml.run_record"
        kind = self._kind(name)
        existing = self.session.execute(select(Artifact).where(
            Artifact.run_id == self.run_id,
            Artifact.kind == kind,
            Artifact.sha256 == digest,
        )).scalar_one_or_none()
        if existing is None:
            key = f"{self.project_id}/{self.run_id}/{name}/{digest}"
            ref = self.blob_store.put(key, data, content_type=content_type)
            existing = Artifact(
                id=str(uuid4()), run_id=self.run_id, project_id=self.project_id,
                kind=kind, sha256=digest, location=ref.location,
                content_type=content_type, size_bytes=len(data),
            )
            self.session.add(existing)
            self.session.flush()
            # Each artifact is independently durable. If a later ML stage
            # fails, task_context may roll back projections but not evidence
            # already emitted by a completed stage.
            self.session.commit()
        self._hashes[name] = digest
        self._hashes[existing.id] = digest
        self._locations[name] = str(existing.location)
        self.ids[name] = existing.id
        self.kinds[name] = kind
        return existing.id

    def sha256(self, name: str) -> str:
        return self._hashes[name]

    def get(self, name: str) -> bytes | None:
        """The bytes written under ``name`` in this run, or ``None``; a digest mismatch is ``None`` too."""
        location = self._locations.get(name)
        if location is None:
            return None
        try:
            data = self.blob_store.get(location)
        except Exception:  # noqa: BLE001 - a missing blob is "unavailable", never a crash in the parent
            logger.warning("artifact %r could not be read back from %s", name, location, exc_info=True)
            return None
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if hashlib.sha256(raw).hexdigest() != self._hashes.get(name):
            logger.warning("artifact %r digest changed since it was written", name)
            return None
        return raw


# ---------------------------------------------------------------------------
# Stage table (spec 6.5) and stage frames
# ---------------------------------------------------------------------------


def _publish_stage(run_id: str, job_id: str, stage: str, status: str = "succeeded") -> None:
    """``{"type": "stage", "name": <stage>, "status": <status>}`` on the run channel (best effort)."""
    from redsim.workers.events import publish_job_event

    publish_job_event(
        run_id, job_id, status, type="stage", name=stage, stage=stage,
    )


def _applies_training_defense(config: CampaignConfig) -> bool:
    """True when ``config.defense`` names a ``kind: training`` row of the defense catalog.

    Mirrors ``redsim.ml.campaign._defense_kind``: an unknown id or an absent catalog reads as
    preprocessing (the child then refuses or wraps inside ``load_target``; no ``defense_apply``).
    """
    if config.defense is None:
        return False
    try:
        from redsim.ml.defenses import is_training_defense
    except ImportError:
        return False
    try:
        return bool(is_training_defense(config.defense.id))
    except ValueError:
        return False


def expected_stages(config: CampaignConfig) -> list[str]:
    """The stage keys this campaign is expected to write, in order (spec 6.5, ``schema.STAGES``).

    ``defense_apply`` follows ``load_target`` only when the campaign applies a training defense
    (ATTACKS_HARDEN-15); the child emits it after fine-tuning the copy it then attacks. A
    preprocessing defense wraps the loaded target and has no stage of its own.
    """
    out = ["load_target"]
    if _applies_training_defense(config):
        out.append("defense_apply")
    out.extend(["sample", "clean_eval"])
    out.extend(f"attack:{aid}" for aid in config.attack_ids)
    if config.include_control:
        out.append("control")
    if config.explain_k > 0:
        out.append("explain")
    out.extend(["score", "interpret"])
    if config.auto_recommend:
        out.append("recommend")
    out.append("report")
    return out


class _StageTracker:
    """Keeps ``Run.stage_table`` in the spec 6.5 shape and publishes stage frames.

    The child reports a stage when it *finishes*, so a stage's ``started_at`` is
    the previous stage's ``finished_at`` (or the job start) and the next expected
    stage is marked ``running``. An expected stage that never completes before a
    later one does (an attack recorded ``not_run``, an explain stage that was
    skipped) becomes ``skipped``; the stage running when the child died becomes
    ``failed`` / ``timed_out`` / ``cancelled``.
    """

    def __init__(self, session: Session, *, run_id: str, job_id: str, job_type: str,
                 config: CampaignConfig) -> None:
        self.session = session
        self.run_id = run_id
        self.job_id = job_id
        self.job_type = job_type
        self.attack_ids = list(config.attack_ids)
        self.expected = expected_stages(config)
        self.started_at = _iso(_now())
        self._cursor = self.started_at
        self.done: list[str] = []

    # -- helpers ---------------------------------------------------------------

    def _live_run(self) -> Any:
        from redsim.db.models import Run

        run = self.session.get(Run, self.run_id)
        if run is None or run.status in {"succeeded", "failed", "cancelled"}:
            return None
        return run

    def _table(self, run: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        table = dict(run.stage_table or {})
        stages = dict(table.get("stages") or {})
        jobs = dict(table.get("jobs") or {})
        return table, stages, jobs

    def _store(self, run: Any, table: dict[str, Any], stages: dict[str, Any], jobs: dict[str, Any],
               *, stage: str | None, job_status: str) -> None:
        jobs[self.job_id] = {
            **dict(jobs.get(self.job_id) or {}),
            "type": self.job_type, "status": job_status, "stage": stage,
            "attack_ids": self.attack_ids,
        }
        table.update({
            "stage": stage,
            "stages_done": list(self.done),
            "stages": stages,
            "jobs": jobs,
        })
        table.setdefault("error", None)
        run.stage_table = table
        self.session.commit()

    def _next_expected(self, stage: str) -> str | None:
        if stage in self.expected:
            idx = self.expected.index(stage)
            return self.expected[idx + 1] if idx + 1 < len(self.expected) else None
        # ``attack`` without an id (older children): the next stage after the last attack.
        if stage == "attack" and self.attack_ids:
            return self._next_expected(f"attack:{self.attack_ids[-1]}")
        return None

    def _open_stage(self, stages: dict[str, Any]) -> str | None:
        """The stage currently marked running/queued, or the next expected one after the last done."""
        for name, entry in stages.items():
            if isinstance(entry, dict) and entry.get("status") in {"running", "queued"}:
                return name
        if self.done:
            return self._next_expected(self.done[-1])
        return self.expected[0] if self.expected else None

    # -- transitions -----------------------------------------------------------

    def begin(self) -> None:
        run = self._live_run()
        if run is None:
            return
        table, stages, jobs = self._table(run)
        first = self.expected[0]
        stages.setdefault(first, {
            "status": "running", "started_at": self.started_at, "finished_at": None, "job_id": self.job_id,
        })
        table.setdefault("completeness", None)
        self._store(run, table, stages, jobs, stage=None, job_status="running")
        _publish_stage(self.run_id, self.job_id, first, "running")

    def completed(self, stage: str) -> None:
        now = _iso(_now())
        if stage not in self.done:
            self.done.append(stage)
        run = self._live_run()
        if run is not None:
            table, stages, jobs = self._table(run)
            existing = stages.get(stage)
            previous: dict[str, Any] = existing if isinstance(existing, dict) else {}
            stages[stage] = {
                "status": "succeeded",
                "started_at": previous.get("started_at") or self._cursor,
                "finished_at": now,
                "job_id": self.job_id,
            }
            # Expected stages before this one that never finished were skipped (not_run attacks, ...).
            if stage in self.expected:
                for earlier in self.expected[: self.expected.index(stage)]:
                    entry = stages.get(earlier)
                    if entry is None or (isinstance(entry, dict) and entry.get("status") in {"running", "queued"}):
                        stages[earlier] = {
                            "status": "skipped",
                            "started_at": (entry or {}).get("started_at") if isinstance(entry, dict) else None,
                            "finished_at": now,
                            "job_id": self.job_id,
                        }
            nxt = self._next_expected(stage)
            if nxt is not None and nxt not in stages:
                stages[nxt] = {"status": "running", "started_at": now, "finished_at": None, "job_id": self.job_id}
            self._store(run, table, stages, jobs, stage=stage, job_status="running")
        self._cursor = now
        _publish_stage(self.run_id, self.job_id, stage, "succeeded")
        if run is not None:
            nxt = self._next_expected(stage)
            if nxt is not None:
                _publish_stage(self.run_id, self.job_id, nxt, "running")

    def finish(self, record: CampaignRecord) -> None:
        """Close the table for a returned record: leftover expected stages are ``skipped``."""
        now = _iso(_now())
        run = self._live_run()
        if run is None:
            return
        table, stages, jobs = self._table(run)
        for stage in record.stages_done:
            if stage not in self.done:
                self.done.append(stage)
            if stage not in stages:
                stages[stage] = {"status": "succeeded", "started_at": None, "finished_at": now, "job_id": self.job_id}
        for name, entry in list(stages.items()):
            if isinstance(entry, dict) and entry.get("status") in {"running", "queued"}:
                stages[name] = {**entry, "status": "skipped", "finished_at": now}
        for name in self.expected:
            if name not in stages:
                stages[name] = {"status": "skipped", "started_at": None, "finished_at": now, "job_id": self.job_id}
        table["completeness"] = record.completeness
        table["error"] = record.error
        self._store(run, table, stages, jobs, stage=record.stage, job_status="running")

    def aborted(self, status: str, error: str, *, stages_done: list[str] | None = None) -> str | None:
        """Mark the open stage ``failed`` / ``timed_out`` / ``cancelled``; returns the stage named."""
        now = _iso(_now())
        for stage in stages_done or []:
            if stage not in self.done:
                self.done.append(stage)
        run = self._live_run()
        if run is None:
            return None
        table, stages, jobs = self._table(run)
        open_stage = self._open_stage(stages)
        if open_stage is not None:
            existing = stages.get(open_stage)
            entry: dict[str, Any] = existing if isinstance(existing, dict) else {}
            stages[open_stage] = {
                "status": status,
                "started_at": entry.get("started_at") or self._cursor,
                "finished_at": now,
                "job_id": self.job_id,
            }
        table["completeness"] = "partial"
        table["error"] = error
        self._store(run, table, stages, jobs, stage=open_stage, job_status="running")
        if open_stage is not None:
            _publish_stage(self.run_id, self.job_id, open_stage, status)
        return open_stage


# ---------------------------------------------------------------------------
# Audit emission (spec 5.11 / 10.5)
# ---------------------------------------------------------------------------


@dataclass
class _AuditEmitter:
    """Emits the worker's spec 10.5 vocabulary on the run chain through ``safety.authorize``.

    ``authorize`` always records ``success=True`` for a ``target=None`` event,
    so refused / failed steps go through the same writer with ``success=False``
    and the identical row shape (``allowlist_check="n/a"``). ``detail`` never
    carries text, bytes or secrets: ids, digests, counts and redacted settings.
    """

    writer: AuditWriter
    allowlist: list[str]
    job_id: str
    job_type: str
    run_id: str
    project_id: str
    requested_by: str | None
    emitted: list[tuple[str, bool]] = field(default_factory=list)

    @property
    def actor(self) -> str:
        return f"worker:{self.job_type}"

    def emit(self, action: str, detail: dict[str, Any], *, success: bool = True) -> None:
        from redsim.safety import authorize

        payload: dict[str, Any] = {
            "job_id": self.job_id, "job_type": self.job_type, "requested_by": self.requested_by, **detail,
        }
        if success:
            authorize(
                action, None, allowlist=self.allowlist, actor=self.actor, writer=self.writer,
                run_id=self.run_id, project_id=self.project_id, detail=payload,
            )
        else:
            payload.setdefault("actor", self.actor)
            self.writer.append(
                action=action, actor=self.actor, target=None, allowlist_check="n/a",
                override=False, success=False, detail=payload,
                run_id=self.run_id, project_id=self.project_id,
            )
        self.emitted.append((action, success))

    def has(self, action: str) -> bool:
        return any(a == action for a, _ok in self.emitted)


def _target_load_detail(config: CampaignConfig, target: Any) -> dict[str, Any]:
    """Non-secret ``model.load`` fields from the target row and the admission snapshot."""
    detail = getattr(target, "detail", None)
    detail = dict(detail) if isinstance(detail, dict) else {}
    manifest = detail.get("manifest")
    manifest = dict(manifest) if isinstance(manifest, dict) else {}
    validation = detail.get("validation")
    validation = dict(validation) if isinstance(validation, dict) else {}
    onnx = manifest.get("onnx")
    onnx = dict(onnx) if isinstance(onnx, dict) else {}
    value = str(getattr(target, "value", "") or "")
    agreement = (
        validation.get("onnx_torch_argmax_agreement")
        if validation.get("onnx_torch_argmax_agreement") is not None
        else manifest.get("onnx_torch_argmax_agreement", onnx.get("argmax_agreement"))
    )
    return {
        "target_id": config.target_id,
        "source": "bundled" if value.startswith("bundled") else "upload",
        "format": detail.get("format") or manifest.get("format"),
        "sha256": detail.get("sha256") or manifest.get("sha256"),
        "architecture_id": detail.get("architecture_id") or manifest.get("architecture_id"),
        "gradients": detail.get("gradients", manifest.get("gradients")),
        "onnx_torch_argmax_agreement": agreement,
        "modality": config.modality,
        "dataset_id": config.dataset_id,
        "dataset_revision": config.dataset_revision,
    }


def _attack_detail(config: CampaignConfig, attack_id: str) -> dict[str, Any]:
    return {
        "attack_id": attack_id,
        "norm": config.norm,
        "eps_grid": list(config.eps_grid),
        "reference_eps": config.reference_eps,
        "params": dict(config.attack_params.get(attack_id) or {}),
        "n_samples": config.n_samples,
        "seed": config.seed,
    }


def _not_run_reasons(record: CampaignRecord) -> dict[str, str]:
    """``attack_id -> reason`` for attacks the child recorded ``not_run`` (interpretation ``i.attack.not_run.<id>``)."""
    out: dict[str, str] = {}
    prefix = "i.attack.not_run."
    for item in record.interpretation:
        if item.id.startswith(prefix):
            out[item.id[len(prefix):]] = item.statement
    return out


# ---------------------------------------------------------------------------
# The Pythia narrative, in the parent (spec 10.8, 16.3)
# ---------------------------------------------------------------------------


def _narrative_limitation(status: str, model: str | None) -> str:
    if status == "ok":
        return (f"LLM narrative generated via Pythia ({model}): the rule outputs were rephrased for a technical "
                "reader; it adds no claim, number or recommendation (narrative_source='llm').")
    return f"LLM narrative: {status}; recommendations carry rule text only (narrative_source='rules')."


def _summary_text(record: CampaignRecord, sink: DatabaseArtifactSink) -> str:
    """The SHAP text summary (``ml.shap.summary_text``) the child wrote, else the same template recomputed here."""
    raw = sink.get(SHAP_SUMMARY_TEXT_NAME)
    if raw:
        return raw.decode("utf-8", errors="replace")
    from redsim.ml.explain.summary import text_summary

    reason = record.score_status.reason if record.score_status is not None else None
    return str(text_summary(
        record.measurements, record.observations, record.score,
        scoring_reason=reason, limitations=list(record.limitations), norm=record.config.norm,
    ))


def _org_id(session: Session, project_id: str) -> str | None:
    from redsim.db.models import Project

    project = session.get(Project, project_id)
    return getattr(project, "org_id", None) if project is not None else None


def _route_narrative_model(
    redsim_config: RedsimConfig, *, project_id: str, org_id: str | None, seed_model: str,
) -> tuple[str | None, str | None]:
    """``(model, skip_reason)`` from the router with the DB budget checker (spec 10.8 step 1)."""
    from redsim.llm.budget import DbBudgetChecker
    from redsim.llm.router import BudgetExceeded, ModelNotConfigured, route

    task_models = getattr(redsim_config, "task_models", None)
    if not isinstance(task_models, dict):
        task_models = {}
        redsim_config.task_models = task_models
    task_models.setdefault(NARRATIVE_TASK, seed_model)
    strict = bool(getattr(redsim_config, "llm_budget_strict", False))
    try:
        spec = route(NARRATIVE_TASK, redsim_config, project_id=project_id, org_id=org_id,
                     budget_checker=DbBudgetChecker())
    except BudgetExceeded as exc:
        return None, f"budget exceeded ({exc})"
    except ModelNotConfigured as exc:
        return None, f"not configured ({exc})"
    except Exception as exc:  # noqa: BLE001 - the budget store could not be read
        if strict:
            return None, f"budget could not be verified ({type(exc).__name__}); denied (llm_budget_strict)"
        logger.warning("LLM budget check unavailable (%s); routing without a budget gate", type(exc).__name__)
        try:
            spec = route(NARRATIVE_TASK, redsim_config, project_id=project_id, org_id=org_id)
        except ModelNotConfigured as exc2:
            return None, f"not configured ({exc2})"
    return spec.model, None


def _parent_narrative(
    ctx: Any, *, config: CampaignConfig, record: CampaignRecord, sink: DatabaseArtifactSink,
    redsim_config: RedsimConfig, allowed: bool = True,
) -> tuple[CampaignRecord, dict[str, Any]]:
    """Run the Pythia writer over the child's candidates; returns the updated record and the audit fields.

    Every path returns: a missing configuration, ``REDSIM_DISABLE_LLM=1``, an
    exhausted budget, an HTTP error, a guardrail block or a post-check rejection
    all leave the rule output standing with ``narrative_source="rules"`` and the
    reason in the record's limitations and on the ``harden.execute`` row.
    """
    from redsim.ml.campaign import NARRATIVE_DEFERRED_LIMITATION
    from redsim.ml.recommend import narrative as narrative_mod

    recs = list(record.recommendations)
    audit: dict[str, Any] = {
        "rules_fired": [r.id for r in recs],
        "n_candidates": len(recs),
        "llm_requested": bool(config.llm_narrative),
        "llm_used": False,
        "narrative_source": "rules",
        "skipped_reason": None,
        "prompt_sha256": None,
        "completion_sha256": None,
        # Token counts as usage.{prompt,completion}: the audit redactor blanks any key naming "token".
        "usage": {"prompt": None, "completion": None},
    }
    limitations = [item for item in record.limitations if item != NARRATIVE_DEFERRED_LIMITATION]

    def skipped(reason: str, *, note: bool = True) -> tuple[CampaignRecord, dict[str, Any]]:
        audit["skipped_reason"] = reason
        if note:
            sentence = _narrative_limitation(reason, None)
            if sentence not in limitations:
                limitations.append(sentence)
        logger.info("LLM narrative skipped for run %s: %s", record.run_id, reason)
        return record.model_copy(update={"limitations": limitations}), audit

    if not recs:
        return skipped("no recommendations to narrate", note=False)
    if not config.llm_narrative:
        # The child already recorded "No LLM narrative was requested".
        return skipped("not requested", note=False)
    if not allowed:
        return skipped("not attempted on a verify.replay job (only harden.recommend calls Pythia)")
    if _truthy(os.environ.get("REDSIM_DISABLE_LLM")):
        return skipped("disabled (REDSIM_DISABLE_LLM=1)")
    try:
        from redsim.llm.pythia import PythiaSettings

        settings = PythiaSettings.from_env()
    except Exception as exc:  # noqa: BLE001 - a malformed .env is "not configured", not a job failure
        settings = None
        logger.warning("Pythia settings unreadable: %s", type(exc).__name__)
    if settings is None:
        return skipped("not configured (PYTHIA_BASE_URL / PYTHIA_API_KEY / REDSIM_ML_LLM_MODEL)")
    org_id = _org_id(ctx.session, ctx.project_id)
    model, reason = _route_narrative_model(
        redsim_config, project_id=ctx.project_id, org_id=org_id, seed_model=settings.model,
    )
    if model is None or reason is not None:
        return skipped(reason or "not configured")
    settings = replace(settings, model=model)
    audit["llm"] = settings.redacted()
    audit["model"] = model
    try:
        summary_text = _summary_text(record, sink)
        outcome = narrative_mod.narrate(recs, summary_text, settings, config=redsim_config)
    except Exception as exc:  # noqa: BLE001 - nothing in the writer may fail the job
        logger.warning("LLM narrative failed in the parent: %s", type(exc).__name__, exc_info=True)
        return skipped(f"unavailable ({type(exc).__name__})")
    audit.update(outcome.audit_detail())
    # Prompt and completion are artifacts; only their digests travel on the audit row.
    if outcome.prompt is not None:
        sink.put(HARDEN_PROMPT_NAME, outcome.prompt.encode("utf-8"), "text/plain; charset=utf-8")
    if outcome.completion is not None:
        sink.put(HARDEN_COMPLETION_NAME, outcome.completion.encode("utf-8"), "text/plain; charset=utf-8")
    narrative_md = outcome.narrative_markdown()
    if narrative_md is not None:
        sink.put(HARDEN_NARRATIVE_NAME, narrative_md.encode("utf-8"), "text/markdown; charset=utf-8")
    if outcome.responded:
        # One LLMUsage row per metered call (spec 5.12); a transport failure consumed nothing.
        _record_llm_usage(ctx, org_id=org_id, model=model, outcome=outcome, audit=audit)
    sentence = _narrative_limitation(outcome.status, model)
    if sentence not in limitations:
        limitations.append(sentence)
    update: dict[str, Any] = {"limitations": limitations, "recommendations": outcome.recommendations}
    if outcome.ok and record.provenance is not None:
        nondeterminism = list(record.provenance.nondeterminism)
        note = "LLM narrative is nondeterministic (temperature=0.2); prompt and response hashes recorded"
        if note not in nondeterminism:
            nondeterminism.append(note)
        update["provenance"] = record.provenance.model_copy(update={
            "llm": outcome.provenance_llm(), "nondeterminism": nondeterminism,
        })
    return record.model_copy(update=update), audit


def _record_llm_usage(ctx: Any, *, org_id: str | None, model: str, outcome: Any, audit: dict[str, Any]) -> None:
    """One ``LLMUsage(task="ml.harden_narrative")`` row per Pythia call (spec 5.12); zero cost when unpriced."""
    from redsim.db.models import LLMUsage
    from redsim.llm import pricing

    prompt_tokens = int(outcome.prompt_tokens or 0)
    completion_tokens = int(outcome.completion_tokens or 0)
    try:
        cost = int(pricing.cost_cents(model, prompt_tokens, completion_tokens))
    except Exception:  # noqa: BLE001 - pricing is accounting, never evidence
        cost = 0
    rate_fn = getattr(pricing, "_static_rate", None)
    priced = bool(callable(rate_fn) and rate_fn(model) is not None)
    audit["cost_cents"] = cost
    if not priced and cost == 0:
        audit["unpriced_model"] = model
    ctx.session.add(LLMUsage(
        project_id=ctx.project_id, org_id=org_id, run_id=ctx.run_id, model=model,
        task=NARRATIVE_TASK, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        cost_cents=cost,
    ))
    ctx.session.flush()


# ---------------------------------------------------------------------------
# Finding projections: verify (spec 6.4, 16.4, 16.5) and follow-on merge (G-FOLLOW1)
# ---------------------------------------------------------------------------


def _cited(items: list[Any], known: set[str], attr: str) -> list[Any]:
    """Keep statements whose citations resolve to ``known`` ids (interpretation ids join progressively)."""
    kept: list[Any] = []
    for item in items:
        cites = list(getattr(item, attr, None) or [])
        if cites and any(c in known for c in cites):
            kept.append(item)
            known.add(item.id)
    return kept


def _merge_followon(ctx: Any, *, job: Any, record: CampaignRecord, sink: DatabaseArtifactSink) -> str | None:
    """Merge an ``explain.run`` / ``harden.recommend`` child record into the parent finding's ``ml`` block.

    Scoped to the finding's attack: the clean and control rows plus that attack's
    evasion rows, every observation (observations carry no attack id; the
    explainer emits them for the campaign), and the interpretation / candidates
    that cite that evidence. ``review`` and ``verify`` are untouched. Returns the
    finding id, or ``None`` when the job names none.
    """
    from redsim.db.models import Finding
    from redsim.ml.schema import MLFindingDetail

    finding_id = (job.detail or {}).get("finding_id")
    if not finding_id:
        return None
    finding = ctx.session.get(Finding, finding_id)
    if finding is None:
        raise RuntimeError("follow-on finding is missing")
    schema_blob = dict(finding.schema_blob or {})
    ml_detail = MLFindingDetail.model_validate(schema_blob.get("ml") or {})
    attack_id = ml_detail.attack_id
    measurements = [
        m for m in record.measurements
        if m.attack_id == attack_id or m.family in ("clean", "control")
    ]
    observations = list(record.observations)
    # Citation anchors mirror ``project_campaign_findings``: this attack's evasion rows and the
    # observations. Clean and control rows travel on every finding and would otherwise pull in
    # statements about another attack.
    known = {m.id for m in measurements if m.attack_id == attack_id} | {o.id for o in observations}
    interpretation = _cited(list(record.interpretation), known, "basis")
    recommendations = _cited(list(record.recommendations), known, "triggered_by")
    artifacts = dict(ml_detail.artifacts)
    for obs in observations:
        artifacts.update(obs.artifacts)
    if "run_record.json" in sink.ids:
        artifacts[f"{job.type}:run_record"] = sink.ids["run_record.json"]
    update: dict[str, Any] = {
        "measurements": measurements or ml_detail.measurements,
        "observations": observations or ml_detail.observations,
        "interpretation": interpretation or ml_detail.interpretation,
        "limitations": list(record.limitations) or ml_detail.limitations,
        "artifacts": artifacts,
    }
    if job.type == "harden.recommend" or recommendations:
        update["recommendations"] = recommendations
    merged = ml_detail.model_copy(update=update)
    schema_blob["ml"] = MLFindingDetail.model_validate(merged.model_dump(mode="json")).model_dump(mode="json")
    schema_blob["updated_at"] = _now().isoformat()
    finding.schema_blob = schema_blob
    finding.updated_at = _now()
    ctx.session.flush()
    return str(finding_id)


def _verify_outcome(record: CampaignRecord, attack_id: str) -> tuple[str, str | None]:
    """``(outcome, inconclusive_reason)`` per spec 6.4 from the verify record's measurements and completeness."""
    from redsim.ml.scoring import finding_inputs

    if record.status != "succeeded":
        return "inconclusive", record.error or f"verify run {record.status}"
    if record.score is None or record.score.completeness != "complete":
        missing = "; ".join(record.score.missing) if record.score is not None else (
            record.score_status.reason if record.score_status is not None else "score unavailable")
        return "inconclusive", f"verify score is partial ({missing})"
    inputs = finding_inputs(record.config, record.measurements, attack_id)
    if not inputs.denominator_ok:
        return "inconclusive", "clean-correct denominator too small at these settings"
    return ("still_vulnerable" if inputs.crosses_threshold else "verified"), None


def _project_verify(
    ctx: Any, *, job: Any, record: CampaignRecord, baseline_run_id: str | None, emitter: _AuditEmitter,
    sink: DatabaseArtifactSink,
) -> dict[str, Any]:
    """Write the verify outcome onto the baseline finding (spec 6.4, 16.4, 16.5) and emit ``verify.execute``.

    A verify whose defense had kind ``training`` also registers the derived model the child produced as a
    new Target (``ml_model_artifact``, source ``derived``, ``MLModelManifest.derived_from`` lineage) through
    the register-then-validate path (ATTACKS_HARDEN-13); the derived digest and the training budget are named
    on the ``verify.execute`` row, in the remediation summary and beside the ``MeasuredDelta`` (ATTACKS_HARDEN-18).
    Every verify appends a :class:`FindingVerify` (with ``settings_hash`` and ``baseline_run_id``) to
    ``retests``, keeping ``verify`` the latest (REVIEW_REPORTS-08).
    """
    from redsim.db.models import Finding, RemediationAttempt
    from redsim.ml.schema import FindingVerify, MeasuredDelta, MLFindingDetail
    from redsim.services.ml_campaigns import recommendation_defense_ids
    from redsim.workers.tasks.verify import _STATE_MAP

    detail = dict(job.detail or {})
    finding = ctx.session.get(Finding, detail.get("finding_id"))
    if finding is None:
        raise RuntimeError("verify finding is missing")
    schema_blob = dict(finding.schema_blob or {})
    ml_detail = MLFindingDetail.model_validate(schema_blob.get("ml") or {})
    defense = record.config.defense
    if defense is None:
        raise RuntimeError("verify campaign carries no defense")
    outcome, reason = _verify_outcome(record, ml_detail.attack_id)
    score_delta = record.score.delta if record.score is not None else None
    # ATTACKS_HARDEN-13: register the derived model a training defense produced (a no-op for a
    # preprocessing defense or when the child left no derived weights).
    derived = _register_derived_target(ctx, record=record, sink=sink, emitter=emitter)
    # REVIEW_REPORTS-08: verify is the latest retest and every verify is appended to the history.
    ml_detail.verify = FindingVerify(run_id=ctx.run_id, defense=defense, outcome=outcome, delta=score_delta,
                                     settings_hash=record.settings_hash, baseline_run_id=baseline_run_id)
    ml_detail.retests = [*ml_detail.retests, ml_detail.verify]

    measured_for: list[str] = []
    if (
        outcome != "inconclusive"
        and score_delta is not None
        and record.settings_hash is not None
        and baseline_run_id
    ):
        measured = MeasuredDelta(
            verify_run_id=ctx.run_id, baseline_run_id=str(baseline_run_id), defense=defense,
            delta_mri=score_delta.delta, delta_subscores=score_delta.delta_subscores,
            delta_acc_clean=score_delta.delta_acc_clean, settings_hash=record.settings_hash,
            measured_at=_now(),
        )
        named = str(detail.get("recommendation_id") or "") or None
        updated = []
        for recommendation in ml_detail.recommendations:
            names_defense = defense.id in recommendation_defense_ids(recommendation)
            is_named = named is None or recommendation.id == named
            if names_defense and is_named:
                measured_for.append(recommendation.id)
                updated.append(recommendation.model_copy(update={"validation": "measured", "measured": measured}))
            else:
                updated.append(recommendation)
        ml_detail.recommendations = updated
        if named is not None and named not in measured_for:
            logger.warning("verify run %s: recommendation %r does not name defense %r; no delta attached",
                           ctx.run_id, named, defense.id)

    validation_state = _STATE_MAP.get(outcome, "inconclusive")
    status = VERIFY_STATUS_MAP[outcome]
    schema_blob["ml"] = MLFindingDetail.model_validate(ml_detail.model_dump(mode="json")).model_dump(mode="json")
    schema_blob["updated_at"] = _now().isoformat()
    schema_blob["status"] = status
    finding.schema_blob = schema_blob
    finding.validation_state = validation_state
    finding.status = status
    finding.validated_at = _now()
    finding.updated_at = _now()

    # ATTACKS_HARDEN-18: the derived model's digest and training budget are the changed variable of a
    # training verify; they travel on the summary (RemediationAttempt), the audit row and beside the
    # MeasuredDelta so the report and compare surfaces can name them without re-reading the campaign.
    derived_detail: dict[str, Any] = {}
    if derived is not None:
        derived_detail = {
            "derived_target_id": derived.get("derived_target_id"),
            "derived_sha256": derived.get("derived_sha256"),
            "parent_target_id": derived.get("parent_target_id"),
            "parent_sha256": derived.get("parent_sha256"),
            "training_budget": derived.get("training_budget"),
        }
    summary = {
        "verify_run_id": ctx.run_id, "baseline_run_id": baseline_run_id, "defense": defense.model_dump(mode="json"),
        "outcome": outcome, "validation_state": validation_state, "status": status,
        "delta_mri": score_delta.delta if score_delta is not None else None,
        "inconclusive_reason": reason, "measured_for": measured_for,
        **({"derived": derived_detail} if derived_detail else {}),
    }
    # Spec 10.2: append_remediation_log(finding_id, action="ml.verify.<defense>", result=<json>, success=<bool>).
    # The finding belongs to the baseline run, so the row is written directly rather than through the
    # verify run's RunState facade (which resolves findings within its own run only).
    ctx.session.add(RemediationAttempt(
        finding_id=finding.id, project_id=finding.project_id, action=f"ml.verify.{defense.id}",
        success=outcome == "verified", detail={"result": json.dumps(summary, sort_keys=True, default=str)},
    ))
    ctx.session.flush()
    emitter.emit("verify.execute", {
        "finding_id": finding.id,
        "defense": defense.model_dump(mode="json"),
        "outcome": outcome,
        "validation_state": validation_state,
        "finding_status": status,
        "delta_mri": score_delta.delta if score_delta is not None else None,
        "delta_subscores": score_delta.delta_subscores.model_dump() if score_delta is not None else None,
        "delta_acc_clean": score_delta.delta_acc_clean.model_dump() if score_delta is not None else None,
        "measured_for": measured_for,
        "inconclusive_reason": reason,
        "baseline_run_id": baseline_run_id,
        **derived_detail,
    }, success=outcome != "inconclusive")
    return summary


def _verify_inconclusive_on_failure(ctx: Any, *, job: Any, error: str) -> None:
    """A verify job that did not return a record leaves its finding ``inconclusive`` / ``open`` (spec 6.4)."""
    from redsim.db.models import Finding
    from redsim.ml.schema import FindingVerify, MLFindingDetail
    from redsim.workers.tasks.verify import _STATE_MAP

    detail = dict(job.detail or {})
    finding = ctx.session.get(Finding, detail.get("finding_id"))
    if finding is None:
        return
    schema_blob = dict(finding.schema_blob or {})
    try:
        ml_detail = MLFindingDetail.model_validate(schema_blob.get("ml") or {})
        config = dict(detail.get("campaign_config") or {})
        defense = config.get("defense")
        if isinstance(defense, dict) and defense.get("id"):
            from redsim.ml.schema import DefenseConfig

            # REVIEW_REPORTS-08: a failed retest is still a retest; append it and keep it the latest.
            ml_detail.verify = FindingVerify(
                run_id=ctx.run_id, defense=DefenseConfig.model_validate(defense), outcome="inconclusive",
                baseline_run_id=detail.get("baseline_run_id"),
            )
            ml_detail.retests = [*ml_detail.retests, ml_detail.verify]
            schema_blob["ml"] = ml_detail.model_dump(mode="json")
    except Exception:  # noqa: BLE001 - the state write below is what matters
        logger.debug("verify failure: could not stamp FindingVerify", exc_info=True)
    schema_blob["updated_at"] = _now().isoformat()
    schema_blob["status"] = VERIFY_STATUS_MAP["inconclusive"]
    finding.schema_blob = schema_blob
    finding.validation_state = _STATE_MAP["inconclusive"]
    finding.status = VERIFY_STATUS_MAP["inconclusive"]
    finding.validated_at = _now()
    finding.updated_at = _now()
    logger.warning("verify run %s failed (%s); finding %s left inconclusive/open", ctx.run_id, error, finding.id)


# ---------------------------------------------------------------------------
# Black-box endpoint jobs (ENDPOINT-05): broker in the worker parent, credential at run time
# ---------------------------------------------------------------------------


def _is_endpoint_target(target: Any) -> bool:
    """True when the campaign target is a registered black-box inference endpoint (spec 9.1 rule 4)."""
    return str(getattr(target, "kind", "") or "") == "ml_model_endpoint"


_ENDPOINT_URL_SCHEMES = ("http://", "https://")


def _stored_endpoint_url(target: Any, detail: dict[str, Any]) -> str | None:
    """The request URL as endpoint-admission stores it: ``Target.value`` (normalised URL), detail host-only.

    ``services.ml_models.admit_endpoint_registration`` / ``api/v1/models`` write the normalised URL as
    ``Target.value`` and keep every projection, manifest and audit detail at ``url_host`` (D3), so the
    value is the primary location. Rows written before that convention (``detail.endpoint_url``,
    ``detail.url``, ``detail.endpoint.url``, ``detail.manifest.endpoint.url``) are still read.
    """
    value = getattr(target, "value", None)
    if isinstance(value, str) and value.startswith(_ENDPOINT_URL_SCHEMES):
        return value
    manifest = detail.get("manifest")
    manifest = dict(manifest) if isinstance(manifest, dict) else {}
    candidates: list[Any] = [detail.get("endpoint_url"), detail.get("url")]
    for block in (detail.get("endpoint"), manifest.get("endpoint")):
        if isinstance(block, dict):
            candidates.append(block.get("url"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.startswith(_ENDPOINT_URL_SCHEMES):
            return candidate
    return None


def _endpoint_request_block(target: Any, config: CampaignConfig) -> dict[str, Any]:
    """The ``target_endpoint`` block ``run_campaign_sandboxed`` hands the worker-parent ``PredictBroker``.

    The URL is read the way endpoint-admission stores it (:func:`_stored_endpoint_url`); the binding
    (``manifest``: modality, dataset, classes, shape, features) and the request caps (``batch_rows``,
    ``timeout_s``) come from ``services.ml_models.endpoint_request_block``, the same helper the
    validate task uses, so the two workers cannot drift. The campaign's frozen config then fixes the
    modality and the dataset binding: admission validated them against the registration and they are
    what the child binds and the broker encodes under (``endpoint-v1`` ``input_format`` /
    ``input_shape``). No credential is read here: only the ``auth_profile_id`` travels, and the secret is
    resolved separately at run time (:func:`_resolve_endpoint_auth`).
    """
    from redsim.services.ml_models import endpoint_request_block

    detail = getattr(target, "detail", None)
    detail = dict(detail) if isinstance(detail, dict) else {}
    url = _stored_endpoint_url(target, detail)
    if not url:
        raise RuntimeError(
            "endpoint target carries no stored request URL (Target.value / detail.endpoint.url); "
            "the worker cannot reach the endpoint without faking a result")
    block = endpoint_request_block(url, detail)
    manifest = dict(block.get("manifest") or {})
    manifest["modality"] = config.modality
    manifest["dataset_id"] = config.dataset_id
    manifest["dataset_split"] = config.dataset_split
    if config.dataset_revision:
        manifest["dataset_revision"] = config.dataset_revision
    block["manifest"] = {k: v for k, v in manifest.items() if v is not None}
    block["auth_profile_id"] = block.get("auth_profile_id") or None
    if "limits" not in block:
        # Per-registration caps recorded beside the endpoint spec on older rows.
        raw_endpoint = detail.get("endpoint")
        raw_manifest = detail.get("manifest")
        detail_endpoint: dict[str, Any] = raw_endpoint if isinstance(raw_endpoint, dict) else {}
        registered: dict[str, Any] = raw_manifest if isinstance(raw_manifest, dict) else {}
        limits = detail_endpoint.get("limits") or registered.get("endpoint_limits")
        if isinstance(limits, dict) and limits:
            block["limits"] = dict(limits)
    return block


def _resolve_endpoint_auth(session: Session, auth_profile_id: str | None) -> dict[str, Any]:
    """The decrypted credential for the endpoint, resolved from the AuthProfile vault at run time.

    Returns the ``resolve_auth_for_scan`` shape (``{"kind", "config", "secret"}``); the secret reaches only
    the worker-parent broker (in memory), never the child, an audit row, a job detail or a log line.
    """
    if not auth_profile_id:
        raise RuntimeError("endpoint target names no auth_profile_id; cannot resolve a credential")
    from redsim.services.auth_profiles import resolve_auth_for_scan

    return resolve_auth_for_scan(session, str(auth_profile_id))


def _endpoint_broker_summary(record: CampaignRecord) -> dict[str, Any] | None:
    """The parent-side broker tally (rows, requests, per-purpose split, budget) for an endpoint run.

    Read from ``record.provenance.model_manifest['endpoint_broker']`` (attached by ``redsim.ml.sandbox``
    after the child exits). Carries counts, the budget the job stayed under and the response fingerprint;
    never a URL or a credential.
    """
    provenance = record.provenance
    if provenance is None:
        return None
    broker = provenance.model_manifest.get("endpoint_broker")
    if not isinstance(broker, dict):
        return None
    return {
        "rows": broker.get("rows"),
        "requests": broker.get("requests"),
        "by_purpose": broker.get("by_purpose"),
        "budget": broker.get("limits"),
        "rate_limit_wait_s": broker.get("rate_limit_wait_s"),
        "fingerprint_sha256": broker.get("fingerprint_sha256"),
    }


# ---------------------------------------------------------------------------
# Derived-model registration for a training verify (ATTACKS_HARDEN-13)
# ---------------------------------------------------------------------------


def _register_derived_target(
    ctx: Any, *, record: CampaignRecord, sink: DatabaseArtifactSink, emitter: _AuditEmitter,
) -> dict[str, Any] | None:
    """Register the derived model a training verify produced as a new Target (ATTACKS_HARDEN-13).

    A ``kind: training`` defense (adversarial fine-tuning, distillation) re-trains a derived copy in the
    verify child; the child writes ``derived_model/weights.pt`` and ``derived_model/training_report.json``.
    This registers those weights as a new ``ml_model_artifact`` Target with source ``derived`` and
    ``MLModelManifest.derived_from = DerivedFrom(parent_target_id, parent_sha256, defense_id, training_budget)``
    through the standard register-then-validate path: the ``model.register`` audit row precedes the Target,
    the validate Run/Job and the enqueue. Returns the lineage fields, or ``None`` when the defense was not a
    training defense or the child left no derived weights (never faked). Never fails the verify job.
    """
    provenance = record.provenance
    defense_prov = provenance.defense if provenance is not None else None
    if not isinstance(defense_prov, dict) or defense_prov.get("kind") != "training":
        return None
    if defense_prov.get("status") == "unavailable":
        return None
    weights_name = "derived_model/weights.pt"
    weights_id = sink.ids.get(weights_name)
    if weights_id is None:
        logger.warning("verify run %s: training defense left no %r artifact; derived target not registered",
                       ctx.run_id, weights_name)
        return None
    from redsim.db.models import Artifact, Job, Run, Target

    weights_row = ctx.session.get(Artifact, weights_id)
    if weights_row is None:
        logger.warning("verify run %s: derived weights artifact %s vanished; not registered", ctx.run_id, weights_id)
        return None
    report = defense_prov.get("training_report")
    report = dict(report) if isinstance(report, dict) else {}
    derived_state_sha = str(defense_prov.get("derived_sha256") or report.get("weights_sha256") or "")
    blob_sha = str(getattr(weights_row, "sha256", "") or "")
    size_bytes = int(getattr(weights_row, "size_bytes", 0) or 0)
    location = str(getattr(weights_row, "location", "") or "")
    parent_target_id = str(report.get("target_id") or record.config.target_id)
    parent_sha256 = str(defense_prov.get("parent_sha256") or report.get("parent_manifest_sha256")
                        or report.get("parent_weights_sha256") or "")
    defense_id = str(defense_prov.get("id") or (record.config.defense.id if record.config.defense else "") or "")
    training_budget: dict[str, Any] = {
        k: report.get(k) for k in (
            "epochs_requested", "epochs_run", "n_train", "wall_budget_s", "wall_time_s",
            "budget_exhausted", "backbone_frozen")
        if report.get(k) is not None
    }
    try:
        from redsim.ml.schema import DerivedFrom

        derived_from = DerivedFrom(
            parent_target_id=parent_target_id, parent_sha256=parent_sha256 or blob_sha or derived_state_sha,
            defense_id=defense_id, training_budget=training_budget,
        ).model_dump(mode="json")
    except Exception:  # noqa: BLE001 - a lineage we cannot form is not registered, never faked
        logger.warning("verify run %s: could not build DerivedFrom lineage; derived target not registered",
                       ctx.run_id, exc_info=True)
        return None

    parent = ctx.session.get(Target, parent_target_id)
    parent_detail = dict(getattr(parent, "detail", None) or {}) if parent is not None else {}
    parent_manifest = parent_detail.get("manifest")
    if not isinstance(parent_manifest, dict):
        parent_manifest = {k: v for k, v in parent_detail.items()
                           if k not in {"manifest", "validation", "blob", "status"}}
    manifest: dict[str, Any] = {
        **parent_manifest,
        "sha256": blob_sha or derived_state_sha,
        "size_bytes": size_bytes,
        "status": "registered", "refusal_reason": None, "bundled": False, "source_url": None,
        "derived_from": derived_from,
    }
    try:  # a fully-valid MLModelManifest when the parent carried enough; else a raw projection carrying lineage
        from redsim.ml.schema import MLModelManifest

        manifest = MLModelManifest.model_validate(manifest).model_dump(mode="json")
    except Exception:  # noqa: BLE001 - derived_from is present either way; validity is not load-bearing here
        logger.info("verify run %s: derived manifest kept as a raw projection (not MLModelManifest-valid)",
                    ctx.run_id, exc_info=True)

    derived_target_id = f"derived-{uuid4().hex}"
    validate_run_id = f"run-{uuid4().hex[:12]}"
    validate_job_id = f"job-{uuid4().hex[:12]}"
    detail: dict[str, Any] = {
        **{k: v for k, v in parent_detail.items() if k not in {"blob", "validation", "registered_at"}},
        "source": "derived",
        "status": "validating",
        "manifest": manifest,
        "derived_from": derived_from,
        "blob": {"key": location, "location": location, "sha256": blob_sha, "size_bytes": size_bytes},
        "validation": {"ingest_job_id": validate_job_id, "ingest_run_id": validate_run_id, "source": "derived"},
        "registered_by": emitter.actor,
    }
    target = Target(id=derived_target_id, project_id=ctx.project_id, kind="ml_model_artifact",
                    value=location, verified=True)
    target.detail = detail
    ctx.session.add(target)
    ctx.session.flush()
    ctx.session.add(Run(id=validate_run_id, project_id=ctx.project_id, target_id=derived_target_id,
                        mode="worker", status="queued", scanner="ml.ingest", created_by=emitter.actor,
                        stage_table={"stage": None, "stages_done": [], "jobs": {}}))
    ctx.session.flush()
    ctx.session.add(Job(id=validate_job_id, run_id=validate_run_id, project_id=ctx.project_id,
                        type="model.validate", status="queued", created_by=emitter.actor,
                        detail={"target_id": derived_target_id}))
    ctx.session.flush()
    # Spec 9.3 step 4: the chained ``model.register`` precedes the enqueue. It lands on the validate run's
    # own chain (that run carries model.validate + job.complete), never the verify run's chain. Ids and
    # digests only; no credential and no weights bytes.
    from redsim.safety import authorize

    authorize(
        "model.register", None, allowlist=emitter.allowlist, actor=emitter.actor, writer=emitter.writer,
        run_id=validate_run_id, project_id=ctx.project_id,
        detail={
            "actor": emitter.actor, "target_id": derived_target_id, "kind": "ml_model_artifact",
            "source": "derived", "parent_target_id": parent_target_id, "parent_sha256": parent_sha256 or None,
            "defense_id": defense_id, "derived_sha256": derived_state_sha or None, "sha256": blob_sha or None,
            "size_bytes": size_bytes, "training_budget": training_budget, "verify_run_id": ctx.run_id,
            "weights_artifact_id": weights_id,
        },
    )
    ctx.session.commit()
    enqueued = False
    try:
        from redsim.workers.tasks.ml_model import ml_model_validate

        queued = ml_model_validate.delay(validate_job_id)
        live = ctx.session.get(Job, validate_job_id)
        if live is not None:
            live.celery_task_id = str(queued.id)
        enqueued = True
    except Exception:  # noqa: BLE001 - the durable queued Job survives a broker outage; the reaper picks it up
        logger.warning("derived-target validation enqueue failed for job %s", validate_job_id, exc_info=True)
    logger.info("registered derived target %s from verify run %s (defense %s, derived sha256 %s)",
                derived_target_id, ctx.run_id, defense_id, derived_state_sha[:12])
    return {
        "derived_target_id": derived_target_id, "derived_sha256": derived_state_sha or None,
        "parent_target_id": parent_target_id, "parent_sha256": parent_sha256 or None,
        "defense_id": defense_id, "training_budget": training_budget,
        "validate_run_id": validate_run_id, "validate_job_id": validate_job_id, "enqueued": enqueued,
    }


# ---------------------------------------------------------------------------
# The task
# ---------------------------------------------------------------------------


def _load_baseline_record(ctx: Any, baseline_run_id: str) -> CampaignRecord:
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.ml.schema import CampaignRecord

    baseline_artifact = ctx.session.execute(select(Artifact).where(
        Artifact.run_id == baseline_run_id,
        Artifact.kind == "ml.run_record",
    ).order_by(Artifact.created_at.desc())).scalars().first()
    if baseline_artifact is None:
        raise RuntimeError("verify baseline campaign record is missing")
    baseline_bytes = ctx.blob_store.get(str(baseline_artifact.location))
    if isinstance(baseline_bytes, str):
        baseline_bytes = baseline_bytes.encode("utf-8")
    if hashlib.sha256(baseline_bytes).hexdigest() != baseline_artifact.sha256:
        raise RuntimeError("verify baseline ml.run_record digest mismatch")
    baseline_record = CampaignRecord.model_validate_json(baseline_bytes)
    if baseline_record.score is None:
        raise RuntimeError("verify baseline score is unavailable")
    return baseline_record


def _apply_verify_baseline(record: CampaignRecord, baseline_record: CampaignRecord, *,
                           baseline_run_id: str) -> CampaignRecord:
    """Identity check against the baseline, then the delta (or its unavailability) on the record."""
    from redsim.ml.schema import CampaignRecord

    baseline_provenance = baseline_record.provenance
    record_provenance = record.provenance
    mismatch = (
        baseline_provenance is None
        or record_provenance is None
        or baseline_provenance.model_sha256 != record_provenance.model_sha256
        or baseline_provenance.sample_indices_sha256 != record_provenance.sample_indices_sha256
        or baseline_record.settings_hash != record.settings_hash
    )
    if mismatch:
        failed = record.model_dump(mode="json")
        failed.update({
            "status": "failed",
            "error": "verify identity mismatch: model, sample, or settings changed",
            "score": None,
            "score_status": {"state": "unavailable", "reason": "verify identity mismatch"},
            "completeness": "partial",
            "missing": ["verify model, sample, or settings identity mismatch"],
        })
        return CampaignRecord.model_validate(failed)
    # A partial score on either side (mri is None) or an incompatible pair leaves the delta
    # unavailable, recorded in the run's limitations. The verification outcome does not need it.
    return _attach_verify_delta(record, baseline_record, baseline_run_id=baseline_run_id)


def _emit_record_audit(
    emitter: _AuditEmitter, *, config: CampaignConfig, record: CampaignRecord, sink: DatabaseArtifactSink,
    load_detail: dict[str, Any], harden_audit: dict[str, Any] | None,
    endpoint_summary: dict[str, Any] | None = None,
) -> None:
    """The spec 10.5 rows a returned record justifies, in order, skipping any already emitted live.

    ``endpoint_summary`` (ENDPOINT-05, -08) is the parent-side broker tally for a black-box endpoint job
    (rows, requests, per-purpose split and the per-job budget). It is merged onto the ``attack.execute``
    and ``campaign.score`` rows so the query counts and the budget the run stayed under travel with the
    trail; it never carries a URL or a credential.
    """
    endpoint_extra = {"endpoint": endpoint_summary} if endpoint_summary else {}
    provenance = record.provenance
    versions = dict(provenance.model_manifest.get("library_versions") or {}) if provenance is not None else {}
    if not emitter.has("model.load"):
        loaded = "load_target" in record.stages_done
        error_class = _error_class(record.error)
        emitter.emit("model.load", {
            **load_detail,
            "sha256": (provenance.model_sha256 if provenance is not None and provenance.model_sha256
                       else load_detail.get("sha256")),
            "library_versions": versions,
            "reason": None if loaded else (record.error or "load_target did not complete"),
            "error_class": None if loaded else error_class,
        }, success=loaded)
    not_run = _not_run_reasons(record)
    executed = {m.attack_id for m in record.measurements if m.family == "evasion" and m.attack_id}
    for attack_id in config.attack_ids:
        action = f"attack.execute.{attack_id}"
        if attack_id in not_run:
            emitter.emit(action, {**_attack_detail(config, attack_id), "not_run": not_run[attack_id],
                                  **endpoint_extra}, success=False)
        elif not emitter.has(action):
            emitter.emit(action, {**_attack_detail(config, attack_id), "executed": attack_id in executed,
                                  **endpoint_extra}, success=attack_id in executed)
    if "explain" in record.stages_done:
        digests = sorted({d for o in record.observations for d in o.artifact_sha256.values()})
        emitter.emit("explain.execute", {
            "n_observations": len(record.observations),
            "explain_k": config.explain_k,
            "artifact_ids": sorted({a for o in record.observations for a in o.artifacts.values()})[:64],
            "artifact_sha256": digests[:64],
            "expl_shift": {
                m.attack_id: {"mean": m.expl_shift_mean, "n": m.expl_shift_n}
                for m in record.measurements
                if m.family == "evasion" and m.expl_shift_mean is not None and m.attack_id
            },
        }, success=bool(record.observations) or not any(
            lim.startswith("Explain stage unavailable for") for lim in record.limitations))
    if record.score is not None:
        emitter.emit("campaign.score", {
            "mri": record.score.mri,
            "grade": record.score.grade,
            "completeness": record.score.completeness,
            "missing": list(record.score.missing),
            "settings_hash": record.score.settings_hash,
            "scoring_version": record.score.scoring_version,
            "score_sha256": sink._hashes.get("score.json"),
            "delta_mri": record.score.delta.delta if record.score.delta is not None else None,
            **endpoint_extra,
        })
    if harden_audit is not None and ("recommend" in record.stages_done or record.recommendations):
        emitter.emit("harden.execute", dict(harden_audit))


@app.task(name="redsim.ml_campaign_run", bind=True, max_retries=2)
def ml_campaign_run(self: Task, job_id: str) -> dict[str, Any]:
    """Validate frozen input, run the pure campaign in the sandbox, and persist projections."""
    from redsim.config import load_config
    from redsim.db.models import Job, Run, Target
    from redsim.ml.errors import EnvelopeInvalid, SandboxKilled, SandboxTimeout
    from redsim.ml.sandbox import run_campaign_sandboxed
    from redsim.ml.schema import CampaignConfig
    from redsim.services.ml_campaigns import persist_campaign_record
    from redsim.workers.bootstrap import task_context
    from redsim.workers.tasks.capacity import deferred_continuation

    with deferred_continuation(job_id), task_context(job_id, task=self) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        audit_writer = ctx.audit_writer
        assert audit_writer is not None
        job = ctx.session.get(Job, job_id)
        if job is None:
            raise RuntimeError(f"job {job_id} disappeared")
        snapshot = dict((job.detail or {}).get("campaign_config") or {})
        config = CampaignConfig.model_validate(snapshot)
        run = ctx.session.get(Run, ctx.run_id)
        if run is None or config.target_id != run.target_id:
            raise RuntimeError("campaign target differs from the admitted Run target")
        target = ctx.session.get(Target, config.target_id)
        if target is None or target.project_id != ctx.project_id:
            raise RuntimeError("campaign target is absent or belongs to another project")
        target_detail = getattr(target, "detail", None) or {}
        target_status = (target_detail.get("status")
                         if isinstance(target_detail, dict) else None)
        if target_status is not None and target_status != "available":
            raise RuntimeError(
                f"campaign target is not available (status={target_status!r})"
            )
        redsim_config = load_config()
        emitter = _AuditEmitter(
            writer=audit_writer, allowlist=list(redsim_config.target_allowlist), job_id=job_id,
            job_type=str(job.type), run_id=ctx.run_id, project_id=ctx.project_id,
            requested_by=job.created_by,
        )
        load_detail = _target_load_detail(config, target)
        is_endpoint = _is_endpoint_target(target)
        if is_endpoint:
            load_detail["source"] = "endpoint"
        sink = DatabaseArtifactSink(
            ctx.session, ctx.blob_store,
            run_id=ctx.run_id, project_id=ctx.project_id,
        )
        tracker = _StageTracker(
            ctx.session, run_id=ctx.run_id, job_id=job_id, job_type=str(job.type), config=config,
        )
        tracker.begin()

        def on_stage(stage: str) -> None:
            tracker.completed(stage)
            # Live rows: model.load once the child loaded the model, one attack.execute.<id> per
            # attack as its stage completes with the executed configuration (a not_run attack has
            # no stage and gets its refused row from the record once the child returns). A
            # defense_apply stage (training defense) carries no row of its own: the derived model
            # and its training record are artifacts and Provenance.defense on the returned record.
            if stage == "load_target" and not emitter.has("model.load"):
                emitter.emit("model.load", dict(load_detail), success=True)
            # An endpoint job defers its attack.execute rows to the post-record pass so the broker's
            # query counts and budget (available only once the child has exited) travel on them.
            if is_endpoint:
                return
            if stage == "attack":
                for attack_id in config.attack_ids:
                    action = f"attack.execute.{attack_id}"
                    if not emitter.has(action):
                        emitter.emit(action, _attack_detail(config, attack_id))
            elif stage.startswith("attack:"):
                attack_id = stage.split(":", 1)[1]
                action = f"attack.execute.{attack_id}"
                if attack_id in config.attack_ids and not emitter.has(action):
                    emitter.emit(action, _attack_detail(config, attack_id))

        from sqlalchemy import MetaData, Table

        campaign_table = Table(
            "ml_campaigns", MetaData(), autoload_with=ctx.session.get_bind(),
        )
        campaign_row = ctx.session.execute(
            campaign_table.select().where(campaign_table.c.run_id == ctx.run_id)
        ).mappings().one()
        baseline_run_id = campaign_row.get("baseline_run_id")
        parent_run_id = campaign_row.get("parent_run_id")
        is_verify = job.type == "verify.replay"

        # ENDPOINT-05: resolve the endpoint request URL and the AuthProfile credential in the worker
        # parent, at run time. ``run_campaign_sandboxed`` starts the ``PredictBroker`` here (worker
        # parent), hands the child only the socket path, and stops the broker in its ``finally``. The
        # secret reaches the broker in memory only; it never enters the request, an audit row or a log.
        endpoint_request: dict[str, Any] | None = None
        endpoint_auth: dict[str, Any] | None = None
        endpoint_summary: dict[str, Any] | None = None
        if is_endpoint:
            endpoint_request = _endpoint_request_block(target, config)
            endpoint_auth = _resolve_endpoint_auth(ctx.session, endpoint_request.get("auth_profile_id"))

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as cancellation_session:
                live_job = cancellation_session.get(Job, job_id)
                live_run = cancellation_session.get(Run, ctx.run_id)
                return (
                    live_job is None
                    or live_run is None
                    or live_job.status == "cancelled"
                    or live_run.status == "cancelled"
                )

        def complete(status: str, *, success: bool, record: CampaignRecord | None,
                     error_class: str | None = None, n_findings: int = 0) -> None:
            emitter.emit("job.complete", {
                "status": status,
                "n_findings": n_findings,
                "n_artifacts": len(sink.ids),
                "n_measurements": len(record.measurements) if record is not None else 0,
                "n_observations": len(record.observations) if record is not None else 0,
                "stages_done": list(record.stages_done) if record is not None else list(tracker.done),
                "completeness": record.completeness if record is not None else "partial",
                "envelope_sha256": sink._hashes.get("run_record.json"),
                "error_class": error_class,
                **({"endpoint": endpoint_summary} if endpoint_summary else {}),
            }, success=success)

        try:
            if is_endpoint:
                assert endpoint_request is not None
                # The broker (and the only outbound HTTP in the worker) is started inside
                # run_campaign_sandboxed, in this worker parent, and stopped in its finally block.
                record = run_campaign_sandboxed(
                    config,
                    sink,
                    on_stage=on_stage,
                    is_cancelled=is_cancelled,
                    baseline_run_id=baseline_run_id,
                    parent_run_id=parent_run_id,
                    job_id=job_id,
                    target_endpoint=endpoint_request,
                    endpoint_auth=endpoint_auth,
                    endpoint_allowlist=list(redsim_config.target_allowlist),
                )
            elif str(target.value).startswith("bundled:"):
                record = run_campaign_sandboxed(
                    config,
                    sink,
                    on_stage=on_stage,
                    is_cancelled=is_cancelled,
                    baseline_run_id=baseline_run_id,
                    parent_run_id=parent_run_id,
                    job_id=job_id,
                )
            else:
                from redsim.services.ml_models import uploaded_model_file

                with uploaded_model_file(target, ctx.blob_store) as (
                    materialized_path,
                    materialized_detail,
                ):
                    record = run_campaign_sandboxed(
                        config,
                        sink,
                        target_file=materialized_path,
                        target_detail=materialized_detail,
                        on_stage=on_stage,
                        is_cancelled=is_cancelled,
                        baseline_run_id=baseline_run_id,
                        parent_run_id=parent_run_id,
                        job_id=job_id,
                    )
        except (SandboxTimeout, SandboxKilled, EnvelopeInvalid) as exc:
            # Spec 10.6: a typed infrastructure failure, never a model outcome. The files the child
            # had written are already under ml/partial/ (the sandbox persisted them through the sink).
            error_class = type(exc).__name__
            stage_status = "timed_out" if isinstance(exc, SandboxTimeout) else "failed"
            error = f"{error_class}: {exc}"
            tracker.aborted(stage_status, error)
            if is_verify:
                _verify_inconclusive_on_failure(ctx, job=job, error=error)
            if not emitter.has("model.load") and "load_target" not in tracker.done:
                emitter.emit("model.load", {**load_detail, "reason": error, "error_class": error_class},
                             success=False)
            complete("failed", success=False, record=None, error_class=error_class)
            # Body writes must survive task_context's failure-path rollback.
            ctx.session.commit()
            raise

        # run_campaign is storage-agnostic and allocates a local id. The
        # platform run id is authoritative at this boundary.
        record = record.model_copy(update={"run_id": ctx.run_id})
        if is_endpoint:
            # The parent-side broker counters and budget (ENDPOINT-05, -08) travel on the run record's
            # provenance and are surfaced on the attack.execute / campaign.score / job.complete rows.
            endpoint_summary = _endpoint_broker_summary(record)
        if record.status == "cancelled" or is_cancelled():
            tracker.aborted("cancelled", str(record.error or "campaign cancelled"),
                            stages_done=list(record.stages_done))
            complete("cancelled", success=False, record=record, error_class=None)
            # Preserve the authoritative partial record and campaign projection.
            # task_context will then observe the committed cancellation and
            # suppress its terminal success write.
            ctx.session.commit()
            return {
                "run_id": ctx.run_id,
                "job_id": job_id,
                "status": "cancelled",
                "stages_done": list(record.stages_done),
            }
        if baseline_run_id and record.status == "succeeded" and record.score is not None:
            baseline_record = _load_baseline_record(ctx, str(baseline_run_id))
            record = _apply_verify_baseline(record, baseline_record, baseline_run_id=str(baseline_run_id))

        harden_audit: dict[str, Any] | None = None
        if record.status == "succeeded":
            # Spec 10.8: only the harden stage of an attack / harden job leaves the boundary; a verify
            # job re-measures and never narrates (its trail carries verify.execute, not harden.execute).
            record, harden_audit = _parent_narrative(
                ctx, config=config, record=record, sink=sink, redsim_config=redsim_config,
                allowed=not is_verify,
            )
            if is_verify:
                harden_audit = None

        from redsim.ml.reporting import render_campaign_reports

        for name, data, content_type in render_campaign_reports(record):
            sink.put(name, data, content_type)
        record_json = record.model_dump_json(indent=2).encode("utf-8")
        sink.finalizing_run_record = True
        sink.put("run_record.json", record_json, "application/json")
        persist_campaign_record(ctx.session, ctx.run_id, record)

        n_findings = 0
        verify_summary: dict[str, Any] | None = None
        _emit_record_audit(emitter, config=config, record=record, sink=sink, load_detail=load_detail,
                           harden_audit=harden_audit, endpoint_summary=endpoint_summary)
        if job.type == "attack.run" and record.status == "succeeded":
            from redsim.services.ml_findings import project_campaign_findings

            n_findings = len(project_campaign_findings(ctx.session, record))
        elif job.type in {"explain.run", "harden.recommend"} and record.status == "succeeded":
            n_findings = 1 if _merge_followon(ctx, job=job, record=record, sink=sink) else 0
        elif is_verify:
            verify_summary = _project_verify(
                ctx, job=job, record=record, baseline_run_id=baseline_run_id, emitter=emitter, sink=sink,
            )
            n_findings = 1
        emitter.emit("report.render", {
            "formats": list(REPORT_FORMATS),
            "artifact_ids": {f"report.{ext}": sink.ids.get(f"report.{ext}") for ext in REPORT_FORMATS},
            "sha256": {f"report.{ext}": sink._hashes.get(f"report.{ext}") for ext in REPORT_FORMATS},
        })

        if record.status == "failed":
            failed_class = _error_class(record.error)
            tracker.aborted("failed", record.error or "ML campaign failed", stages_done=list(record.stages_done))
            complete("failed", success=False, record=record, error_class=failed_class, n_findings=n_findings)
            ctx.session.commit()
            raise RuntimeError(record.error or "ML campaign failed")

        tracker.finish(record)
        complete("succeeded", success=True, record=record, n_findings=n_findings)
        logger.info("ML campaign completed run=%s job=%s", ctx.run_id, job_id)
        result: dict[str, Any] = {
            "run_id": ctx.run_id, "job_id": job_id, "status": record.status,
            "stages_done": list(record.stages_done), "n_findings": n_findings,
        }
        if verify_summary is not None:
            result["verify"] = {k: verify_summary[k] for k in ("outcome", "validation_state", "status")}
        return result


__all__ = [
    "DELTA_UNAVAILABLE_LIMITATION",
    "HARDEN_COMPLETION_NAME",
    "HARDEN_NARRATIVE_NAME",
    "HARDEN_PROMPT_NAME",
    "NARRATIVE_TASK",
    "PARTIAL_PREFIX",
    "REPORT_FORMATS",
    "STAGE_STATUSES",
    "VERIFY_STATUS_MAP",
    "DatabaseArtifactSink",
    "artifact_kind",
    "expected_stages",
    "ml_campaign_run",
]
