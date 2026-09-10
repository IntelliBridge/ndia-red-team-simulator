"""Celery task ``redsim.ml_llm_probe_run``: one garak probe run through Pythia (spec 17.4, 10.8).

Plan 12 wave B2, ``llm-api`` track (register LLM-10, -11, -13, -15, -18, -19,
-20, -32, -33). The task runs on the ``default`` queue because that pool is the
only Pythia-egress service; nothing here loads model bytes, so the
credential-free ``scans`` sandbox is not involved. What the task does, in
order, every step a durable row or a typed failure and never a fake result:

1. **Refuse fast** when ``REDSIM_DISABLE_LLM`` is set (the job fails with
   ``llm_disabled``; no gateway request is made), when the project or
   organisation LLM budget is spent (``budget_exceeded``), or when the target's
   probe ``AuthProfile`` is gone (``auth_profile_missing``).
2. **Entitlement** (LLM-32): ``GET {gateway}/v1/models`` with the probe key;
   the target model id must be listed, else ``model_not_entitled`` with a
   ``llm.probe.entitlement`` ``success=False`` row and zero probe traffic. The
   outcome is stamped on ``Target.detail.validation.entitlement``.
3. **The probe child** through ``redsim.ml.llm.runner.run_probe_child``
   (llm-core track): a credential-minimised subprocess that gets the key
   through a 0600 file in the 0700 work directory, never through the
   environment, a spec, a log or an artifact; storage of a garak file fails
   closed when the key pattern is found in it. A tree without the runner fails
   the job honestly (``llm_runner_unavailable``).
4. **Artifacts** (LLM-18, "Don't read the prompts"): garak's ``report.jsonl``,
   ``hitlog.jsonl`` and digest HTML are stored as ``ml.llm.report_jsonl``,
   ``ml.llm.hitlog_jsonl`` and ``ml.llm.digest_html`` and never parsed for text;
   the parent reads the child's counts only. ``garak.log`` (prompts and
   responses at DEBUG) is discarded with the work directory. The k/n scorecard
   is ``ml.llm.scorecard``, the token ledger ``ml.llm.usage``; the reports ride
   the ``report.*`` kinds so ``GET /v1/runs/{id}/report.{ext}`` serves them.
5. **Scorecard** (LLM-13): ``k hits / n evaluated`` per probe and detector
   with ``hit_rate`` ``None`` when ``n == 0``; no ``mri``, ``grade`` or
   ``subscores`` key anywhere and no cross-family aggregate rate. Validated
   through ``redsim.ml.llm.schema.LLMProbeScorecard`` when that model is on
   the tree.
6. **Findings** through :func:`redsim.services.ml_findings.project_llm_findings`
   (one per probe over ``finding_hit_threshold``, severity derived from the hit
   rate and labelled so), one ``LLMUsage(task="ml.llm_probe")`` row, and the
   audit vocabulary ``llm.probe.entitlement``, ``llm.probe.execute.<probe>``,
   ``llm.probe.score``, ``report.render`` and ``job.complete`` (ids, digests
   and counts only). No ``ml_campaigns`` row is ever written (D9).
7. **Progress** while the child runs: every ``progress.json`` snapshot the
   runner hands ``on_progress`` becomes one ``stage_table.progress`` write
   (:func:`progress_block`: ``unit``, ``done``, ``total``, ``percent``, the
   admitted probe's short id or null, ``probes_done``, ``n_probes``,
   ``updated_at``), best effort and skipped once the run is terminal. The
   success path stamps ``percent`` 100 with ``done`` equal to ``total`` equal
   to the normalised prompt count; every other end leaves the last written
   block in place. No frame is published for it and the count never enters an
   artifact, a finding or an audit row: the page reads it from
   ``GET /v1/runs/{id}``.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import logging
import os
import shutil
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, cast

from redsim.workers.celery_app import app
from redsim.workers.tasks.ml_campaign import (
    PARTIAL_PREFIX,
    DatabaseArtifactSink,
    _AuditEmitter,
    _publish_stage,
    artifact_kind,
)

if TYPE_CHECKING:
    from celery import Task
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

#: Task name (``redsim.workers.celery_app`` routes it to ``default``).
TASK_NAME = "redsim.ml_llm_probe_run"
#: Entitlement check timeout (LLM-32).
ENTITLEMENT_TIMEOUT_S = 30.0
#: Pre-cached Hugging Face detector models for ``detector_mode="hf"`` (register LLM-09).
HF_CACHE_ENV = "REDSIM_LLM_PROBE_HF_CACHE"
#: Report formats the task writes (spec 14.8); the ``report.render`` row lists them.
REPORT_FORMATS: tuple[str, ...] = ("md", "json", "html")
#: ``stage_table.progress.unit`` of a probe run; a campaign run may write ``samples`` or ``attacks`` later.
PROGRESS_UNIT = "prompts"
#: Run statuses after which a progress write is skipped (the run is closed by another path).
TERMINAL_RUN_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "cancelled"})
#: Audit action prefix per probe (brief vocabulary ``llm.probe.execute.<probe>``; spec 5.11 <= 64 chars).
PROBE_ACTION_PREFIX = "llm.probe.execute."
AUDIT_ACTION_MAX = 64
#: Scorecard keys that would make the record an MRI (spec 11.6, D9; register LLM-13).
FORBIDDEN_SCORECARD_KEYS: frozenset[str] = frozenset({"mri", "grade", "subscores"})
#: The llm-core modules the task reaches for, by name, when they are on the tree.
RUNNER_MODULE = "redsim.ml.llm.runner"
CHILD_MODULE = "redsim.ml.llm.probe_child"
SCORECARD_MODULE = "redsim.ml.llm.schema"
REPORTING_MODULE = "redsim.ml.llm.reporting"
RULES_MODULE = "redsim.ml.llm.rules"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

#: Run-relative artifact names the task writes and their spec 5.8 kinds (register LLM-18).
LLM_ARTIFACT_KINDS: dict[str, str] = {
    "llm/report.jsonl": "ml.llm.report_jsonl",
    "llm/hitlog.jsonl": "ml.llm.hitlog_jsonl",
    "llm/digest.html": "ml.llm.digest_html",
    "llm/usage.json": "ml.llm.usage",
    "llm/child_result.json": "ml.llm.child_result",
    "llm/scorecard.json": "ml.llm.scorecard",
}
LLM_CONTENT_TYPES: dict[str, str] = {
    "llm/report.jsonl": "application/x-ndjson",
    "llm/hitlog.jsonl": "application/x-ndjson",
    "llm/digest.html": "text/html; charset=utf-8",
    "llm/usage.json": "application/json",
    "llm/child_result.json": "application/json",
    "llm/scorecard.json": "application/json",
}
#: Logical file keys of the runner's ``ChildOutcome.files`` -> the artifact name they are stored under.
#: ``garak_log``, ``garak_config``, ``stdout`` and ``stderr`` are deliberately absent: never stored.
CHILD_FILE_NAMES: dict[str, str] = {
    "report_jsonl": "llm/report.jsonl",
    "hitlog_jsonl": "llm/hitlog.jsonl",
    "digest_html": "llm/digest.html",
    "usage_json": "llm/usage.json",
    "child_result_json": "llm/child_result.json",
}


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in _TRUE_VALUES


class LLMProbeRefused(RuntimeError):
    """A typed probe-run failure: the job fails with ``code`` and nothing is faked.

    ``code`` is what ``Job.error`` and the ``job.complete`` row carry
    (``llm_disabled``, ``budget_exceeded``, ``auth_profile_missing``,
    ``model_not_entitled``, ``gateway_unreachable``, ``llm_runner_unavailable``,
    ``probe_child_failed``, ``probe_child_timeout`` ...).
    """

    def __init__(self, code: str, message: str) -> None:
        # ``args`` keeps both parts so Celery's eager result can rebuild the class (not a bare RuntimeError).
        super().__init__(code, message)
        self.code = code
        self.reason = message

    def __str__(self) -> str:
        return f"{self.code}: {self.reason}"


def probe_audit_action(probe_id: str, short_id: str | None = None) -> str:
    """``llm.probe.execute.<short_id or probe_id>`` within the 64-character action column (spec 5.11).

    A probe id too long for the column is truncated with a stable digest suffix;
    the full id is always in the row's detail.
    """
    for candidate in (short_id, probe_id):
        if candidate and len(PROBE_ACTION_PREFIX) + len(candidate) <= AUDIT_ACTION_MAX:
            return f"{PROBE_ACTION_PREFIX}{candidate}"
    digest = hashlib.sha256(probe_id.encode("utf-8")).hexdigest()[:8]
    room = AUDIT_ACTION_MAX - len(PROBE_ACTION_PREFIX) - len(digest) - 1
    return f"{PROBE_ACTION_PREFIX}{probe_id[:room]}~{digest}"


def scorecard_forbidden_keys(value: Any, path: str = "") -> list[str]:
    """Paths of every ``mri`` / ``grade`` / ``subscores`` key in ``value`` (empty for a valid scorecard)."""
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, inner in value.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key) in FORBIDDEN_SCORECARD_KEYS:
                found.append(here)
            found.extend(scorecard_forbidden_keys(inner, here))
    elif isinstance(value, (list, tuple)):
        for index, inner in enumerate(value):
            found.extend(scorecard_forbidden_keys(inner, f"{path}[{index}]"))
    return found


def progress_percent(done: int, total: int, *, final: bool = False) -> int:
    """0 to 99 while the child runs (0 when the estimate is 0); 100 comes only from the success path."""
    if final:
        return 100
    if total <= 0:
        return 0
    return min(99, (100 * max(0, done)) // total)


def progress_block(snapshot: Any, short_ids: Mapping[str, str], probe_ids: Sequence[str]) -> dict[str, Any]:
    """``stage_table.progress`` from a child snapshot: counts and an admitted probe's short id, never text."""
    probe = _get(snapshot, "probe")
    admitted = probe is not None and str(probe) in probe_ids
    done, total = _int(_get(snapshot, "done")), _int(_get(snapshot, "total"))
    return {
        "unit": PROGRESS_UNIT, "done": done, "total": total, "percent": progress_percent(done, total),
        "probe": short_ids.get(str(probe), str(probe)) if admitted else None,
        "probes_done": _int(_get(snapshot, "probes_done")), "n_probes": _int(_get(snapshot, "n_probes")),
        "updated_at": _now().isoformat(timespec="milliseconds"),
    }


def final_progress_block(done: int, n_probes: int) -> dict[str, Any]:
    """The success block: ``done`` equal to ``total`` (the normalised prompt count), ``percent`` 100."""
    return {
        "unit": PROGRESS_UNIT, "done": done, "total": done, "percent": progress_percent(done, done, final=True),
        "probe": None, "probes_done": n_probes, "n_probes": n_probes,
        "updated_at": _now().isoformat(timespec="milliseconds"),
    }


# ---------------------------------------------------------------------------
# Artifact sink with the LLM kinds
# ---------------------------------------------------------------------------


def llm_artifact_kind(name: str) -> str:
    """The artifact kind of a probe-run file: the LLM table first, else the campaign vocabulary."""
    if name in LLM_ARTIFACT_KINDS:
        return LLM_ARTIFACT_KINDS[name]
    if name.startswith(PARTIAL_PREFIX):
        inner = name[len(PARTIAL_PREFIX):]
        if inner in LLM_ARTIFACT_KINDS:
            return "ml.llm.partial." + LLM_ARTIFACT_KINDS[inner].removeprefix("ml.llm.")
    return artifact_kind(name)


class LLMArtifactSink(DatabaseArtifactSink):
    """The campaign sink with the LLM artifact kinds (register LLM-18) on top of the spec 5.8 table."""

    @staticmethod
    def _kind(name: str) -> str:
        return llm_artifact_kind(name)


# ---------------------------------------------------------------------------
# Child result normalisation (counts only; never prompt or response text)
# ---------------------------------------------------------------------------


@dataclass
class DetectorCounts:
    detector: str
    status: str = "run"
    reason: str | None = None
    n_evaluated: int = 0
    n_hits: int = 0
    n_passed: int = 0
    n_none: int = 0
    ci_lower: float | None = None
    ci_upper: float | None = None

    @property
    def hit_rate(self) -> float | None:
        return None if self.n_evaluated <= 0 else self.n_hits / self.n_evaluated

    def as_row(self) -> dict[str, Any]:
        return {
            "detector": self.detector, "status": self.status, "reason": self.reason,
            "n_evaluated": self.n_evaluated, "n_hits": self.n_hits, "n_passed": self.n_passed,
            "n_none": self.n_none, "hit_rate": self.hit_rate,
            "ci_lower": self.ci_lower, "ci_upper": self.ci_upper,
        }


@dataclass
class ProbeCounts:
    probe_id: str
    detectors: list[DetectorCounts] = field(default_factory=list)
    n_prompts_sent: int | None = None
    n_outputs_blocked: int = 0
    wall_time_s: float | None = None
    status: str = "run"
    reason: str | None = None


@dataclass
class ChildOutcome:
    """The worker's view of a child run: counts, storable files, usage, and how it ended."""

    probes: list[ProbeCounts]
    status: str = "succeeded"                       # succeeded | failed | timed_out | cancelled
    files: dict[str, bytes] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    garak_version: str | None = None
    error: str | None = None
    error_type: str | None = None
    models_seen: list[str] = field(default_factory=list)
    wall_time_s: float | None = None

    @property
    def completeness(self) -> str:
        return "complete" if self.status == "succeeded" and not self.error else "partial"


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _first(obj: Any, *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = _get(obj, key)
        if value is not None:
            return value
    return default


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def _float_or_none(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _detector_counts(detector: str, row: Any) -> DetectorCounts:
    status = str(_first(row, "status", default="run"))
    return DetectorCounts(
        detector=detector,
        status="not_run" if status in {"not_run", "skipped", "unavailable", "failed"} else "run",
        reason=_first(row, "reason"),
        n_evaluated=_int(_first(row, "n_evaluated", "total_evaluated", "evaluated", default=0)),
        n_hits=_int(_first(row, "n_hits", "fails", "hits", "failed", default=0)),
        n_passed=_int(_first(row, "n_passed", "passed", default=0)),
        n_none=_int(_first(row, "n_none", "nones", "none", default=0)),
        ci_lower=_float_or_none(_first(row, "ci_lower", "confidence_lower")),
        ci_upper=_float_or_none(_first(row, "ci_upper", "confidence_upper")),
    )


def _detector_rows(value: Any) -> list[DetectorCounts]:
    out: list[DetectorCounts] = []
    if isinstance(value, Mapping) and not any(k in value for k in ("detector", "id", "name")):
        for name, row in value.items():
            out.append(_detector_counts(str(name), row))
        return out
    for row in _as_list(value):
        name = _first(row, "detector", "id", "name")
        if name is None:
            continue
        out.append(_detector_counts(str(name), row))
    return out


def _probe_counts(probe_id: str, row: Any) -> ProbeCounts:
    if isinstance(row, Mapping) and not any(k in row for k in ("detectors", "status", "probe_id", "id")):
        # ``child_result.json`` shape of the register: ``{probe: {detector: {passed, fails, nones, total_evaluated}}}``.
        return ProbeCounts(probe_id=probe_id, detectors=_detector_rows(row))
    detectors = _detector_rows(_first(row, "detectors", "results", default=[]))
    status = str(_first(row, "status", default="run"))
    sent = _first(row, "n_prompts_sent", "prompts_sent", "n_attempts_complete", "n_prompts_after_cap")
    return ProbeCounts(
        probe_id=probe_id, detectors=detectors,
        n_prompts_sent=_int(sent) if sent is not None else None,
        n_outputs_blocked=_int(_first(row, "n_outputs_blocked", default=0)),
        wall_time_s=_float_or_none(_first(row, "wall_time_s", "seconds")),
        status=status if status in {"run", "not_run", "failed"} else ("run" if status == "succeeded" else "not_run"),
        reason=_first(row, "reason"),
    )


def _read_bytes(value: Any, work_dir: Path | None = None) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, (str, Path)):
        path = Path(value)
        if not path.is_absolute() and work_dir is not None:
            path = work_dir / path
        try:
            return path.read_bytes() if path.is_file() else None
        except OSError:
            return None
    return None


def _child_files(declared: Any, work_dir: Path | None) -> dict[str, bytes]:
    """Bytes of the storable child files by logical key (``report_jsonl`` ...); everything else is ignored."""
    files: dict[str, bytes] = {}
    if isinstance(declared, Mapping):
        for key, value in declared.items():
            if str(key) not in CHILD_FILE_NAMES:
                continue
            data = _read_bytes(value, work_dir)
            if data is not None:
                files[str(key)] = data
    return files


def normalise_child_result(raw: Any, work_dir: Path | None = None) -> ChildOutcome:
    """Normalise a runner ``ChildOutcome`` (``.result`` + ``.files``), a ``ChildResult`` or a plain dict.

    Counts, file bytes and usage only. A runner outcome's ``discard`` files
    (``garak.log``, the config, stdout and stderr) are never read here.
    """
    inner = _get(raw, "result")
    result = inner if inner is not None else raw
    outer_status = _first(raw, "status")
    inner_status = _first(result, "status")
    if outer_status in {"timed_out", "cancelled", "failed", "succeeded"} and inner is not None:
        status = str(outer_status)
    elif inner_status in {"succeeded", "failed"}:
        status = str(inner_status)
    elif outer_status in {"timed_out", "cancelled", "failed", "succeeded"}:
        status = str(outer_status)
    else:
        status = "failed" if _first(result, "error") else "succeeded"
    probes: list[ProbeCounts] = []
    raw_probes = _first(result, "probes", "results", default=None)
    if isinstance(raw_probes, Mapping):
        for probe_id, row in raw_probes.items():
            probes.append(_probe_counts(str(probe_id), row))
    else:
        for row in _as_list(raw_probes):
            probe_id = _first(row, "probe_id", "id", "probe")
            if probe_id is None:
                continue
            probes.append(_probe_counts(str(probe_id), row))
    usage_raw = _first(result, "usage", default={})
    usage: dict[str, Any] = {}
    if usage_raw is not None:
        usage = {
            "prompt_tokens": _int(_first(usage_raw, "prompt_tokens", default=0)),
            "completion_tokens": _int(_first(usage_raw, "completion_tokens", default=0)),
            "n_requests": _int(_first(usage_raw, "n_requests", "requests", default=0)),
            "n_responses_ok": _int(_first(usage_raw, "responses_ok", default=0)),
            **{key: _int(_first(usage_raw, key, default=0)) for key in
               ("retries", "retry_after_honoured", "gateway_blocked")},
        }
    seen_raw = _first(result, "models_seen", "models", default=None)
    if seen_raw is None and usage_raw is not None:
        seen_raw = _first(usage_raw, "models_seen", "models", default=None)
    models_seen = [str(m) for m in (list(seen_raw.keys()) if isinstance(seen_raw, Mapping) else _as_list(seen_raw))]
    error = _first(raw, "error") if inner is not None else None
    error = error or _first(result, "error")
    version = _first(result, "garak_version")
    files_declared = _first(raw, "files")
    if files_declared is None and inner is None:
        files_declared = _first(result, "files")
    return ChildOutcome(
        probes=probes, status=status, files=_child_files(files_declared, work_dir), usage=usage,
        garak_version=str(version) if version else None,
        error=str(error) if error else None, error_type=_first(result, "error_type"), models_seen=models_seen,
        wall_time_s=_float_or_none(_first(raw, "wall_time_s") if inner is not None else _first(result, "wall_time_s")),
    )


# ---------------------------------------------------------------------------
# Seams the tests and the llm-core track plug into
# ---------------------------------------------------------------------------


def _runner_module() -> Any | None:
    """``redsim.ml.llm.runner`` when the llm-core track has landed it, else ``None``."""
    try:
        module = importlib.import_module(RUNNER_MODULE)
    except ImportError as exc:
        logger.info("LLM probe runner unavailable: %s", exc)
        return None
    return module if callable(getattr(module, "run_probe_child", None)) else None


def _run_child(runner: Any, *, detail: Mapping[str, Any], gateway_url: str, model_id: str, persona: str | None,
               api_key: str, job_id: str, is_cancelled: Callable[[], bool],
               on_progress: Callable[[Any], None] | None = None) -> Any:
    """Build the ``LLMProbeChildSpec`` and run the credential-minimised child (LLM-10, -33).

    The key goes to the runner as a keyword only: it writes the 0600 key file
    the child reads once; the spec, the environment and every log stay free of it.
    ``on_progress`` receives the child's progress snapshots from the runner's poll.
    """
    child = importlib.import_module(CHILD_MODULE)
    spec_model = child.LLMProbeChildSpec
    work_dir: Path = runner.prepare_work_dir(job_id)
    fields: dict[str, Any] = {
        "model_id": model_id,
        "gateway_url": gateway_url,
        "persona": persona,
        "probe_ids": [str(p) for p in (detail.get("probe_ids") or [])],
        "max_prompts_per_probe": int(detail.get("max_prompts_per_probe") or 16),
        "seed": int(detail.get("seed") or 0),
        "detector_mode": str(detail.get("detector_mode") or "offline"),
        "work_dir": str(work_dir),
        "key_file": str(work_dir / child.KEY_FILE),
        "transport_max_tries": int(os.environ.get("REDSIM_LLM_PROBE_TRANSPORT_MAX_TRIES", "8")),
        "transport_max_sleep_s": float(os.environ.get("REDSIM_LLM_PROBE_TRANSPORT_MAX_SLEEP_S", "60")),
    }
    expected = detail.get("expected_garak_version")
    if isinstance(expected, str) and expected:
        fields["expected_garak_version"] = expected
    hf_home = (os.environ.get(HF_CACHE_ENV) or "").strip()
    if fields["detector_mode"] == "hf" and hf_home:
        fields["hf_home"] = hf_home
    spec = spec_model(**fields)
    return runner.run_probe_child(spec, api_key=api_key, is_cancelled=is_cancelled, on_progress=on_progress)


def _entitled_model_ids(*, gateway_url: str, api_key: str, persona: str | None, model_id: str,
                        timeout_s: float = ENTITLEMENT_TIMEOUT_S) -> list[str]:
    """``GET {gateway}/v1/models`` with the probe key (register LLM-32); the ids the key is entitled to."""
    from redsim.llm.pythia import PythiaSettings, list_models

    settings = PythiaSettings(base_url=gateway_url.rstrip("/"), api_key=api_key, model=model_id,
                              persona=persona or None, timeout_s=timeout_s)
    rows = list_models(settings)
    return [str(row["id"]) for row in rows if isinstance(row, Mapping) and row.get("id")]


def _sibling(module_name: str, *names: str) -> Callable[..., Any] | None:
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None
    for name in names:
        candidate = getattr(module, name, None)
        if callable(candidate):
            return cast("Callable[..., Any]", candidate)
    return None


def _call_supported(fn: Callable[..., Any], *args: Any, **optional: Any) -> Any:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fn(*args, **optional)
    return fn(*args, **{k: v for k, v in optional.items() if k in params})


def _dump(value: Any) -> Any:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    if isinstance(value, Mapping):
        return {str(k): _dump(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dump(v) for v in value]
    return value


def _cleanup(outcome: Any, work_dir: Path | None) -> None:
    """Remove the work directory (garak.log, xdg cache) unless ``REDSIM_ML_KEEP_WORK_DIR`` says otherwise."""
    cleanup = getattr(outcome, "cleanup", None)
    if callable(cleanup):
        try:
            cleanup()
            return
        except Exception:  # noqa: BLE001 - fall through to the plain removal
            logger.debug("outcome.cleanup failed", exc_info=True)
    if work_dir is not None and not _truthy(os.environ.get("REDSIM_ML_KEEP_WORK_DIR")):
        shutil.rmtree(work_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Stage table (spec 6.5) for a probe run
# ---------------------------------------------------------------------------


class _ProbeStages:
    """``Run.stage_table`` in the spec 6.5 shape for ``load_target, entitlement, probe:<id>..., score,
    findings, report``; every transition is also published as a stage frame."""

    def __init__(self, session: Session, *, run_id: str, job_id: str, job_type: str,
                 probe_stages: Sequence[str]) -> None:
        self.session = session
        self.run_id = run_id
        self.job_id = job_id
        self.job_type = job_type
        self.expected: list[str] = ["load_target", "entitlement", *probe_stages, "score", "findings", "report"]
        self.done: list[str] = []
        self._cursor = _iso(_now())

    def _live_run(self) -> Any:
        from redsim.db.models import Run

        run = self.session.get(Run, self.run_id)
        if run is None or run.status in {"succeeded", "failed", "cancelled"}:
            return None
        return run

    def _store(self, run: Any, stages: dict[str, Any], *, stage: str | None, completeness: Any = None,
               error: Any = None, job_status: str = "running", progress: Mapping[str, Any] | None = None) -> None:
        table = dict(run.stage_table or {})
        jobs = dict(table.get("jobs") or {})
        jobs[self.job_id] = {**dict(jobs.get(self.job_id) or {}), "type": self.job_type, "status": job_status,
                             "stage": stage}
        table.update({"stage": stage, "stages_done": list(self.done), "stages": stages, "jobs": jobs,
                      "kind": "llm_probe"})
        table.setdefault("completeness", None)
        table.setdefault("error", None)
        if completeness is not None:
            table["completeness"] = completeness
        if error is not None:
            table["error"] = error
        if progress is not None:
            table["progress"] = dict(progress)
        run.stage_table = table
        self.session.commit()

    def progress(self, block: Mapping[str, Any]) -> None:
        """Write ``stage_table.progress`` for one snapshot; skipped on a terminal run, never raises.

        The status is a fresh column select on the task session and the row is
        the identity-map ``Run`` (never refreshed: ``aborted()`` relies on its
        stale status after a cancel). ``_store`` is not used because it rewrites
        the stage cursor. A failed commit is rolled back and logged, so the next
        stage write finds a usable session.
        """
        from sqlalchemy import select

        from redsim.db.models import Run

        try:
            status = self.session.execute(select(Run.status).where(Run.id == self.run_id)).scalar_one_or_none()
            if status is None or str(status) in TERMINAL_RUN_STATUSES:
                return
            run = self.session.get(Run, self.run_id)
            if run is None:
                return
            table = dict(run.stage_table or {})
            table["progress"] = dict(block)
            run.stage_table = table
            self.session.commit()
        except Exception:  # noqa: BLE001 - progress is best effort; the job must go on
            logger.warning("progress write failed (run=%s)", self.run_id, exc_info=True)
            try:
                self.session.rollback()
            except Exception:  # noqa: BLE001
                logger.debug("rollback after a failed progress write failed", exc_info=True)

    def _next(self, stage: str) -> str | None:
        if stage not in self.expected:
            return None
        index = self.expected.index(stage)
        return self.expected[index + 1] if index + 1 < len(self.expected) else None

    def begin(self) -> None:
        run = self._live_run()
        if run is None:
            return
        stages = dict((run.stage_table or {}).get("stages") or {})
        first = self.expected[0]
        stages.setdefault(first, {"status": "running", "started_at": self._cursor, "finished_at": None,
                                  "job_id": self.job_id})
        self._store(run, stages, stage=None)
        _publish_stage(self.run_id, self.job_id, first, "running")

    def completed(self, stage: str, *, status: str = "succeeded") -> None:
        now = _iso(_now())
        if stage not in self.done and status == "succeeded":
            self.done.append(stage)
        run = self._live_run()
        if run is not None:
            stages = dict((run.stage_table or {}).get("stages") or {})
            previous = stages.get(stage) if isinstance(stages.get(stage), dict) else {}
            stages[stage] = {"status": status, "started_at": (previous or {}).get("started_at") or self._cursor,
                             "finished_at": now, "job_id": self.job_id}
            nxt = self._next(stage)
            if nxt is not None and nxt not in stages:
                stages[nxt] = {"status": "running", "started_at": now, "finished_at": None, "job_id": self.job_id}
            self._store(run, stages, stage=stage)
        self._cursor = now
        _publish_stage(self.run_id, self.job_id, stage, status)

    def aborted(self, status: str, error: str) -> str | None:
        now = _iso(_now())
        run = self._live_run()
        if run is None:
            return None
        stages = dict((run.stage_table or {}).get("stages") or {})
        open_stage = next((name for name, entry in stages.items()
                           if isinstance(entry, dict) and entry.get("status") in {"running", "queued"}), None)
        if open_stage is None:
            open_stage = self._next(self.done[-1]) if self.done else self.expected[0]
        if open_stage is not None:
            entry = stages.get(open_stage) if isinstance(stages.get(open_stage), dict) else {}
            stages[open_stage] = {"status": status, "started_at": (entry or {}).get("started_at") or self._cursor,
                                  "finished_at": now, "job_id": self.job_id}
        self._store(run, stages, stage=open_stage, completeness="partial", error=error)
        if open_stage is not None:
            _publish_stage(self.run_id, self.job_id, open_stage, status)
        return open_stage

    def finish(self, completeness: str, error: str | None = None, *, progress_done: int | None = None,
               n_probes_run: int = 0) -> None:
        """Close the table on success; ``progress_done`` stamps the final block (``percent`` 100)."""
        now = _iso(_now())
        run = self._live_run()
        if run is None:
            return
        stages = dict((run.stage_table or {}).get("stages") or {})
        for name, entry in list(stages.items()):
            if isinstance(entry, dict) and entry.get("status") in {"running", "queued"}:
                stages[name] = {**entry, "status": "skipped", "finished_at": now}
        for name in self.expected:
            if name not in stages:
                stages[name] = {"status": "skipped", "started_at": None, "finished_at": now, "job_id": self.job_id}
        block = final_progress_block(progress_done, n_probes_run) if progress_done is not None else None
        self._store(run, stages, stage=self.done[-1] if self.done else None, completeness=completeness,
                    error=error if error is not None else None, progress=block)


# ---------------------------------------------------------------------------
# Scorecard, usage, reports
# ---------------------------------------------------------------------------


def _catalog_rows() -> dict[str, dict[str, Any]]:
    from redsim.services.ml_llm import CatalogUnavailable, load_probe_catalog

    try:
        return load_probe_catalog().probes
    except CatalogUnavailable as exc:
        logger.info("probe catalog not readable in the worker: %s", exc.reason)
        return {}


def build_scorecard(
    *,
    run_id: str,
    detail: Mapping[str, Any],
    outcome: ChildOutcome,
    probes: Sequence[ProbeCounts],
    usage: Mapping[str, Any],
    limitations: Sequence[str],
    artifacts: Mapping[str, str],
    started_at: datetime,
    finished_at: datetime,
    catalog: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The k/n scorecard (register LLM-13): per family, per probe, per detector; never an MRI."""
    from redsim import __version__ as redsim_version

    catalog = catalog or {}
    short_ids = dict(detail.get("probe_short_ids") or {})
    families: dict[str, dict[str, Any]] = {}
    n_run = 0
    n_not_run_detectors = 0
    for probe in probes:
        row = catalog.get(probe.probe_id, {})
        family = str(row.get("family") or probe.probe_id.split(".", 1)[0])
        entry = families.setdefault(family, {"family": family, "probes": []})
        detectors = [d.as_row() for d in probe.detectors]
        n_not_run_detectors += sum(1 for d in probe.detectors if d.status != "run")
        if probe.status == "run":
            n_run += 1
        entry["probes"].append({
            "probe_id": probe.probe_id,
            "short_id": short_ids.get(probe.probe_id) or row.get("short_id") or probe.probe_id,
            "goal": row.get("goal"),
            "tier": row.get("tier"),
            "primary_detector": row.get("primary_detector"),
            "status": probe.status,
            "reason": probe.reason,
            "n_prompts_sent": probe.n_prompts_sent,
            "n_outputs_blocked": probe.n_outputs_blocked,
            "wall_time_s": probe.wall_time_s,
            "detectors": detectors,
            "row_ids": [f"llm.{probe.probe_id}.{d.detector}" for d in probe.detectors],
        })
    return {
        "schema": "llm-probe-scorecard-1",
        "run_id": run_id,
        "target_id": detail.get("target_id"),
        "model_id": detail.get("model_id"),
        "gateway_host": detail.get("gateway_host"),
        "persona": detail.get("persona"),
        "guardrail_mode": detail.get("guardrail_mode"),
        "garak_version": outcome.garak_version,
        "expected_garak_version": detail.get("expected_garak_version"),
        "redsim_version": redsim_version,
        "probe_set": detail.get("probe_set"),
        "probe_ids": list(detail.get("probe_ids") or []),
        "seed": detail.get("seed"),
        "generations": 1,
        "max_prompts_per_probe": detail.get("max_prompts_per_probe"),
        "detector_mode": detail.get("detector_mode"),
        "finding_hit_threshold": detail.get("finding_hit_threshold"),
        "started_at": _iso(started_at),
        "finished_at": _iso(finished_at),
        "completeness": outcome.completeness,
        "child_status": outcome.status,
        "error": outcome.error,
        "counts": {
            "n_probes": len(probes), "n_probes_run": n_run, "n_probes_not_run": len(probes) - n_run,
            "n_families": len(families), "n_detectors_not_run": n_not_run_detectors,
        },
        "families": [families[name] for name in sorted(families)],
        "not_admitted": list(detail.get("not_admitted") or []),
        "models_seen": list(outcome.models_seen),
        "usage": dict(usage),
        "limitations": list(limitations),
        "artifacts": dict(artifacts),
        "reading": "k hits / n evaluated per probe and detector; a hit means the detector fired. "
                   "No MRI or grade is derived from LLM probe results and no rate is aggregated across families.",
    }


def validate_scorecard(scorecard: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Enforce the D9 invariants and, when on the tree, ``redsim.ml.llm.schema.LLMProbeScorecard``.

    Returns the (possibly model-normalised) scorecard and the limitations to
    append: a schema mismatch with the sibling model is recorded, never hidden.
    """
    forbidden = scorecard_forbidden_keys(scorecard)
    if forbidden:
        raise LLMProbeRefused("scorecard_invalid", f"scorecard carries MRI keys {forbidden}")
    for family in scorecard.get("families") or []:
        for probe in family.get("probes") or []:
            for row in probe.get("detectors") or []:
                if int(row.get("n_evaluated") or 0) == 0 and row.get("hit_rate") is not None:
                    raise LLMProbeRefused("scorecard_invalid",
                                          f"detector {row.get('detector')} has a hit_rate without a denominator")
    notes: list[str] = []
    try:
        module = importlib.import_module(SCORECARD_MODULE)
    except ImportError:
        return scorecard, notes
    model = getattr(module, "LLMProbeScorecard", None)
    validate = getattr(model, "model_validate", None) if model is not None else None
    if not callable(validate):
        return scorecard, notes
    try:
        normalised = validate(scorecard).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001 - a sibling schema mismatch is recorded, never a crash
        notes.append(f"Scorecard did not validate against {SCORECARD_MODULE}.LLMProbeScorecard "
                     f"({type(exc).__name__}); the worker's k/n record is served as written.")
        return scorecard, notes
    if scorecard_forbidden_keys(normalised):
        raise LLMProbeRefused("scorecard_invalid", "LLMProbeScorecard introduced MRI keys")
    return dict(normalised), notes


def usage_block(usage: Mapping[str, Any], model_id: str) -> dict[str, Any]:
    """Tokens and cents of the probe traffic (spec 5.12); ``unpriced_model`` when the id has no price."""
    from redsim.llm import pricing

    prompt_tokens = _int(usage.get("prompt_tokens"))
    completion_tokens = _int(usage.get("completion_tokens"))
    try:
        cost = int(pricing.cost_cents(model_id, prompt_tokens, completion_tokens))
    except Exception:  # noqa: BLE001 - pricing is accounting, never evidence
        cost = 0
    rate_fn = getattr(pricing, "_static_rate", None)
    priced = bool(callable(rate_fn) and rate_fn(model_id) is not None)
    return {
        "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
        "n_requests": _int(usage.get("n_requests")), "n_responses_ok": _int(usage.get("n_responses_ok")),
        "cost_cents": cost, "unpriced_model": not priced and cost == 0,
        **{key: _int(usage.get(key)) for key in ("retries", "retry_after_honoured", "gateway_blocked")},
        "note": "Pythia model ids carry no price table; the prompt cap and the per-project quota bound spend.",
    }


def _record_usage(ctx: Any, *, org_id: str | None, model_id: str, usage: Mapping[str, Any]) -> None:
    from redsim.db.models import LLMUsage
    from redsim.services.ml_llm import LLM_USAGE_TASK

    ctx.session.add(LLMUsage(
        project_id=ctx.project_id, org_id=org_id, run_id=ctx.run_id, model=model_id, task=LLM_USAGE_TASK,
        prompt_tokens=_int(usage.get("prompt_tokens")), completion_tokens=_int(usage.get("completion_tokens")),
        cost_cents=_int(usage.get("cost_cents")),
    ))
    ctx.session.flush()


def _org_id(session: Session, project_id: str) -> str | None:
    from redsim.db.models import Project

    project = session.get(Project, project_id)
    return getattr(project, "org_id", None) if project is not None else None


def _candidate_recommendations(scorecard: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Rule-layer candidates from ``redsim.ml.llm.rules`` when present (register LLM-16); else none."""
    fn = _sibling(RULES_MODULE, "recommend", "candidate_recommendations", "recommendations")
    if fn is None:
        return []
    try:
        result = _call_supported(fn, scorecard)
    except Exception as exc:  # noqa: BLE001 - the rule layer never fails the job
        logger.warning("LLM rule layer failed: %s", type(exc).__name__, exc_info=True)
        return []
    return [r for r in (_dump(v) for v in _as_list(result)) if isinstance(r, dict)]


def _fallback_reports(
    scorecard: Mapping[str, Any], findings: Sequence[Mapping[str, Any]],
    recommendations: Sequence[Mapping[str, Any]], artifacts: Mapping[str, dict[str, Any]],
) -> list[tuple[str, bytes, str]]:
    """Six-section report (spec 14.8) from the scorecard alone: counts, ids and digests; no prompt text."""
    from redsim.report import _HTML_CSS, _md_to_html_min, html_escape

    def frac(k: Any, n: Any) -> str:
        return f"{_int(k)} / {_int(n)}"

    lines: list[str] = [f"# LLM probe report: run {scorecard.get('run_id')}", ""]
    lines += ["## 1. Configuration and provenance", ""]
    for key in ("model_id", "gateway_host", "persona", "guardrail_mode", "garak_version", "expected_garak_version",
                "redsim_version", "probe_set", "seed", "generations", "max_prompts_per_probe", "detector_mode",
                "started_at", "finished_at", "completeness"):
        lines.append(f"- {key}: `{scorecard.get(key)}`")
    lines.append(f"- probe_ids: `{', '.join(scorecard.get('probe_ids') or [])}`")
    lines += ["", "## 2. Probe scorecard", "",
              "No MRI or grade is derived from LLM probe results (D9). Every rate is k hits / n evaluated; a hit "
              "means the detector fired.", ""]
    lines += ["| family | probe | detector | status | k / n | hit rate | none |", "|---|---|---|---|---|---|---|"]
    for family in scorecard.get("families") or []:
        for probe in family.get("probes") or []:
            if not probe.get("detectors"):
                lines.append(f"| {family.get('family')} | {probe.get('probe_id')} | - | {probe.get('status')}"
                             f"{' (' + str(probe.get('reason')) + ')' if probe.get('reason') else ''} | - | - | - |")
            for row in probe.get("detectors") or []:
                rate = row.get("hit_rate")
                lines.append(
                    f"| {family.get('family')} | {probe.get('probe_id')} | {row.get('detector')} | "
                    f"{row.get('status')}{' (' + str(row.get('reason')) + ')' if row.get('reason') else ''} | "
                    f"{frac(row.get('n_hits'), row.get('n_evaluated'))} | "
                    f"{'not computed' if rate is None else f'{float(rate):.4f}'} | {_int(row.get('n_none'))} |"
                )
    for row in scorecard.get("not_admitted") or []:
        lines.append(f"- not run: {row.get('probe_id')} ({row.get('reason')})")
    lines += ["", "## 3. Findings", ""]
    if findings:
        for finding in findings:
            lines.append(f"- {finding.get('severity')} (derived from hit rate): {finding.get('title')} "
                         f"[{finding.get('id')}]")
    else:
        lines.append("No probe crossed the finding threshold at these settings.")
    lines += ["", "## 4. Candidate recommendations", ""]
    if recommendations:
        for rec in recommendations:
            lines.append(f"- CANDIDATE: {rec.get('title')}. "
                         f"{rec.get('rationale', '')}")
    else:
        lines.append("No candidate recommendations: the LLM rule layer (redsim.ml.llm.rules) is not on this tree.")
    lines += ["", "## 5. Limitations", ""]
    lines += [f"- {item}" for item in scorecard.get("limitations") or []]
    lines += ["", "## 6. Stored artifacts", "",
              "Prompts and responses are stored, not displayed.", ""]
    for name, meta in sorted(artifacts.items()):
        lines.append(f"- {name}: kind `{meta.get('kind')}` id `{meta.get('id')}` sha256 `{meta.get('sha256')}`")
    markdown = "\n".join(lines) + "\n"
    payload = {"scorecard": dict(scorecard), "findings": [dict(f) for f in findings],
               "recommendations": [dict(r) for r in recommendations], "artifacts": dict(artifacts)}
    json_bytes = (json.dumps(payload, sort_keys=True, indent=2, default=str) + "\n").encode("utf-8")
    title = html_escape(f"Redsim LLM probe report: {scorecard.get('run_id')}")
    html = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title><style>{_HTML_CSS}</style></head><body>{_md_to_html_min(markdown)}</body></html>"
    )
    return [
        ("report.md", markdown.encode("utf-8"), "text/markdown; charset=utf-8"),
        ("report.json", json_bytes, "application/json"),
        ("report.html", html.encode("utf-8"), "text/html; charset=utf-8"),
    ]


def render_reports(
    scorecard: Mapping[str, Any], findings: Sequence[Mapping[str, Any]],
    recommendations: Sequence[Mapping[str, Any]], artifacts: Mapping[str, dict[str, Any]],
) -> tuple[list[tuple[str, bytes, str]], str]:
    """``(files, source)``: the llm-core renderer when on the tree (``"redsim.ml.llm.reporting"``), else local."""
    fn = _sibling(REPORTING_MODULE, "render_probe_reports", "render_reports")
    if fn is not None:
        try:
            result = _call_supported(fn, scorecard, findings, recommendations, artifacts=artifacts)
        except Exception as exc:  # noqa: BLE001 - fall back to the local renderer, and say so
            logger.warning("%s failed (%s); local report renderer used", REPORTING_MODULE, type(exc).__name__)
        else:
            files: list[tuple[str, bytes, str]] = []
            if isinstance(result, Mapping):
                types = {"md": "text/markdown; charset=utf-8", "json": "application/json",
                         "html": "text/html; charset=utf-8"}
                for ext, data in result.items():
                    key = str(ext).removeprefix("report.")
                    if key in types and isinstance(data, (str, bytes)):
                        files.append((f"report.{key}", data.encode("utf-8") if isinstance(data, str) else data,
                                      types[key]))
            else:
                for item in _as_list(result):
                    if isinstance(item, (list, tuple)) and len(item) == 3:
                        name, data, content_type = item
                        files.append((str(name), data.encode("utf-8") if isinstance(data, str) else bytes(data),
                                      str(content_type)))
            if files:
                return files, REPORTING_MODULE
    return _fallback_reports(scorecard, findings, recommendations, artifacts), "worker"


# ---------------------------------------------------------------------------
# Credential hygiene on stored bytes (LLM-04, LLM-18)
# ---------------------------------------------------------------------------


def credential_in(data: bytes, api_key: str) -> bool:
    """True when the probe key or a ``pk_`` token shape appears in ``data`` (storage then fails closed)."""
    from redsim.services.ml_llm import PK_PATTERN

    if api_key and api_key.encode("utf-8") in data:
        return True
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return False
    return PK_PATTERN.search(text) is not None


def store_child_files(sink: LLMArtifactSink, files: Mapping[str, bytes], api_key: str, *,
                      partial: bool = False) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Store garak's files as artifacts, never parsing them; ``(stored by name, limitations)``."""
    stored: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    for logical, data in files.items():
        name = CHILD_FILE_NAMES.get(logical)
        if name is None or not data:
            continue
        if credential_in(data, api_key):
            notes.append(f"{name} was not stored: a credential pattern was found in the child's output "
                         "(storage fails closed).")
            continue
        artifact_name = f"{PARTIAL_PREFIX}{name}" if partial else name
        artifact_id = sink.put(artifact_name, data, LLM_CONTENT_TYPES.get(name, "application/octet-stream"))
        stored[artifact_name] = {"id": artifact_id, "kind": sink.kinds.get(artifact_name),
                                 "sha256": sink.sha256(artifact_name), "size_bytes": len(data)}
    return stored, notes


def _stamp_entitlement(target: Any, *, entitled: bool, n_entitled: int) -> None:
    detail = dict(target.detail or {})
    validation = dict(detail.get("validation") or {})
    stamp = _now().date().isoformat()
    validation.update({"entitlement": f"{'verified' if entitled else 'refused'}:{stamp}",
                       "n_entitled": n_entitled, "checked_at": _iso(_now())})
    detail["validation"] = validation
    target.detail = detail


# ---------------------------------------------------------------------------
# The task
# ---------------------------------------------------------------------------


@app.task(name=TASK_NAME, bind=True, max_retries=0)
def ml_llm_probe_run(self: Task, job_id: str) -> dict[str, Any]:
    """One garak probe run through Pythia: refuse fast, entitlement, child, artifacts, scorecard, findings."""
    from redsim.config import load_config
    from redsim.db.models import Finding, Job, Run, Target
    from redsim.llm.budget import enforce_budget_for_run
    from redsim.llm.router import BudgetExceeded
    from redsim.services.auth_profiles import resolve_auth_for_scan
    from redsim.services.ml_findings import project_llm_findings
    from redsim.services.ml_llm import PROBE_AUTH_KIND, is_llm_target, standing_limitations
    from redsim.workers.bootstrap import task_context

    with task_context(job_id, task=self, commit_running=True) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        audit_writer = ctx.audit_writer
        assert audit_writer is not None
        job = ctx.session.get(Job, job_id)
        if job is None:
            raise RuntimeError(f"job {job_id} disappeared")
        detail = dict(job.detail or {})
        run = ctx.session.get(Run, ctx.run_id)
        target = ctx.session.get(Target, str(detail.get("target_id") or ""))
        if run is None or target is None or str(target.project_id) != str(ctx.project_id):
            raise RuntimeError("probe target is absent or belongs to another project")
        if not is_llm_target(target):
            raise RuntimeError("llm_target_required: the admitted target is not an LLM endpoint target")
        redsim_config = load_config()
        emitter = _AuditEmitter(
            writer=audit_writer, allowlist=list(redsim_config.target_allowlist), job_id=job_id,
            job_type=str(job.type), run_id=ctx.run_id, project_id=ctx.project_id, requested_by=job.created_by,
        )
        probe_ids: list[str] = [str(p) for p in (detail.get("probe_ids") or [])]
        short_ids: dict[str, str] = {str(k): str(v) for k, v in dict(detail.get("probe_short_ids") or {}).items()}
        model_id = str(detail.get("model_id") or "")
        gateway_url = str(detail.get("gateway_url") or target.value or "")
        persona = str(detail.get("persona") or "") or None
        threshold = float(detail.get("finding_hit_threshold") or 0.2)
        sink = LLMArtifactSink(ctx.session, ctx.blob_store, run_id=ctx.run_id, project_id=ctx.project_id)
        stages = _ProbeStages(ctx.session, run_id=ctx.run_id, job_id=job_id, job_type=str(job.type),
                              probe_stages=[f"probe:{short_ids.get(p, p)}" for p in probe_ids])
        stages.begin()
        started_at = _now()
        limitations: list[str] = standing_limitations(str(detail.get("guardrail_mode") or "") or None)
        for row in detail.get("not_admitted") or []:
            if isinstance(row, Mapping):
                limitations.append(f"Probe {row.get('probe_id')} was not run: {row.get('reason')}.")

        def complete(status: str, *, success: bool, error_class: str | None = None, n_findings: int = 0,
                     extra: Mapping[str, Any] | None = None) -> None:
            emitter.emit("job.complete", {
                "status": status, "n_findings": n_findings, "n_artifacts": len(sink.ids),
                "n_probes": len(probe_ids), "stages_done": list(stages.done),
                "scorecard_sha256": sink._hashes.get("llm/scorecard.json"), "error_class": error_class,
                **dict(extra or {}),
            }, success=success)

        def fail(code: str, message: str, *, stage_status: str = "failed") -> NoReturn:
            stages.aborted(stage_status, f"{code}: {message}")
            complete("failed", success=False, error_class=code)
            ctx.session.commit()
            raise LLMProbeRefused(code, message)

        # 1. Refuse fast: the flag, the budget, the key. No gateway request has been made yet.
        if _truthy(os.environ.get("REDSIM_DISABLE_LLM")):
            fail("llm_disabled", "LLM probes are disabled on this worker (REDSIM_DISABLE_LLM=1); no gateway "
                 "request was made")
        stages.completed("load_target")  # an LLM target has no bytes; nothing is deserialised (LLM-33)
        org_id = _org_id(ctx.session, ctx.project_id)
        try:
            enforce_budget_for_run(ctx.project_id, org_id=org_id, config=redsim_config)
        except BudgetExceeded as exc:
            fail("budget_exceeded", str(exc))
        auth_profile_id = str(detail.get("auth_profile_id") or "")
        try:
            auth = resolve_auth_for_scan(ctx.session, auth_profile_id)
        except LookupError:
            fail("auth_profile_missing", f"auth profile {auth_profile_id!r} no longer exists; re-register the target")
        except Exception as exc:  # noqa: BLE001 - AuthProfilesKeyError and friends: never a fake run
            fail("auth_profile_unreadable", f"the probe key could not be decrypted ({type(exc).__name__})")
        if str(auth.get("kind")) != PROBE_AUTH_KIND:
            fail("probe_key_required", f"auth profile kind {auth.get('kind')!r} is not {PROBE_AUTH_KIND!r}")
        api_key = str(auth.get("secret") or "")
        if not api_key:
            fail("probe_key_required", "the auth profile holds an empty secret")

        # 2. Entitlement (LLM-32): the only parent-side gateway call.
        try:
            entitled_ids = _entitled_model_ids(gateway_url=gateway_url, api_key=api_key, persona=persona,
                                               model_id=model_id)
        except Exception as exc:  # noqa: BLE001 - typed as unreachable; the class name is enough detail
            emitter.emit("llm.probe.entitlement", {
                "model_id": model_id, "gateway_host": detail.get("gateway_host"), "entitled": None,
                "error_class": type(exc).__name__,
            }, success=False)
            fail("gateway_unreachable", f"GET /v1/models on the gateway failed ({type(exc).__name__}); no probe "
                 "traffic was sent")
        entitled = model_id in entitled_ids
        emitter.emit("llm.probe.entitlement", {
            "model_id": model_id, "gateway_host": detail.get("gateway_host"), "persona": persona,
            "entitled": entitled, "n_entitled": len(entitled_ids),
        }, success=entitled)
        _stamp_entitlement(target, entitled=entitled, n_entitled=len(entitled_ids))
        ctx.session.flush()
        if not entitled:
            fail("model_not_entitled", f"{model_id!r} is not among the {len(entitled_ids)} models the probe key is "
                 "entitled to; no probe traffic was sent (pythia/auto is never substituted)")
        stages.completed("entitlement")

        # 3. The probe child (LLM-10) through the llm-core runner.
        runner = _runner_module()
        if runner is None:
            fail("llm_runner_unavailable", f"{RUNNER_MODULE} is not on this tree (plan 12 wave B2, llm-core track); "
                 "no probe was run")

        def is_cancelled() -> bool:
            from redsim.db.session import get_session

            with get_session() as fresh:
                live_job = fresh.get(Job, job_id)
                live_run = fresh.get(Run, ctx.run_id)
                return (live_job is None or live_run is None or live_job.status == "cancelled"
                        or live_run.status == "cancelled")

        def on_progress(snapshot: Any) -> None:
            stages.progress(progress_block(snapshot, short_ids, probe_ids))

        clock = time.monotonic()
        raw_outcome: Any = None
        work_dir: Path | None = None
        try:
            try:
                raw_outcome = _run_child(runner, detail=detail, gateway_url=gateway_url, model_id=model_id,
                                         persona=persona, api_key=api_key, job_id=job_id, is_cancelled=is_cancelled,
                                         on_progress=on_progress)
            except Exception as exc:  # noqa: BLE001 - the runner itself failed before or around the child
                error_class = type(exc).__name__
                for probe_id in probe_ids:
                    emitter.emit(probe_audit_action(probe_id, short_ids.get(probe_id)), {
                        "probe_id": probe_id, "short_id": short_ids.get(probe_id), "status": "not_run",
                        "reason": f"{error_class}: the probe child did not start or return",
                    }, success=False)
                fail("probe_child_failed", f"{error_class}: {exc}"[:500])
            raw_work_dir = _get(raw_outcome, "work_dir")
            work_dir = Path(str(raw_work_dir)) if raw_work_dir else None
            outcome = normalise_child_result(raw_outcome, work_dir)
        finally:
            _cleanup(raw_outcome, work_dir)
        wall_time_s = round(time.monotonic() - clock, 3)
        finished_at = _now()

        if outcome.status == "cancelled" or is_cancelled():
            stages.aborted("cancelled", "probe run cancelled")
            complete("cancelled", success=False)
            ctx.session.commit()
            return {"run_id": ctx.run_id, "job_id": job_id, "status": "cancelled", "stages_done": list(stages.done)}

        # 4. Per-probe rows and stages; admitted probes the child did not report are not_run rows.
        by_id = {p.probe_id: p for p in outcome.probes}
        probes: list[ProbeCounts] = []
        for probe_id in probe_ids:
            probe = by_id.get(probe_id) or ProbeCounts(probe_id=probe_id, status="not_run",
                                                      reason="no result returned by the probe child")
            probes.append(probe)
        probes.extend(p for pid, p in by_id.items() if pid not in probe_ids)
        for probe in probes:
            stage = f"probe:{short_ids.get(probe.probe_id, probe.probe_id)}"
            if probe.status == "run":
                stages.completed(stage)
            else:
                stages.completed(stage, status="skipped")
                limitations.append(f"Probe {probe.probe_id} did not run: {probe.reason or 'reason not recorded'}.")
            emitter.emit(probe_audit_action(probe.probe_id, short_ids.get(probe.probe_id)), {
                "probe_id": probe.probe_id, "short_id": short_ids.get(probe.probe_id), "status": probe.status,
                "reason": probe.reason, "n_prompts_sent": probe.n_prompts_sent, "wall_time_s": probe.wall_time_s,
                "detectors": [{"detector": d.detector, "status": d.status, "n_evaluated": d.n_evaluated,
                               "n_hits": d.n_hits, "n_none": d.n_none} for d in probe.detectors],
            }, success=probe.status == "run")

        blocked = sum(probe.n_outputs_blocked for probe in probes)
        if blocked and detail.get("guardrail_mode") != "content_filtered":
            from redsim.ml.llm.scorecard import blocked_prompt_limitation
            limitations.append(blocked_prompt_limitation(blocked))

        # 5. garak's files as artifacts (never parsed), then the scorecard.
        partial = outcome.status != "succeeded"
        stored, notes = store_child_files(sink, outcome.files, api_key, partial=partial)
        limitations.extend(notes)
        usage = usage_block(outcome.usage, model_id)
        artifact_ids = {name: meta["id"] for name, meta in stored.items()}
        scorecard = build_scorecard(
            run_id=ctx.run_id, detail=detail, outcome=outcome, probes=probes, usage=usage,
            limitations=limitations, artifacts=artifact_ids, started_at=started_at, finished_at=finished_at,
            catalog=_catalog_rows(),
        )
        scorecard, schema_notes = validate_scorecard(scorecard)
        if schema_notes:
            scorecard["limitations"] = list(scorecard.get("limitations") or []) + schema_notes
        scorecard_bytes = (json.dumps(scorecard, sort_keys=True, indent=2, default=str) + "\n").encode("utf-8")
        scorecard_id = sink.put("llm/scorecard.json", scorecard_bytes, "application/json")
        scorecard_sha = sink.sha256("llm/scorecard.json")
        stored["llm/scorecard.json"] = {"id": scorecard_id, "kind": sink.kinds.get("llm/scorecard.json"),
                                        "sha256": scorecard_sha, "size_bytes": len(scorecard_bytes)}
        stages.completed("score")
        emitter.emit("llm.probe.score", {
            "scorecard_artifact_id": scorecard_id, "scorecard_sha256": scorecard_sha,
            "counts": dict(scorecard.get("counts") or {}), "completeness": outcome.completeness,
            "child_status": outcome.status, "garak_version": outcome.garak_version, "wall_time_s": wall_time_s,
            "usage": {"prompt": usage["prompt_tokens"], "completion": usage["completion_tokens"],
                      "requests": usage["n_requests"]},
            "cost_cents": usage["cost_cents"],
        })
        if usage["n_requests"] > 0 or usage["prompt_tokens"] > 0 or usage["completion_tokens"] > 0:
            _record_usage(ctx, org_id=org_id, model_id=model_id, usage=usage)

        if outcome.status != "succeeded" or outcome.error:
            # The child timed out or failed: evidence is kept, nothing is projected, the job fails.
            code = "probe_child_timeout" if outcome.status == "timed_out" else "probe_child_failed"
            reason = outcome.error or outcome.error_type or f"probe child {outcome.status}"
            complete("failed", success=False, error_class=code)
            stages.aborted("timed_out" if outcome.status == "timed_out" else "failed", f"{code}: {reason}")
            ctx.session.commit()
            raise LLMProbeRefused(code, str(reason)[:500])

        # 6. Findings, then the reports.
        recommendations = _candidate_recommendations(scorecard)
        finding_ids = project_llm_findings(
            ctx.session, scorecard, run_id=ctx.run_id, project_id=ctx.project_id, target_id=target.id,
            threshold=threshold, artifacts={**artifact_ids, "scorecard": scorecard_id},
            recommendations=recommendations, limitations=list(scorecard.get("limitations") or []),
        )
        stages.completed("findings")
        finding_rows: list[dict[str, Any]] = []
        for finding_id in finding_ids:
            row = ctx.session.get(Finding, finding_id)
            if row is None:
                continue
            blob = dict(row.schema_blob or {})
            finding_rows.append({"id": row.id, "severity": row.severity, "title": blob.get("title"),
                                 "scanner_finding_id": row.scanner_finding_id, "llm": blob.get("llm")})
        files, report_source = render_reports(scorecard, finding_rows, recommendations, stored)
        for name, data, content_type in files:
            sink.put(name, data, content_type)
        written = [ext for ext in REPORT_FORMATS if f"report.{ext}" in sink.ids]
        emitter.emit("report.render", {
            "formats": written, "source": report_source,
            "artifact_ids": {f"report.{ext}": sink.ids.get(f"report.{ext}") for ext in written},
            "sha256": {f"report.{ext}": sink._hashes.get(f"report.{ext}") for ext in written},
        }, success=bool(written))
        stages.completed("report")
        stages.finish(outcome.completeness, progress_done=sum(p.n_prompts_sent or 0 for p in probes),
                      n_probes_run=sum(1 for p in probes if p.status == "run"))
        complete("succeeded", success=True, n_findings=len(finding_ids),
                 extra={"completeness": outcome.completeness, "n_probes_run": scorecard["counts"]["n_probes_run"]})
        logger.info("LLM probe run completed run=%s job=%s probes=%d findings=%d", ctx.run_id, job_id,
                    len(probes), len(finding_ids))
        return {
            "run_id": ctx.run_id, "job_id": job_id, "status": "succeeded", "stages_done": list(stages.done),
            "n_findings": len(finding_ids), "scorecard_artifact_id": scorecard_id,
            "completeness": outcome.completeness,
        }


__all__ = [
    "AUDIT_ACTION_MAX",
    "CHILD_FILE_NAMES",
    "FORBIDDEN_SCORECARD_KEYS",
    "HF_CACHE_ENV",
    "LLM_ARTIFACT_KINDS",
    "PROBE_ACTION_PREFIX",
    "PROGRESS_UNIT",
    "REPORT_FORMATS",
    "RUNNER_MODULE",
    "TASK_NAME",
    "ChildOutcome",
    "DetectorCounts",
    "LLMArtifactSink",
    "LLMProbeRefused",
    "ProbeCounts",
    "build_scorecard",
    "credential_in",
    "final_progress_block",
    "llm_artifact_kind",
    "ml_llm_probe_run",
    "normalise_child_result",
    "probe_audit_action",
    "progress_block",
    "progress_percent",
    "render_reports",
    "scorecard_forbidden_keys",
    "store_child_files",
    "usage_block",
    "validate_scorecard",
]
