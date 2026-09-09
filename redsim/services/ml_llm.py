"""LLM probe targets and probe-run admission (spec 17.4 garak through Pythia; plan 12 wave B2 ``llm-api``).

Three admission boundaries share this module and it stays light for all of
them: no garak, no OpenAI client, no ML library is imported at module import
time or by any function the API process calls
(``tests/test_api_process_has_no_ml.py``).

* :func:`register_llm_target` is the ``endpoint_kind="llm"`` case of
  ``POST /v1/models`` with ``source="endpoint"`` (register LLM-03). The models
  route dispatches on ``endpoint_kind`` and calls it; the black-box classifier
  case belongs to the endpoint-admission track. It validates the canonical
  ``<vendor>/<model>`` id, the persona, the ``guardrail_mode`` declaration and
  the probe ``AuthProfile`` (kind ``bearer``), runs the static egress rules on
  the gateway URL, writes the ``model.register`` audit row with the gateway URL
  as the audit target so the host allowlist applies, and only then adds the
  ``Target`` row (``kind="ml_model_endpoint"``, ``detail.endpoint_kind="llm"``).
  Every refusal is a ``success=False`` ``model.register`` row before the
  :class:`~redsim.api.errors.ApiError` is raised; the caller converts the error
  and must not write a second row.
* :func:`admit_llm_probe_run` is ``POST /v1/models/{id}/probes`` (LLM-11,
  -12, -21): the target must be an LLM target (``409 llm_target_required``),
  the probe set or ids must exist in the committed catalog
  (``422 probe_set_unknown``), the probe key must be a live bearer profile
  (``422``, reason ``probe_key_required``), one in-flight job per target
  (``409 job_in_flight``), a per-project daily quota (``429``), then the
  ``llm.probe.run`` audit row, the ``Run`` (``scanner="ml.llm_probe"``) and
  ``Job`` (``type="llm.probe"``) rows, and the enqueue on the default queue.
  No ``ml_campaigns`` row is written: probe results never enter an MRI (D9).
* :func:`read_llm_scorecard` serves ``GET /v1/runs/{id}/llm-scorecard`` from
  the ``ml.llm.scorecard`` artifact, digest checked; ``409 score_unavailable``
  while the run is not terminal, ``409 llm_target_required`` for a run that is
  not a probe run. :func:`is_llm_probe_run` is the predicate ``/campaign`` and
  ``/compare`` use to refuse probe runs.

The probe catalog is read through ``redsim.ml.llm.catalog`` (llm-core track),
imported lazily and tolerantly: a tree without that package answers
``501 not_implemented`` with the reason rather than an empty list.
"""

from __future__ import annotations

import importlib
import logging
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, NoReturn, TypedDict, cast
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from redsim.api import errors as _errors
from redsim.api.errors import (
    ALREADY_REGISTERED,
    AUTH_PROFILE_KIND_UNSUPPORTED,
    ENDPOINT_NOT_ALLOWLISTED,
    ENDPOINT_URL_INVALID,
    JOB_IN_FLIGHT,
    LLM_TARGET_REQUIRED,
    MODEL_LOAD_REFUSED,
    NOT_FOUND,
    NOT_IMPLEMENTED,
    PARAMS_OUT_OF_RANGE,
    PROBE_SET_UNKNOWN,
    QUEUE_UNAVAILABLE,
    RATE_LIMITED,
    SCORE_UNAVAILABLE,
    ApiError,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.db.models import Target
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vocabulary (spec 5.11, 6.6, 17.4; register LLM-03, -11, -13, -19)
# ---------------------------------------------------------------------------

#: ``Target.detail.endpoint_kind`` of an LLM target; classifier endpoints use another value.
LLM_ENDPOINT_KIND = "llm"
#: ``Target.detail.modality`` of an LLM target (the ``Domain`` literal, never a ``Modality``).
LLM_MODALITY = "llm"
#: ``Run.scanner`` of a probe run (spec 5.2; register LLM-11).
LLM_SCANNER = "ml.llm_probe"
#: ``Job.type`` of a probe run.
LLM_JOB_TYPE = "llm.probe"
#: Celery task name, routed to the ``default`` queue (the only Pythia-egress pool, spec 10.8).
LLM_TASK_NAME = "redsim.ml_llm_probe_run"
#: ``LLMUsage.task`` of the probe traffic (spec 5.12).
LLM_USAGE_TASK = "ml.llm_probe"
#: ``RunSummary.kind`` / ``stage_table.kind`` of a probe run (schema ``RunKind``).
LLM_RUN_KIND = "llm_probe"
#: Artifact kind of the k/n scorecard (spec 5.8 addendum; register LLM-13, -18).
SCORECARD_KIND = "ml.llm.scorecard"
#: Admission audit action (the ``Action.LLM_PROBE_RUN`` value).
ADMISSION_ACTION = "llm.probe.run"
#: Registration audit action (shared with every other ``POST /v1/models`` source).
REGISTER_ACTION = "model.register"
#: ``guardrail_mode`` declarations (register LLM-26): what the hit rates measure.
GUARDRAIL_MODES: tuple[str, ...] = ("permission_gate_only", "content_filtered", "unknown")
#: The default probe set (spec 11.6; register LLM-07).
DEFAULT_PROBE_SET = "redsim-core"
#: Catalog row statuses ``GET /v1/llm/probes`` reports.
PROBE_STATUSES: tuple[str, ...] = ("offline", "extended", "excluded")
#: Model ids that are not chat models (register LLM-32: the two embedding ids).
_EMBEDDING_PATTERN = re.compile(r"embed", re.IGNORECASE)
#: Pythia gateway key shape (mirrors ``redsim.audit.redact``).
PK_PATTERN = re.compile(r"\bpk_[A-Za-z0-9_\-]{8,}\b")
#: The auth-profile kind a probe key must have (``Authorization: Bearer pk_...``).
PROBE_AUTH_KIND = "bearer"

#: Environment knobs (register LLM-09, -21), spec 20.3 style.
MAX_PROMPTS_ENV = "REDSIM_LLM_PROBE_MAX_PROMPTS_PER_PROBE"
DEFAULT_MAX_PROMPTS_PER_PROBE = 64
QUOTA_ENV = "REDSIM_LLM_PROBE_MAX_RUNS_PER_PROJECT_PER_DAY"
DEFAULT_QUOTA_PER_DAY = 10
HF_DETECTORS_ENV = "REDSIM_LLM_PROBE_HF_DETECTORS"
GATEWAY_ENV = "PYTHIA_BASE_URL"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

# Codes the register names that the 17.3 addendum has not (yet) given a row.
# Resolved by name so the module also works on a tree whose ``errors.py`` lags;
# the stand-in is the nearest table code and ``reason`` carries the planned name.
MODEL_ID_INVALID: str = getattr(_errors, "MODEL_ID_INVALID", PARAMS_OUT_OF_RANGE)
MODEL_NOT_CHAT: str = getattr(_errors, "MODEL_NOT_CHAT", PARAMS_OUT_OF_RANGE)
AUTH_PROFILE_REQUIRED: str = getattr(_errors, "AUTH_PROFILE_REQUIRED", PARAMS_OUT_OF_RANGE)
GATEWAY_URL_REQUIRED: str = getattr(_errors, "GATEWAY_URL_REQUIRED", PARAMS_OUT_OF_RANGE)
PROBE_KEY_REQUIRED: str = getattr(_errors, "PROBE_KEY_REQUIRED", AUTH_PROFILE_KIND_UNSUPPORTED)
UNKNOWN_PROBE: str = getattr(_errors, "UNKNOWN_PROBE", PROBE_SET_UNKNOWN)
PROBE_EXCLUDED: str = getattr(_errors, "PROBE_EXCLUDED", PROBE_SET_UNKNOWN)
PROBE_DETECTOR_UNAVAILABLE: str = getattr(_errors, "PROBE_DETECTOR_UNAVAILABLE", PARAMS_OUT_OF_RANGE)
LLM_PROBE_QUOTA_EXCEEDED: str = getattr(_errors, "LLM_PROBE_QUOTA_EXCEEDED", RATE_LIMITED)

#: Standing limitations every probe scorecard and report carries (spec 11.6, 14.5; register
#: LLM-09, -17, -26). ``redsim.ml.llm.schema.LLM_STANDING_LIMITATIONS`` wins when that module
#: is on the tree (:func:`standing_limitations`).
LLM_STANDING_LIMITATIONS: tuple[str, ...] = (
    "No MRI or grade is derived from LLM probe results; the scorecard is k hits / n evaluated per "
    "probe and detector, never aggregated across probe families (D9).",
    "Keyword and trigger detectors approximate refusal and can misclassify a response in either "
    "direction; a hit is 'detector fired', not a verified harm.",
    "Results describe the model behind the named Pythia persona at these settings only: a prompt "
    "cap per probe, a single seed and one generation per prompt. They are not a safety claim.",
    "garak's report.jsonl and hitlog.jsonl are stored as artifacts and never rendered; prompt and "
    "response text is viewable only by downloading them deliberately.",
)
#: Appended when ``guardrail_mode`` is not ``permission_gate_only`` (register LLM-26).
GUARDRAIL_LIMITATION = (
    "guardrail_mode is {mode}: the hit rates measure the gateway's content filters as much as the model."
)
#: The sentence D9 tests look for (register LLM-14).
D9_SENTENCE = "No MRI or grade is derived from LLM probe results"


class LLMProbeRequest(BaseModel):
    """Body of ``POST /v1/models/{id}/probes`` (register LLM-12).

    Exactly one of ``probe_set`` / ``probe_ids`` names the probes; neither means
    the default ``redsim-core`` set. ``max_prompts_per_probe`` is garak's soft
    prompt cap, further clamped by ``REDSIM_LLM_PROBE_MAX_PROMPTS_PER_PROBE``.
    ``detector_mode="hf"`` loads Hugging Face detector models from a pre-cached
    directory and is admitted only when ``REDSIM_LLM_PROBE_HF_DETECTORS=1``.
    """

    model_config = ConfigDict(extra="forbid")

    probe_set: str | None = None
    probe_ids: list[str] | None = None
    max_prompts_per_probe: int = Field(default=16, ge=1, le=DEFAULT_MAX_PROMPTS_PER_PROBE)
    seed: int = Field(default=0, ge=0)
    detector_mode: Literal["offline", "hf"] = "offline"
    finding_hit_threshold: float = Field(default=0.2, gt=0.0, le=1.0)


class LLMProbeJobDetail(TypedDict):
    """Shape of ``Job.detail`` for ``llm.probe`` jobs: ids and settings only, never a key."""

    kind: str
    target_id: str
    model_id: str
    gateway_url: str
    gateway_host: str
    persona: str
    guardrail_mode: str
    auth_profile_id: str
    probe_set: str | None
    probe_ids: list[str]
    probe_short_ids: dict[str, str]
    not_admitted: list[dict[str, Any]]
    max_prompts_per_probe: int
    seed: int
    detector_mode: str
    finding_hit_threshold: float
    expected_garak_version: str | None
    prompt_estimate: int
    requested_by: str


@dataclass(frozen=True)
class LLMProbeHandle:
    """The 17.3 ``JobHandle`` of a probe admission, plus the scorecard link."""

    run_id: str
    job_ids: list[str]

    def to_response(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_ids": list(self.job_ids),
            "status_url": f"/v1/runs/{self.run_id}",
            "scorecard_url": f"/v1/runs/{self.run_id}/llm-scorecard",
            "kind": LLM_RUN_KIND,
        }


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in _TRUE_VALUES


def _env_int(name: str, default: int, environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default
    return value if value > 0 else default


def hf_detectors_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Whether this deployment admits ``detector_mode="hf"`` (register LLM-09)."""
    env = os.environ if environ is None else environ
    return _truthy(env.get(HF_DETECTORS_ENV))


def max_prompts_cap(environ: Mapping[str, str] | None = None) -> int:
    return _env_int(MAX_PROMPTS_ENV, DEFAULT_MAX_PROMPTS_PER_PROBE, environ)


def daily_quota(environ: Mapping[str, str] | None = None) -> int:
    return _env_int(QUOTA_ENV, DEFAULT_QUOTA_PER_DAY, environ)


def _detail(target: Any) -> dict[str, Any]:
    value = getattr(target, "detail", None)
    return dict(value) if isinstance(value, Mapping) else {}


def is_llm_target(target: Any) -> bool:
    """``Target.kind == "ml_model_endpoint"`` with ``detail.endpoint_kind == "llm"``."""
    if target is None or getattr(target, "kind", None) != "ml_model_endpoint":
        return False
    return _detail(target).get("endpoint_kind") == LLM_ENDPOINT_KIND


def gateway_host(url: str) -> str:
    """The host of a gateway URL, or ``""`` when it has none (never userinfo or query)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _refuse(
    audit_writer: AuditWriter,
    *,
    action: str,
    actor: str,
    project_id: str | None,
    exc: ApiError,
    **context: Any,
) -> NoReturn:
    """Write the ``success=False`` admission row for a refusal, then raise it (spec 5.11, 9.5).

    ``context`` carries ids, digests and short reasons only; the request body and
    every credential stay off the chain. The row sits on the project chain
    because no run exists for a refused admission.
    """
    detail: dict[str, Any] = {
        "actor": actor, "refused": True, "code": exc.code, "http_status": exc.status, "reason": str(exc),
    }
    for key, value in context.items():
        if value is not None:
            detail[key] = value
    audit_writer.append(
        action=action, actor=actor, target=None, allowlist_check="n/a", override=False,
        success=False, detail=detail, run_id=None, project_id=project_id,
    )
    raise exc


def standing_limitations(guardrail_mode: str | None) -> list[str]:
    """The LLM standing limitations, from ``redsim.ml.llm.schema`` when present, else the local copy."""
    items: list[str] = list(LLM_STANDING_LIMITATIONS)
    try:
        module = importlib.import_module("redsim.ml.llm.schema")
    except ImportError:
        module = None
    if module is not None:
        sibling = getattr(module, "LLM_STANDING_LIMITATIONS", None)
        if isinstance(sibling, (list, tuple)) and all(isinstance(s, str) for s in sibling):
            items = list(sibling)
            if not any(D9_SENTENCE in s for s in items):
                items.insert(0, LLM_STANDING_LIMITATIONS[0])
    if guardrail_mode and guardrail_mode != "permission_gate_only":
        items.append(GUARDRAIL_LIMITATION.format(mode=guardrail_mode))
    return items


# ---------------------------------------------------------------------------
# The committed probe catalog (``redsim.ml.llm.catalog``, llm-core track)
# ---------------------------------------------------------------------------


class CatalogUnavailable(RuntimeError):
    """The committed probe catalog cannot be read in this process.

    ``kind`` is ``"not_built"`` when ``redsim.ml.llm`` is not on the tree (the
    honest ``501`` of a tree where the llm-core track has not landed) and
    ``"import_error"`` / ``"invalid"`` otherwise (``503``).
    """

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(f"probe catalog unavailable ({kind}): {reason}")
        self.kind = kind
        self.reason = reason


@dataclass(frozen=True)
class ProbeCatalog:
    """The normalised view of the committed catalog this module and the routes read."""

    garak_version: str | None
    probes: dict[str, dict[str, Any]]
    sets: dict[str, list[str]] = field(default_factory=dict)

    def status_of(self, probe_id: str) -> str:
        return str(self.probes[probe_id]["status"])

    def short_id(self, probe_id: str) -> str:
        row = self.probes.get(probe_id) or {}
        short = row.get("short_id")
        return str(short) if isinstance(short, str) and short else probe_id


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _as_rows(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _probe_status(row: Any, detector_offline: bool) -> tuple[str, str]:
    """``(status, reason)`` of a catalog row: explicit ``status`` / ``excluded`` first, else derived."""
    explicit = _get(row, "status")
    reason = _get(row, "reason") or _get(row, "exclusion_reason") or _get(row, "status_reason")
    if isinstance(explicit, str) and explicit in PROBE_STATUSES:
        status = explicit
    elif _get(row, "excluded", False):
        status = "excluded"
    else:
        status = "offline" if detector_offline else "extended"
    if not isinstance(reason, str) or not reason:
        primary = _get(row, "primary_detector")
        if status == "offline":
            reason = f"primary detector {primary} is a string/trigger detector; runs offline"
        elif status == "extended":
            reason = (f"primary detector {primary} needs a Hugging Face detector model; runs only with "
                      f"detector_mode=hf ({HF_DETECTORS_ENV}=1 and a pre-cached model directory)")
        else:
            reason = "excluded from every probe set by the catalog (owner decision recorded there)"
    return status, str(reason)


def normalise_catalog(raw: Any) -> ProbeCatalog:
    """Normalise whatever ``redsim.ml.llm.catalog`` returns (pydantic model or plain JSON object)."""
    probes: dict[str, dict[str, Any]] = {}
    for row in _as_rows(_get(raw, "probes")):
        probe_id = _get(row, "id") or _get(row, "probe_id")
        if not isinstance(probe_id, str) or not probe_id:
            continue
        module = _get(row, "module") or probe_id.split(".", 1)[0]
        detector_offline = bool(_get(row, "detector_offline", False))
        status, reason = _probe_status(row, detector_offline)
        sets_value = _get(row, "sets") or []
        probes[probe_id] = {
            "id": probe_id,
            "module": str(module),
            "short_id": str(_get(row, "short_id") or probe_id),
            "family": str(_get(row, "family") or module),
            "tier": _get(row, "tier"),
            "goal": _get(row, "goal"),
            "primary_detector": _get(row, "primary_detector"),
            "extended_detectors": list(_get(row, "extended_detectors") or []),
            "detector_offline": detector_offline,
            "data_files": list(_get(row, "data_files") or []),
            "upstream_licence_note": _get(row, "upstream_licence_note"),
            "sets": [str(s) for s in sets_value],
            "status": status,
            "reason": reason,
        }
    def member_ids(members: Any) -> list[str]:
        if isinstance(members, (list, tuple)):
            return [str(_get(m, "id") or m) for m in members]
        listed = _get(members, "probe_ids") or _get(members, "probes") or []
        return [str(_get(m, "id") or m) for m in listed] if isinstance(listed, (list, tuple)) else []

    sets: dict[str, list[str]] = {}
    raw_sets = _get(raw, "sets")
    if isinstance(raw_sets, Mapping):
        for name, members in raw_sets.items():
            sets[str(name)] = member_ids(members)
    else:
        for entry in _as_rows(raw_sets):
            set_name = _get(entry, "id") or _get(entry, "name") or entry
            sets[str(set_name)] = member_ids(entry)
    for probe_id, row in probes.items():
        for set_name in row["sets"]:
            sets.setdefault(set_name, [])
            if probe_id not in sets[set_name]:
                sets[set_name].append(probe_id)
    version = _get(raw, "garak_version")
    return ProbeCatalog(
        garak_version=str(version) if version else None, probes=probes, sets=sets,
    )


def _catalog_loader(module: Any) -> Callable[[], Any] | None:
    for name in ("load_catalog", "read_catalog", "catalog", "get_catalog"):
        candidate = getattr(module, name, None)
        if callable(candidate):
            return cast("Callable[[], Any]", candidate)
    for name in ("CATALOG", "PROBE_CATALOG"):
        constant = getattr(module, name, None)
        if constant is not None:
            def _constant(value: Any = constant) -> Any:
                return value

            return _constant
    return None


def load_probe_catalog() -> ProbeCatalog:
    """The committed catalog through ``redsim.ml.llm.catalog`` (no garak import), normalised.

    Raises :class:`CatalogUnavailable` (``kind="not_built"``) when the llm-core
    package is not on the tree, so the routes answer ``501`` with the reason
    instead of an empty list.
    """
    try:
        module = importlib.import_module("redsim.ml.llm.catalog")
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing.startswith("redsim.ml.llm"):
            raise CatalogUnavailable(
                "not_built", "redsim.ml.llm.catalog is not on this tree (plan 12 wave B2, llm-core track)",
            ) from exc
        raise CatalogUnavailable("import_error", str(exc)) from exc
    except ImportError as exc:
        raise CatalogUnavailable("import_error", str(exc)) from exc
    loader = _catalog_loader(module)
    if loader is None:
        raise CatalogUnavailable("invalid", "redsim.ml.llm.catalog exposes no load_catalog() or CATALOG")
    try:
        raw = loader()
    except Exception as exc:  # noqa: BLE001 - a broken snapshot is "unavailable", never an empty list
        raise CatalogUnavailable("invalid", f"{type(exc).__name__}: {exc}") from exc
    catalog = normalise_catalog(raw)
    if not catalog.probes:
        raise CatalogUnavailable("invalid", "the committed catalog lists no probes")
    return catalog


def probe_catalog_response(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The ``GET /v1/llm/probes`` body: probe sets, probes with status and reason, versions and flags."""
    catalog = load_probe_catalog()
    rows = [dict(catalog.probes[pid]) for pid in sorted(catalog.probes)]
    sets = [
        {"id": name, "probe_ids": list(members), "n_probes": len(members),
         "n_offline": sum(1 for pid in members if catalog.probes.get(pid, {}).get("status") == "offline"),
         "n_excluded": sum(1 for pid in members if catalog.probes.get(pid, {}).get("status") == "excluded")}
        for name, members in sorted(catalog.sets.items())
    ]
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in PROBE_STATUSES}
    return {
        "garak_version": catalog.garak_version,
        "default_probe_set": DEFAULT_PROBE_SET if DEFAULT_PROBE_SET in catalog.sets else None,
        "hf_detectors_enabled": hf_detectors_enabled(environ),
        "max_prompts_per_probe": max_prompts_cap(environ),
        "sets": sets,
        "probes": rows,
        "count": len(rows),
        "counts": counts,
        "statuses": {
            "offline": "string/trigger detectors; runs without network or a detector model",
            "extended": "needs a Hugging Face detector model; runs only with detector_mode=hf",
            "excluded": "never run; the catalog records the owner decision and reason",
        },
        "launch_route": "POST /v1/models/{model_id}/probes",
        "limitations": standing_limitations(None),
    }


# ---------------------------------------------------------------------------
# LLM target registration (``POST /v1/models`` source=endpoint endpoint_kind=llm)
# ---------------------------------------------------------------------------


def _clean_token(value: Any, *, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if len(text) > max_len or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return ""
    return text


def find_llm_registration(session: Session, project_id: str, *, model_id: str, host: str,
                          persona: str) -> Target | None:
    """The live LLM target of ``project_id`` for the same model, gateway host and persona, if any."""
    from sqlalchemy import select

    from redsim.db.models import Target
    from redsim.services.ml_models import is_deleted

    rows = session.execute(
        select(Target).where(Target.project_id == project_id, Target.kind == "ml_model_endpoint")
    ).scalars().all()
    for row in rows:
        detail = _detail(row)
        if detail.get("endpoint_kind") != LLM_ENDPOINT_KIND or is_deleted(detail):
            continue
        if (detail.get("model_id") == model_id and detail.get("gateway_host") == host
                and detail.get("persona") == persona):
            return row
    return None


def register_llm_target(
    session: Session,
    *,
    project_id: str,
    fields: Mapping[str, Any],
    actor: str,
    audit_writer: AuditWriter,
    config: RedsimConfig,
    environ: Mapping[str, str] | None = None,
) -> Target:
    """Admission boundary for an LLM target (register LLM-03, -04, -26, -32).

    ``fields`` is the request body of ``POST /v1/models`` (``source="endpoint"``,
    ``endpoint_kind="llm"``): ``model_id`` (canonical ``<vendor>/<model>``),
    ``persona``, ``guardrail_mode``, ``auth_profile_id`` (a ``bearer`` profile of
    the same project holding the ``pk_`` key), optional ``gateway_url`` (else
    ``PYTHIA_BASE_URL``) and ``name``. The caller has already run
    ``ensure_project_access`` and the ``target.manage`` / ``model.register``
    role gate.

    Order: static field checks, profile lookup, the B0 egress rules on the URL
    (``redsim.ml.endpoint_egress.check_registration_url``), the duplicate check,
    then the ``model.register`` audit row with the gateway URL as target (the
    host allowlist applies; spec 5.11), then the ``Target`` row on ``session``
    (the caller owns the transaction). Every refusal writes a ``success=False``
    ``model.register`` row before it is raised; the caller converts the
    :class:`ApiError` with ``as_http_exception`` and writes nothing else.
    """
    from redsim.llm.router import is_pythia_canonical
    from redsim.safety import AuthorizationError, authorize

    env = os.environ if environ is None else environ
    model_id = str(fields.get("model_id") or "").strip()
    persona = _clean_token(fields.get("persona"))
    guardrail_mode = str(fields.get("guardrail_mode") or "").strip()
    auth_profile_id = str(fields.get("auth_profile_id") or "").strip()
    gateway_url = str(fields.get("gateway_url") or env.get(GATEWAY_ENV, "") or "").strip()
    host = gateway_host(gateway_url)
    context: dict[str, Any] = {
        "kind": "ml_model_endpoint", "source": "endpoint", "endpoint_kind": LLM_ENDPOINT_KIND,
        "model_id": model_id or None, "persona": persona or None, "guardrail_mode": guardrail_mode or None,
        "gateway_host": host or None, "auth_profile_id": auth_profile_id or None,
    }

    def refuse(exc: ApiError) -> NoReturn:
        _refuse(audit_writer, action=REGISTER_ACTION, actor=actor, project_id=project_id, exc=exc, **context)

    if not model_id or not is_pythia_canonical(model_id):
        refuse(ApiError(MODEL_ID_INVALID, "model_id must be a canonical Pythia id (<vendor>/<model> or "
                        "pythia/auto)", field="model_id", reason="model_id_invalid"))
    if _EMBEDDING_PATTERN.search(model_id):
        refuse(ApiError(MODEL_NOT_CHAT, f"{model_id!r} is an embedding model, not a chat model; probes need a "
                        "chat completion endpoint", field="model_id", reason="model_not_chat"))
    if not persona:
        refuse(ApiError(PARAMS_OUT_OF_RANGE, "persona is required: the Pythia persona the probe key is scoped to "
                        "(register LLM-26)", field="persona", reason="persona_required"))
    if guardrail_mode not in GUARDRAIL_MODES:
        refuse(ApiError(PARAMS_OUT_OF_RANGE, f"guardrail_mode must be one of {list(GUARDRAIL_MODES)}: it declares "
                        "what the hit rates measure", field="guardrail_mode", allowed=list(GUARDRAIL_MODES),
                        reason="guardrail_mode_required"))
    if not auth_profile_id:
        refuse(ApiError(AUTH_PROFILE_REQUIRED, "auth_profile_id is required: the probe key lives in a bearer "
                        "AuthProfile, never in the request or the environment", field="auth_profile_id",
                        reason="auth_profile_required"))
    from redsim.db.models import AuthProfile

    profile = session.get(AuthProfile, auth_profile_id)
    if profile is None or str(profile.project_id) != str(project_id):
        refuse(ApiError(NOT_FOUND, f"auth profile {auth_profile_id!r} is not in project {project_id!r}",
                        field="auth_profile_id"))
    if str(profile.kind) != PROBE_AUTH_KIND:
        refuse(ApiError(AUTH_PROFILE_KIND_UNSUPPORTED, f"auth profile kind {profile.kind!r} cannot carry a probe "
                        f"key; the Pythia gateway takes Authorization: Bearer (kind {PROBE_AUTH_KIND!r})",
                        field="auth_profile_id", kind=str(profile.kind), allowed=[PROBE_AUTH_KIND]))
    if not gateway_url:
        refuse(ApiError(GATEWAY_URL_REQUIRED, f"gateway_url is required when {GATEWAY_ENV} is not set on the API",
                        field="gateway_url", reason="gateway_url_required"))

    from redsim.ml.endpoint_egress import EgressRefused, EndpointNotAllowlisted, check_registration_url

    allowlist = list(getattr(config, "target_allowlist", None) or [])
    try:
        parsed = check_registration_url(gateway_url, allowlist)
    except EndpointNotAllowlisted as exc:
        egress = {k: v for k, v in exc.detail().items() if k != "code"}
        refuse(ApiError(ENDPOINT_NOT_ALLOWLISTED, f"gateway host {exc.host!r} is not in target_allowlist; add "
                        "the Pythia gateway host to redsim.yaml", field="gateway_url", **egress))
    except EgressRefused as exc:
        egress = {k: v for k, v in exc.detail().items() if k != "code"}
        refuse(ApiError(ENDPOINT_URL_INVALID, exc.reason, field="gateway_url", egress_code=exc.code, **egress))
    gateway_url = parsed.url
    host = parsed.host
    context["gateway_host"] = host

    existing = find_llm_registration(session, project_id, model_id=model_id, host=host, persona=persona)
    if existing is not None:
        refuse(ApiError(ALREADY_REGISTERED, f"LLM target for {model_id!r} on {host!r} with persona {persona!r} is "
                        f"already registered in project {project_id!r}", target_id=existing.id))

    target_id = f"llm-{uuid4().hex[:12]}"
    # The gateway and persona are recorded in the manifest and shown as a badge; the
    # default name is the model id alone (owner request, 2026-09-09).
    name = str(fields.get("name") or model_id).strip()[:256]
    expected_garak: str | None = None
    try:
        expected_garak = load_probe_catalog().garak_version
    except CatalogUnavailable as exc:
        logger.info("LLM target %s registered without a catalog garak version: %s", target_id, exc.reason)

    # The chained event precedes the row (spec 6.7 invariant 4, 9.3 step 4). The gateway URL is the
    # audit target so the host allowlist applies (spec 5.11); a failed check is the writer's own row.
    try:
        authorize(
            REGISTER_ACTION, gateway_url, allowlist=allowlist, actor=actor, writer=audit_writer,
            project_id=project_id,
            detail={
                **context, "target_id": target_id, "modality": LLM_MODALITY, "format": "endpoint",
                "name": name, "catalog_garak_version": expected_garak,
            },
        )
    except AuthorizationError as exc:
        raise ApiError(ENDPOINT_NOT_ALLOWLISTED, str(exc), field="gateway_url", host=host) from exc

    registered_at = datetime.now(UTC).isoformat()
    manifest: dict[str, Any] = {
        "name": name, "modality": LLM_MODALITY, "format": "endpoint", "sha256": None, "size_bytes": 0,
        "endpoint_kind": LLM_ENDPOINT_KIND, "model_id": model_id, "gateway_host": host, "persona": persona,
        "guardrail_mode": guardrail_mode, "auth_profile_id": auth_profile_id, "gradients": False,
        "status": "available", "garak_version_expected": expected_garak, "license": None,
    }
    detail: dict[str, Any] = {
        **manifest,
        "kind": "ml_model_endpoint",
        "source": "endpoint",
        "gateway_url": gateway_url,
        "refusal_reason": None,
        "reason": None,
        "manifest": manifest,
        "validation": {"entitlement": "unverified", "n_entitled": None, "checked_at": None,
                       "ingest_job_id": None, "ingest_run_id": None},
        "registered_by": actor,
        "registered_at": registered_at,
    }
    from redsim.db.models import Target

    target = Target(id=target_id, project_id=project_id, kind="ml_model_endpoint", value=gateway_url, verified=True)
    target.detail = detail
    session.add(target)
    session.flush()
    logger.info("register_llm_target project_id=%s target_id=%s model_id=%s host=%s persona=%s",
                project_id, target_id, model_id, host, persona)
    return target


# ---------------------------------------------------------------------------
# Probe-run admission (``POST /v1/models/{id}/probes``)
# ---------------------------------------------------------------------------


def _start_of_utc_day(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _in_flight_probe_job(session: Session, *, project_id: str, target_id: str) -> Any | None:
    from sqlalchemy import select

    from redsim.db.models import Job

    rows = session.execute(
        select(Job).where(Job.project_id == project_id, Job.type == LLM_JOB_TYPE,
                          Job.status.in_(("queued", "running")))
    ).scalars().all()
    for job in rows:
        if (job.detail or {}).get("target_id") == target_id:
            return job
    return None


def _probe_jobs_today(session: Session, *, project_id: str, now: datetime | None = None) -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Job

    start = _start_of_utc_day(now)
    count = session.execute(
        select(func.count()).select_from(Job).where(
            Job.project_id == project_id, Job.type == LLM_JOB_TYPE, Job.created_at >= start,
        )
    ).scalar_one()
    return int(count or 0)


def resolve_probes(
    catalog: ProbeCatalog, body: LLMProbeRequest, *, environ: Mapping[str, str] | None = None,
) -> tuple[str | None, list[str], list[dict[str, Any]]]:
    """``(probe_set, admitted probe ids, not_admitted rows)`` for a request, or an :class:`ApiError`.

    Explicit ``probe_ids`` must every one be runnable under the requested
    detector mode (an unknown, excluded or detector-unavailable id refuses the
    request). A ``probe_set`` is admitted as its runnable members; members that
    cannot run are recorded with their reason so the scorecard can name them.
    """
    if body.probe_set is not None and body.probe_ids is not None:
        raise ApiError(PARAMS_OUT_OF_RANGE, "name either probe_set or probe_ids, not both", field="probe_ids")
    hf_ok = hf_detectors_enabled(environ)
    if body.detector_mode == "hf" and not hf_ok:
        raise ApiError(PROBE_DETECTOR_UNAVAILABLE, f"detector_mode='hf' needs {HF_DETECTORS_ENV}=1 and a pre-cached "
                       "detector model directory on the worker", field="detector_mode",
                       reason="probe_detector_unavailable")

    def runnable(probe_id: str) -> str | None:
        """``None`` when the probe can run under this mode, else the reason it cannot."""
        row = catalog.probes[probe_id]
        if row["status"] == "excluded":
            return f"probe_excluded: {row['reason']}"
        if row["status"] == "extended" and body.detector_mode != "hf":
            return f"probe_detector_unavailable: {row['reason']}"
        return None

    if body.probe_ids is not None:
        requested = list(dict.fromkeys(str(p).strip() for p in body.probe_ids if str(p).strip()))
        if not requested:
            raise ApiError(PARAMS_OUT_OF_RANGE, "probe_ids must name at least one probe", field="probe_ids")
        unknown = [p for p in requested if p not in catalog.probes]
        if unknown:
            raise ApiError(UNKNOWN_PROBE, f"unknown probe ids {unknown}; see GET /v1/llm/probes", field="probe_ids",
                           reason="unknown_probe", unknown=unknown)
        excluded = [p for p in requested if catalog.probes[p]["status"] == "excluded"]
        if excluded:
            raise ApiError(PROBE_EXCLUDED, f"probes {excluded} are excluded by the catalog", field="probe_ids",
                           reason="probe_excluded", probes=excluded,
                           reasons={p: catalog.probes[p]["reason"] for p in excluded})
        unavailable = [p for p in requested if runnable(p) is not None]
        if unavailable:
            raise ApiError(PROBE_DETECTOR_UNAVAILABLE, f"probes {unavailable} need detector_mode='hf'",
                           field="probe_ids", reason="probe_detector_unavailable", probes=unavailable,
                           reasons={p: catalog.probes[p]["reason"] for p in unavailable})
        return None, requested, []

    probe_set = body.probe_set or DEFAULT_PROBE_SET
    if probe_set not in catalog.sets:
        raise ApiError(PROBE_SET_UNKNOWN, f"probe set {probe_set!r} is not in the catalog", field="probe_set",
                       known=sorted(catalog.sets))
    admitted: list[str] = []
    not_admitted: list[dict[str, Any]] = []
    for probe_id in catalog.sets[probe_set]:
        if probe_id not in catalog.probes:
            not_admitted.append({"probe_id": probe_id, "status": "unknown", "reason": "not in the probe table"})
            continue
        reason = runnable(probe_id)
        if reason is None:
            admitted.append(probe_id)
        else:
            not_admitted.append({"probe_id": probe_id, "status": catalog.probes[probe_id]["status"],
                                 "reason": reason})
    if not admitted:
        raise ApiError(PROBE_DETECTOR_UNAVAILABLE, f"no probe of set {probe_set!r} can run with detector_mode="
                       f"{body.detector_mode!r}", field="probe_set", reason="probe_detector_unavailable",
                       not_admitted=not_admitted)
    return probe_set, admitted, not_admitted


def _enqueue(job_id: str) -> str | None:
    """``ml_llm_probe_run.apply_async`` on the default queue; the Celery task id when the broker returned one."""
    from redsim.workers.tasks.ml_llm import ml_llm_probe_run

    queued = ml_llm_probe_run.apply_async(args=[job_id], queue="default")
    task_id = getattr(queued, "id", None)
    return str(task_id) if task_id is not None else None


def _delete_admission_rows(run_id: str, job_id: str) -> None:
    from redsim.db.models import Job, Run
    from redsim.db.session import get_session

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is not None:
            sess.delete(job)
        run = sess.get(Run, run_id)
        if run is not None:
            sess.delete(run)


def admit_llm_probe_run(
    *,
    project_id: str,
    target_id: str,
    body: LLMProbeRequest | None,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    enqueue: bool = True,
    environ: Mapping[str, str] | None = None,
) -> LLMProbeHandle:
    """Admission boundary for a probe run (register LLM-11, -12, -21; spec 6.7 invariant 4).

    Refusals (each a ``success=False`` ``llm.probe.run`` row on the project
    chain): ``not_found``, ``llm_target_required`` (a classifier target; use
    ``/attacks``), ``model_load_refused`` (status not ``available``),
    ``probe_key_required`` (the bearer profile is gone), ``not_implemented``
    (the catalog package is not on the tree), ``probe_set_unknown`` /
    ``unknown_probe`` / ``probe_excluded`` / ``probe_detector_unavailable``,
    ``params_out_of_range``, ``job_in_flight``, the daily quota (``429``) and
    ``endpoint_not_allowlisted``. Then, in order: the ``llm.probe.run`` audit
    row with the gateway URL as target, the ``Run`` and ``Job`` rows, the
    enqueue (``503 queue_unavailable`` with the rows removed when the broker
    refuses). Never an ``ml_campaigns`` row.
    """
    from redsim.db.models import AuthProfile, Job, Run, Target
    from redsim.db.session import get_session
    from redsim.safety import AuthorizationError, authorize

    body = body if body is not None else LLMProbeRequest()
    context: dict[str, Any] = {"target_id": target_id, "kind": LLM_RUN_KIND}

    def refuse(exc: ApiError, **more: Any) -> NoReturn:
        _refuse(audit_writer, action=ADMISSION_ACTION, actor=actor, project_id=project_id, exc=exc,
                **context, **more)

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None or target.kind not in {"ml_model_artifact", "ml_model_endpoint"}:
            refuse(ApiError(NOT_FOUND, "model not found"))
        if str(target.project_id) != str(project_id):
            refuse(ApiError(NOT_FOUND, "model not found"))
        detail = _detail(target)
        if not is_llm_target(target):
            refuse(ApiError(LLM_TARGET_REQUIRED, "probe runs need an LLM endpoint target (POST /v1/models "
                            "source=endpoint endpoint_kind=llm); classifier targets run campaigns through "
                            "POST /v1/models/{id}/attacks", target_kind=str(target.kind),
                            modality=detail.get("modality")))
        status = str(detail.get("status") or "")
        if status != "available":
            refuse(ApiError(MODEL_LOAD_REFUSED, f"LLM target status is {status!r}, not 'available'", status=status,
                            refusal_reason=detail.get("refusal_reason")))
        model_id = str(detail.get("model_id") or "")
        gateway_url = str(detail.get("gateway_url") or target.value or "")
        host = str(detail.get("gateway_host") or gateway_host(gateway_url))
        persona = str(detail.get("persona") or "")
        guardrail_mode = str(detail.get("guardrail_mode") or "unknown")
        auth_profile_id = str(detail.get("auth_profile_id") or "")
        context.update({"model_id": model_id, "gateway_host": host, "persona": persona,
                        "guardrail_mode": guardrail_mode, "auth_profile_id": auth_profile_id or None})
        profile = sess.get(AuthProfile, auth_profile_id) if auth_profile_id else None
        if profile is None or str(profile.project_id) != str(project_id) or str(profile.kind) != PROBE_AUTH_KIND:
            refuse(ApiError(PROBE_KEY_REQUIRED, "the target's probe key is not a live bearer AuthProfile of this "
                            "project; re-register the target with a valid auth_profile_id",
                            field="auth_profile_id", reason="probe_key_required"))
        try:
            catalog = load_probe_catalog()
        except CatalogUnavailable as exc:
            if exc.kind == "not_built":
                refuse(ApiError(NOT_IMPLEMENTED, "LLM probe runs need the committed probe catalog, which is not on "
                                "this tree", phase="B", reason=exc.reason))
            refuse(ApiError(QUEUE_UNAVAILABLE, f"the probe catalog could not be read: {exc.reason}",
                            reason="catalog_unavailable"))
        try:
            probe_set, probe_ids, not_admitted = resolve_probes(catalog, body, environ=environ)
        except ApiError as exc:
            refuse(exc)
        cap = max_prompts_cap(environ)
        if body.max_prompts_per_probe > cap:
            refuse(ApiError(PARAMS_OUT_OF_RANGE, f"max_prompts_per_probe {body.max_prompts_per_probe} exceeds the "
                            f"deployment cap {cap} ({MAX_PROMPTS_ENV})", field="max_prompts_per_probe",
                            maximum=cap))
        in_flight = _in_flight_probe_job(sess, project_id=project_id, target_id=target_id)
        if in_flight is not None:
            refuse(ApiError(JOB_IN_FLIGHT, "a probe run is already queued or running for this target",
                            run_id=in_flight.run_id, job_id=in_flight.id), run_id=in_flight.run_id)
        quota = daily_quota(environ)
        used = _probe_jobs_today(sess, project_id=project_id)
        if used >= quota:
            now = datetime.now(UTC)
            retry_after = int((_start_of_utc_day(now) + timedelta(days=1) - now).total_seconds())
            refuse(ApiError(LLM_PROBE_QUOTA_EXCEEDED, f"project {project_id!r} has used {used} of {quota} probe "
                            f"runs today ({QUOTA_ENV})", reason="llm_probe_quota_exceeded", limit=quota,
                            used=used, retry_after=retry_after))

        run_id = f"run-{uuid4().hex[:12]}"
        job_id = f"job-{uuid4().hex[:12]}"
        short_ids = {pid: catalog.short_id(pid) for pid in probe_ids}
        job_detail: LLMProbeJobDetail = {
            "kind": LLM_RUN_KIND,
            "target_id": target_id,
            "model_id": model_id,
            "gateway_url": gateway_url,
            "gateway_host": host,
            "persona": persona,
            "guardrail_mode": guardrail_mode,
            "auth_profile_id": auth_profile_id,
            "probe_set": probe_set,
            "probe_ids": list(probe_ids),
            "probe_short_ids": short_ids,
            "not_admitted": list(not_admitted),
            "max_prompts_per_probe": int(body.max_prompts_per_probe),
            "seed": int(body.seed),
            "detector_mode": body.detector_mode,
            "finding_hit_threshold": float(body.finding_hit_threshold),
            "expected_garak_version": catalog.garak_version,
            "prompt_estimate": len(probe_ids) * int(body.max_prompts_per_probe),
            "requested_by": actor,
        }
        # Spec 6.7 invariant 4 / 21.4: the chained event precedes the rows and the enqueue. The gateway
        # URL is the audit target so the host allowlist applies; a failed check is the writer's own row.
        try:
            authorize(
                ADMISSION_ACTION, gateway_url, allowlist=list(getattr(config, "target_allowlist", None) or []),
                actor=actor, writer=audit_writer, project_id=project_id, run_id=None,
                detail={
                    **context, "run_id": run_id, "job_id": job_id, "probe_set": probe_set,
                    "probe_ids": list(probe_ids), "n_probes": len(probe_ids),
                    "n_not_admitted": len(not_admitted), "max_prompts_per_probe": int(body.max_prompts_per_probe),
                    "seed": int(body.seed), "detector_mode": body.detector_mode,
                    "finding_hit_threshold": float(body.finding_hit_threshold),
                    "catalog_garak_version": catalog.garak_version,
                    "prompt_estimate": job_detail["prompt_estimate"],
                },
            )
        except AuthorizationError as exc:
            raise ApiError(ENDPOINT_NOT_ALLOWLISTED, str(exc), host=host) from exc
        sess.add(Run(
            id=run_id, project_id=project_id, target_id=target_id, mode="api", status="queued",
            scanner=LLM_SCANNER, created_by=actor,
            stage_table={"stage": None, "stages_done": [], "jobs": {}, "kind": LLM_RUN_KIND,
                         "probe_ids": list(probe_ids)},
        ))
        sess.flush()
        sess.add(Job(id=job_id, run_id=run_id, project_id=project_id, type=LLM_JOB_TYPE, status="queued",
                     created_by=actor, detail=dict(job_detail)))
        sess.flush()

    if enqueue:
        try:
            task_id = _enqueue(job_id)
        except Exception as exc:  # noqa: BLE001 - the broker refused: the admission is undone, never half-done
            logger.warning("enqueue failed for probe job %s; admission rows removed", job_id, exc_info=True)
            _delete_admission_rows(run_id, job_id)
            raise ApiError(QUEUE_UNAVAILABLE, "the job queue refused the probe run; nothing was admitted",
                           reason=type(exc).__name__) from exc
        if task_id is not None:
            with get_session() as sess:
                job = sess.get(Job, job_id)
                if job is not None:
                    job.celery_task_id = task_id
    return LLMProbeHandle(run_id=run_id, job_ids=[job_id])


# ---------------------------------------------------------------------------
# Reads: the scorecard and the probe-run predicate
# ---------------------------------------------------------------------------


def is_llm_probe_run(session: Session, run_id: str) -> bool:
    """True when ``run_id`` is a probe run (``Run.scanner == "ml.llm_probe"``)."""
    from redsim.db.models import Run

    run = session.get(Run, run_id)
    return run is not None and run.scanner == LLM_SCANNER


def refuse_llm_probe_run(session: Session, run_id: str, *, route: str) -> None:
    """Raise ``409 llm_target_required`` when ``route`` is asked about a probe run (D9).

    ``/campaign`` and ``/compare`` call this before reading a record: probe
    results have no MRI, no ``ml_campaigns`` row and are never compared with
    image or tabular campaigns.
    """
    if is_llm_probe_run(session, run_id):
        raise ApiError(LLM_TARGET_REQUIRED, f"{route} does not apply to an LLM probe run: probe results carry a "
                       "k/n scorecard, never an MRI (D9); read GET /v1/runs/{run_id}/llm-scorecard",
                       run_id=run_id, scorecard_url=f"/v1/runs/{run_id}/llm-scorecard")


def read_llm_scorecard(
    session: Session, run_id: str, *, blob_store: BlobStore | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(scorecard, meta)`` of a probe run from its ``ml.llm.scorecard`` artifact, digest checked.

    ``meta`` carries ``artifact_id``, ``sha256`` and ``run_status``. Raises
    ``ApiError(llm_target_required)`` for a run that is not a probe run and
    ``ApiError(score_unavailable)`` (with ``status``) while the run is queued or
    running, when a terminal run wrote no scorecard, or when the stored bytes no
    longer match their digest.
    """
    import hashlib
    import json

    from sqlalchemy import select

    from redsim.db.models import Artifact, Run

    run = session.get(Run, run_id)
    if run is None:
        raise ApiError(NOT_FOUND, "run not found")
    if run.scanner != LLM_SCANNER:
        raise ApiError(LLM_TARGET_REQUIRED, "this run is not an LLM probe run; campaign runs are read through "
                       "GET /v1/runs/{run_id}/campaign", run_id=run_id, scanner=run.scanner)
    artifact = session.execute(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.kind == SCORECARD_KIND)
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().first()
    if artifact is None:
        if run.status in {"queued", "running"}:
            raise ApiError(SCORE_UNAVAILABLE, f"the probe run is {run.status}; the scorecard is written when it "
                           "completes", status=run.status, run_id=run_id)
        raise ApiError(SCORE_UNAVAILABLE, f"the probe run {run.status} without a scorecard", status=run.status,
                       run_id=run_id, error=(run.stage_table or {}).get("error"))
    if blob_store is None:
        from redsim.storage.blobs import open_blob_store

        blob_store = open_blob_store()
    data = blob_store.get(str(artifact.location))
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if hashlib.sha256(raw).hexdigest() != str(artifact.sha256):
        raise ApiError(SCORE_UNAVAILABLE, "scorecard artifact bytes do not match the recorded digest",
                       status=run.status, run_id=run_id, artifact_id=artifact.id)
    scorecard = json.loads(raw)
    if not isinstance(scorecard, dict):
        raise ApiError(SCORE_UNAVAILABLE, "scorecard artifact is not a JSON object", status=run.status,
                       run_id=run_id)
    return scorecard, {"artifact_id": artifact.id, "sha256": str(artifact.sha256), "run_status": run.status}


def probe_history(session: Session, target_id: str) -> list[dict[str, Any]]:
    """Probe runs on an LLM target, newest first (the ``GET /v1/models/{id}`` history of an LLM row)."""
    from sqlalchemy import select

    from redsim.db.models import Run

    runs = session.execute(
        select(Run).where(Run.target_id == target_id, Run.scanner == LLM_SCANNER)
        .order_by(Run.created_at.desc(), Run.id.desc())
    ).scalars().all()
    out: list[dict[str, Any]] = []
    for run in runs:
        table = dict(run.stage_table or {})
        out.append({
            "run_id": run.id, "kind": LLM_RUN_KIND, "status": run.status,
            "created_at": run.created_at.isoformat() if run.created_at is not None else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at is not None else None,
            "probe_ids": list(table.get("probe_ids") or []),
            "scorecard_url": f"/v1/runs/{run.id}/llm-scorecard" if run.status == "succeeded" else None,
            "status_url": f"/v1/runs/{run.id}",
        })
    return out


__all__: Sequence[str] = [
    "ADMISSION_ACTION",
    "D9_SENTENCE",
    "DEFAULT_MAX_PROMPTS_PER_PROBE",
    "DEFAULT_PROBE_SET",
    "DEFAULT_QUOTA_PER_DAY",
    "GATEWAY_ENV",
    "GUARDRAIL_LIMITATION",
    "GUARDRAIL_MODES",
    "HF_DETECTORS_ENV",
    "LLM_ENDPOINT_KIND",
    "LLM_JOB_TYPE",
    "LLM_MODALITY",
    "LLM_RUN_KIND",
    "LLM_SCANNER",
    "LLM_STANDING_LIMITATIONS",
    "LLM_TASK_NAME",
    "LLM_USAGE_TASK",
    "MAX_PROMPTS_ENV",
    "PK_PATTERN",
    "PROBE_AUTH_KIND",
    "PROBE_STATUSES",
    "QUOTA_ENV",
    "REGISTER_ACTION",
    "SCORECARD_KIND",
    "CatalogUnavailable",
    "LLMProbeHandle",
    "LLMProbeJobDetail",
    "LLMProbeRequest",
    "ProbeCatalog",
    "admit_llm_probe_run",
    "daily_quota",
    "find_llm_registration",
    "gateway_host",
    "hf_detectors_enabled",
    "is_llm_probe_run",
    "is_llm_target",
    "load_probe_catalog",
    "max_prompts_cap",
    "normalise_catalog",
    "probe_catalog_response",
    "probe_history",
    "read_llm_scorecard",
    "refuse_llm_probe_run",
    "register_llm_target",
    "resolve_probes",
    "standing_limitations",
]
