"""The shared campaign frame and the ``ModalityRunner`` contract (Phase B, MODALITIES-09).

``redsim.ml.campaign.run_campaign`` is a frame: it resolves the target and the attack set, runs the
stage bookkeeping (``stages_done`` and the live ``on_stage`` callback), owns the evidence lists
(measurements, observations, interpretation, limitations, nondeterminism), writes the curve and
flip-matrix artifacts, scores, interprets, recommends and assembles the record with its provenance.
Everything that depends on what a sample *is* (a float32 image or feature tensor with integer
labels, a string slice, an image with a list of boxes) lives in a modality runner.

A runner is a callable ``run_<modality>(config, target, *, frame) -> ModalityResult``. It performs
the ``sample``, ``clean_eval``, ``attack:<attack_id>`` and ``control`` stages by appending rows to
``frame.measurements`` and calling ``frame.stage_done(...)`` in that order, reports an attack that
cannot run through ``frame.record_not_run(...)`` (spec 9.5: no row, no curve, no finding, removed
from the in-scope set before scoring) and returns a :class:`ModalityResult` that tells the frame
how many samples it measured, which indices, the per-attack flip matrix, whether an accuracy
curve and an MRI apply to this modality, and a closure that runs the ``explain`` stage at the
reference budget (``None`` when the modality has no explainer; the frame then records that). The
frame runs the closure *after* it has written the curve and flip-matrix artifacts, which keeps the
artifact and limitation order of the pre-refactor classification path.

Runners are looked up by modality in :data:`MODALITY_RUNNERS` and imported lazily, so a modality
whose runner module has not landed is reported as ``ModalityRunnerUnavailable`` before any stage
runs, never faked. The classification runner (``image`` and ``tabular``) is today's code moved;
``text`` and ``detection`` are sibling tracks that register ``run_text`` and ``run_detection`` by
these names.

Ground rules the frame enforces for every modality: the MRI describes one campaign and is never
aggregated across modalities (each run has one modality); a modality that declares ``mri=False``
(detection) gets a score status of ``unavailable`` with its reason and never an MRI; measurements
carry ``n`` and their denominators; the control runs at the same budget as the attacks; nothing
unavailable is interpolated.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import inspect
import io
import json
import logging
import math
import os
import tempfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast, get_args

import numpy as np

from redsim.ml.artifacts import ArtifactSink
from redsim.ml.errors import MLError
from redsim.ml.schema import (
    CampaignConfig,
    Interpretation,
    Measurement,
    Modality,
    Observation,
    RobustnessCurve,
    TargetInfo,
)
from redsim.ml.targets.base import Target

logger = logging.getLogger(__name__)

# --- shared vocabulary (spec 12.2, 12.4, 12.9, 13.4) ----------------------------------------------------

CONTROL_ATTACK_ID = "noise_control"
DEFAULT_MAX_ADV_ARTIFACT_MB = 64.0                   # spec 12.8

REALIZABILITY_CAVEAT = "feature-space perturbation; realizability not established"
TABULAR_LIMITATION = (
    "Tabular evasion rows are feature-space perturbations; a perturbed feature vector is evidence about "
    "the decision surface and is a realizable attack only if it maps back to a constructible input, which "
    "this run neither constructs nor checks. L-inf budgets on mixed-type features are a further caveat.")
# Spec 13.4: appended to Observation.metric_note and the limitations when the manifest flags subject_centered=false.
SUBJECT_CENTERED_CAVEAT = (
    "The dataset manifest flags subject_centered=false: subjects are not reliably centred or tightly framed, so the "
    "centre-mass ratio is weaker evidence of attention on the subject on this dataset than on a centred fixture; it "
    "stays a heuristic proxy.")
# Spec 12.9: white-box rows on a tree ensemble came from the declared surrogate; scored on the real model.
SURROGATE_TRANSFER_LIMITATION_TEMPLATE = (
    "White-box rows for {attacks} were computed by surrogate transfer: the gradients came from the declared surrogate "
    "({surrogate}), the adversarial rows were scored on the real model. They measure the transfer of gradient-aligned "
    "perturbations onto the target, not direct white-box access to it, and remain feature-space evidence whose "
    "realizability is not established.")
# Spec 12.2 / 12.9 row label for surrogate-transfer rows (the adapters use the same prefix).
SURROGATE_NOTE_PREFIX = "white-box via surrogate transfer: "
CURVE_PNG_NAME = "curve/robustness_curve.png"          # spec 12.3, Artifact kind ml.curve (rendered form)
#: Explainer module per domain (spec 13). A domain absent here has no explainer and the frame says so.
EXPLAIN_MODULES: dict[str, str] = {"image": "redsim.ml.explain.shap_image", "tabular": "redsim.ml.explain.shap_tabular"}
# The reference-row Measurement fields the explain stage supplies (spec 13.5; ``explain.base.MEASUREMENT_FIELDS``).
EXPLAIN_FIELDS = ("expl_shift_mean", "expl_shift_n", "expl_shift_n_excluded", "expl_shift_noise_floor",
                  "expl_shift_noise_floor_n")

#: Registry of modality runners: one entry per ``schema.Modality`` literal, ``"<module>:<attribute>"``,
#: imported lazily by :func:`resolve_runner` (a runner module that fails to import is reported as
#: ``ModalityRunnerUnavailable`` before any stage runs, never replaced by another modality's runner).
MODALITY_RUNNERS: dict[str, str] = {
    "image": "redsim.ml.runners.classification:run_classification",
    "tabular": "redsim.ml.runners.classification:run_classification",
    "text": "redsim.ml.runners.text:run_text",
    "detection": "redsim.ml.runners.detection:run_detection",
}
if set(MODALITY_RUNNERS) != set(get_args(Modality)):   # a Modality literal without a runner is a build error
    raise RuntimeError(f"MODALITY_RUNNERS {sorted(MODALITY_RUNNERS)} does not match schema.Modality "
                       f"{sorted(get_args(Modality))}")

#: Offline pins for the sandbox child (MODALITIES-10): WordNet lives under the assets dir, torch hub and
#: weight caches are pointed inside the work dir so nothing downloads. Applied only when unset.
NLTK_DATA_ENV = "NLTK_DATA"
TORCH_HOME_ENV = "TORCH_HOME"
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
NLTK_DATA_SUBDIR = Path("lexicons") / "nltk_data"


class ModalityRunnerUnavailable(MLError):
    """No runner is importable for the campaign's modality (the module has not landed or failed to import)."""

    code = "modality_runner_unavailable"


# --- small helpers shared by the frame and the runners ---------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(UTC)


def manifest_get(manifest: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in manifest and manifest[k] is not None:
            return manifest[k]
    return None


def max_adv_artifact_bytes() -> int:
    raw = os.environ.get("REDSIM_ML_MAX_ADV_ARTIFACT_MB", "").strip()
    try:
        mb = float(raw) if raw else DEFAULT_MAX_ADV_ARTIFACT_MB
    except ValueError:
        mb = DEFAULT_MAX_ADV_ARTIFACT_MB
    return int(mb * 1024 * 1024)


def npz_bytes(x_adv: np.ndarray, indices: np.ndarray, y: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.savez_compressed(buf, x_adv=x_adv, indices=indices, y=y)
    return buf.getvalue()


#: Slice families every runner writes (mirrors ``redsim.ml.interop.parquet.FAMILY_*``; the runners never
#: import the export). The attack label of the control family is the shared control adapter id.
SLICE_FAMILY_CLEAN = "clean"
SLICE_FAMILY_ADVERSARIAL = "adversarial"
SLICE_FAMILY_CONTROL = "control"
#: Row note when a slice was not retained under the ``REDSIM_ML_MAX_ADV_ARTIFACT_MB`` cap (never faked).
SLICE_NOT_RETAINED_NOTE = "{what} slice not retained (over REDSIM_ML_MAX_ADV_ARTIFACT_MB)"


def slice_bytes(*, family: str, attack: str, eps: float | None, **arrays: Any) -> bytes:
    """A self-describing per-sample export slice (INTEROP-04), shared by every modality runner.

    ``arrays`` are the per-sample columns: ``x`` or ``x_adv`` (a numeric input tensor), ``indices``,
    ``y``, and when the runner has them ``y_pred_clean`` / ``y_pred_adv`` / ``conf_clean`` / ``conf_adv``.
    The text runner carries its message strings as ``text`` / ``text_adv`` (unicode arrays, never
    ``object``) since a text model has no numeric input tensor; the detection runner adds its packed
    ``boxes`` / ``labels`` / ``offsets``. ``family`` / ``attack`` travel as zero-dimensional unicode
    arrays and ``eps`` as a float scalar (omitted for the clean slice), so the export labels the slice
    from its own bytes whatever the blob backend did with its name (``allow_pickle=False`` loads every
    key). Compressed, no pickle: an ``object`` array is refused here rather than pickled.
    """
    payload: dict[str, Any] = {}
    for key, value in arrays.items():
        arr = np.asarray(value)
        if arr.dtype == object:
            arr = np.asarray([str(v) for v in arr.reshape(-1).tolist()], dtype=str).reshape(arr.shape)
        payload[key] = arr
    payload["family"] = np.asarray(family)
    payload["attack"] = np.asarray(attack)
    if eps is not None:
        payload["eps"] = np.asarray(float(eps), dtype=np.float64)
    buf = io.BytesIO()
    np.savez_compressed(buf, **payload)
    return buf.getvalue()


def json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")


def split_notes(notes: list[str], nondeterminism_prefix: str) -> tuple[list[str], list[str]]:
    """Separate ``nondeterminism: ...`` notes (-> Provenance) from row notes (-> Measurement)."""
    row, nd = [], []
    for n in notes:
        if n.startswith(nondeterminism_prefix):
            nd.append(n[len(nondeterminism_prefix):])
        else:
            row.append(n)
    return row, nd


def uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def call_supported(fn: Any, *args: Any, **optional: Any) -> Any:
    """Call ``fn`` with the positional contract plus only those optional keywords its signature
    accepts. The explain / recommend modules may extend the base contract with extra keywords
    (``x_ctrl``, ``reference_eps``, ...); a callee that lacks them still gets a valid call."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fn(*args, **optional)
    return fn(*args, **{k: v for k, v in optional.items() if k in params})


def sha256_indices(indices: Any) -> str:
    arr = np.asarray(indices).astype(np.int64)
    return hashlib.sha256(arr.tobytes()).hexdigest()


def as_int(v: Any) -> int | None:
    if isinstance(v, bool) or not isinstance(v, (int, float, np.integer, np.floating)):
        return None
    return int(v)


def as_float(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float, np.integer, np.floating)):
        return None
    return float(v)


def explain_fields(out: Any) -> dict[str, Any]:
    """The reference-row fields from an explainer's output: ``ExplainOutput.measurement_fields()`` when the
    output provides it, else the same-named attributes, else the legacy ``meta`` keys."""
    fields_fn = getattr(out, "measurement_fields", None)
    if callable(fields_fn):
        got = fields_fn()
        if isinstance(got, dict):
            return dict(got)
    meta = dict(getattr(out, "meta", {}) or {})
    return {name: getattr(out, name, meta.get(name)) for name in EXPLAIN_FIELDS}


# --- control predicate (spec 12.4) ----------------------------------------------------------------------

def control_tolerance(acc_clean: float, n: int) -> float:
    """``max(0.02, sqrt(acc_clean * (1 - acc_clean) / n))``: two points or one binomial standard error."""
    if n <= 0:
        return 0.02
    p = min(1.0, max(0.0, float(acc_clean)))
    return max(0.02, math.sqrt(p * (1.0 - p) / n))


def control_verdict(clean: Measurement, control: Measurement) -> tuple[bool, str]:
    """``(preserved, how)`` for the spec 12.4 "control preserves accuracy" predicate on two measurement rows.

    Prefers ``redsim.ml.scoring.control_preserves_accuracy(clean, control)`` (the scoring track's exact
    binomial predicate) and falls back to the local closed form ``|acc_control - acc_clean| <= max(0.02, one
    binomial SE)`` when the symbol is absent or has another calling convention. ``how`` states which
    predicate answered and its thresholds, so the row note and the Interpretation print them."""
    scoring = importlib.import_module("redsim.ml.scoring")
    predicate = getattr(scoring, "control_preserves_accuracy", None)
    if callable(predicate):
        try:
            preserved = bool(predicate(clean, control))
        except TypeError:
            logger.debug("scoring.control_preserves_accuracy has another signature; using the campaign fallback")
        else:
            floor = getattr(scoring, "CONTROL_ACCURACY_FLOOR", 0.02)
            alpha = getattr(scoring, "DEFAULT_CONTROL_ALPHA", 0.05)
            pvalue_fn = getattr(scoring, "control_degradation_pvalue", None)
            p_value = None
            if callable(pvalue_fn):
                with contextlib.suppress(Exception):
                    p_value = pvalue_fn(clean, control)
            how = (f"scoring.control_preserves_accuracy: within {float(floor):g} of the clean accuracy or not "
                   f"significantly below it (one-sided exact binomial test, alpha={float(alpha):g}"
                   + (f", p={float(p_value):.4f})" if isinstance(p_value, (int, float)) else ")"))
            return preserved, how
    acc_clean = clean.n_correct / clean.n if clean.n else 0.0
    acc_control = control.n_correct / control.n if control.n else 0.0
    tol = control_tolerance(acc_clean, control.n)
    return (abs(acc_control - acc_clean) <= tol,
            f"campaign fallback: |acc_control - acc_clean| <= max(0.02, one binomial SE) = {tol:.4f}")


# --- manifest readers (spec 11.5, 13.4) -----------------------------------------------------------------

def manifest_sources(manifest: dict[str, Any], metadata: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [manifest]
    for key in ("dataset", "preprocessing"):
        nested = manifest.get(key)
        if isinstance(nested, dict):
            out.append(nested)
    out.append(metadata)
    return out


def dataset_caveats(manifest: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    """The build-time dataset caveats (spec 11.3) as recorded in the manifest or the target metadata."""
    out: list[str] = []
    for source in manifest_sources(manifest, metadata):
        for key in ("caveats", "dataset_caveats"):
            v = source.get(key)
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
            elif isinstance(v, (list, tuple)):
                out.extend(str(s).strip() for s in v if isinstance(s, str) and s.strip())
    return uniq(out)


def subject_centered(manifest: dict[str, Any], metadata: dict[str, Any]) -> bool | None:
    """The manifest's ``subject_centered`` flag (spec 13.4), ``None`` when the dataset does not declare it."""
    for source in manifest_sources(manifest, metadata):
        v = source.get("subject_centered")
        if isinstance(v, bool):
            return v
    return None


def surrogate_description(manifest: dict[str, Any]) -> str:
    """``kind=..., sha256=..., agreement_clean=k/n`` from the manifest's ``surrogate`` block (spec 5.5)."""
    decl = manifest.get("surrogate")
    if not isinstance(decl, dict):
        return "declared surrogate"
    parts = [f"kind={decl.get('kind', 'unknown')}"]
    sha = decl.get("sha256")
    if isinstance(sha, str) and sha:
        parts.append(f"sha256={sha[:16]}...")
    agree = decl.get("agreement_clean")
    if isinstance(agree, dict) and agree.get("n"):
        n_agree = agree.get("n_correct")
        if n_agree is None and isinstance(agree.get("value"), (int, float)):
            n_agree = round(float(agree["value"]) * int(agree["n"]))
        parts.append(f"agreement_clean={n_agree}/{agree['n']}" if n_agree is not None
                     else f"agreement_clean n={agree['n']}")
    else:
        parts.append("agreement_clean=not recorded")
    return ", ".join(parts)


class SurrogateTargetView:
    """A target whose ``art_classifier()`` is the declared surrogate estimator (spec 12.9 surrogate transfer).

    Everything else (``predict_proba``, ``manifest``, ``info``, ``sample``, feature ranges, ...) is delegated to
    the real target, so the attack's gradients come from the surrogate while every prediction the campaign
    measures comes from the real model. Used only for adapters that need gradients on a target without them."""

    def __init__(self, target: Target, surrogate_clf: Any) -> None:
        self._target = target
        self._surrogate_clf = surrogate_clf
        self.id = target.id

    def art_classifier(self) -> Any:
        return self._surrogate_clf

    def surrogate_art_classifier(self) -> Any:
        return self._surrogate_clf

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target, name)


def surrogate_for_white_box(target: Target) -> Any | None:
    """The surrogate estimator to hand white-box adapters, or ``None`` when the target's own estimator has
    loss gradients (no transfer needed) or no surrogate is declared. Never introduces a surrogate silently:
    the caller notes the transfer on every row and in the limitations."""
    try:
        own = target.art_classifier()
    except Exception:  # noqa: BLE001 - the adapter reports an unusable estimator itself
        own = None
    if own is not None and hasattr(own, "loss_gradient"):
        return None
    getter = getattr(target, "surrogate_art_classifier", None)
    if not callable(getter):
        return None
    try:
        sur = getter()
    except Exception:  # noqa: BLE001 - a broken surrogate is the same as no surrogate; the attack is then not_run
        logger.debug("surrogate_art_classifier() failed", exc_info=True)
        return None
    return sur if sur is not None and hasattr(sur, "loss_gradient") else None


# --- offline pins for the child (MODALITIES-10) ----------------------------------------------------------

def offline_env_pins(work_dir: Path | None) -> dict[str, str]:
    """The ``NLTK_DATA`` / ``TORCH_HOME`` values a campaign runs under when the environment leaves them unset.

    ``NLTK_DATA`` is ``<assets>/lexicons/nltk_data`` when ``REDSIM_ML_ASSETS_DIR`` is set (the sandbox child
    always receives it; the WordNet lexicon is a build-time asset), else an empty directory under the work
    dir. ``TORCH_HOME`` is ``<work_dir>/torch``: an empty hub cache, so a ``weights=...`` lookup finds nothing
    and fails instead of downloading (the child has no network in any case). Nothing is created here."""
    root = work_dir if work_dir is not None else Path(os.environ.get("REDSIM_ML_WORK_DIR")
                                                       or tempfile.gettempdir()) / "redsim-offline"
    assets = os.environ.get(ASSETS_DIR_ENV, "").strip()
    nltk = Path(assets) / NLTK_DATA_SUBDIR if assets else root / "nltk_data"
    return {NLTK_DATA_ENV: str(nltk), TORCH_HOME_ENV: str(root / "torch")}


@contextlib.contextmanager
def pinned_offline_env(work_dir: Path | None) -> Iterator[dict[str, str]]:
    """Apply :func:`offline_env_pins` for the duration of a run, without overriding an explicit setting, and
    restore the previous environment afterwards (in-process callers such as the CLI and the tests keep their
    environment; the sandbox child exits after one run anyway). Yields the pins that took effect."""
    applied: dict[str, str] = {}
    for key, value in offline_env_pins(work_dir).items():
        if not os.environ.get(key):
            os.environ[key] = value
            applied[key] = value
    try:
        yield applied
    finally:
        for key in applied:
            os.environ.pop(key, None)


def sink_work_dir(sink: ArtifactSink) -> Path | None:
    """The directory a filesystem-backed sink belongs to: the sandbox child's ``work_dir`` (so the caches sit
    beside, not inside, the artifact tree the envelope lists), else the sink ``root``; ``None`` for a database sink."""
    for attr in ("work_dir", "root"):
        value = getattr(sink, attr, None)
        if isinstance(value, (str, Path)):
            return Path(value)
    return None


# --- the frame state a runner works against ---------------------------------------------------------------

@dataclass
class CampaignFrame:
    """Shared state of one campaign, owned by ``run_campaign`` and extended by the modality runner.

    The runner appends to the evidence lists, calls :meth:`stage_done` after each stage it completes,
    reports attacks that cannot run through :meth:`record_not_run` and calls :meth:`close_attack_set` once
    its attack loop is over (the frame calls it again, idempotently, when the runner returns)."""

    config: CampaignConfig
    sink: ArtifactSink
    target: Target
    info: TargetInfo
    domain: str
    manifest: dict[str, Any]
    adapters: list[Any]                        # every declared adapter, resolved and bounds-checked, config order
    params_by_attack: dict[str, dict[str, Any]]
    grid: list[float]
    ref: float
    l2: bool
    attack_registry: Any                       # the ATTACKS registry the adapters came from (control lookup)
    explain: bool
    dataset_name: Any
    dataset_revision: Any
    subject_centered: bool | None
    on_stage: Callable[[str], None] | None = None
    measurements: list[Measurement] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    interpretation: list[Interpretation] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    nondeterminism: list[str] = field(default_factory=list)
    versions: dict[str, str] = field(default_factory=dict)
    stages_done: list[str] = field(default_factory=list)
    explain_meta: dict[str, dict[str, Any]] = field(default_factory=dict)   # attack_id -> explainer meta
    not_run: dict[str, str] = field(default_factory=dict)                   # attack_id -> reason (spec 9.5)
    _attack_set_closed: bool = field(default=False, repr=False)
    _in_scope: list[Any] = field(default_factory=list, repr=False)
    _scoring_config: CampaignConfig | None = field(default=None, repr=False)

    def stage_done(self, stage: str) -> None:
        """Record a completed stage and best-effort live progress callback."""
        self.stages_done.append(stage)
        if self.on_stage is not None:
            try:
                self.on_stage(stage)
            except Exception:  # progress cannot invalidate evidence
                logger.debug("live campaign stage callback failed", exc_info=True)

    def record_not_run(self, aid: str, reason: str) -> None:
        """Recorded not_run (spec 9.5, 15.4): no measurement row is written for this attack, it leaves the
        in-scope set before scoring, and the record says so. Nothing is interpolated or faked."""
        self.not_run[aid] = reason
        self.interpretation.append(Interpretation(
            id=f"i.attack.not_run.{aid}",
            statement=(f"Attack {aid!r} was not run against this target ({reason}); it is recorded as not_run "
                       "and was removed from the in-scope attack set before scoring. No evasion measurement, "
                       "curve point or finding exists for it, and the score does not describe robustness to it."),
            basis=["m.clean"]))
        self.limitations.append(f"Attack {aid!r} was not run ({reason}); it was removed from the in-scope attack set "
                                "before scoring and no evasion row, curve or finding exists for it.")

    def close_attack_set(self) -> list[Any]:
        """Fix the in-scope attack set to what ran (spec 15.4). The declared config stays on the record and in
        the settings hash; scoring, curves and the explain stage read the reduced set. Idempotent."""
        if not self._attack_set_closed:
            self._attack_set_closed = True
            self._in_scope = [a for a in self.adapters if a.id not in self.not_run]
            ids = [a.id for a in self._in_scope]
            self._scoring_config = self.config if not self.not_run else self.config.model_copy(update={
                "attack_ids": ids,
                "attack_params": {k: v for k, v in self.config.attack_params.items() if k in ids}})
            if not self._in_scope:
                self.limitations.append("No declared attack could run against this target (all recorded not_run); "
                                        "the campaign carries clean and control rows only and no score.")
        return list(self._in_scope)

    @property
    def in_scope_adapters(self) -> list[Any]:
        return self.close_attack_set()

    @property
    def in_scope_ids(self) -> list[str]:
        return [a.id for a in self.close_attack_set()]

    @property
    def scoring_config(self) -> CampaignConfig:
        self.close_attack_set()
        assert self._scoring_config is not None
        return self._scoring_config


@dataclass
class ModalityResult:
    """What a modality runner hands back to the frame after the ``control`` stage."""

    n: int                                          # samples measured (every row's denominator ``n``)
    indices: Sequence[int] | np.ndarray             # dataset indices of the slice (flip matrix, provenance)
    flip_matrix: dict[str, dict[str, list[bool]]]   # attack_id -> eps tag -> per-sample flipped (clean-correct & wrong)
    explain: Callable[[], None] | None = None       # runs the explain stage at the reference budget; None: no explainer
    curves: bool = True                             # derive accuracy-over-eps curves from the measurement table (12.3)
    mri: bool = True                                # score with the MRI; False: score status unavailable (detection)
    score_unavailable_reason: str | None = None     # required when ``mri`` is False
    trailing_limitations: list[str] = field(default_factory=list)   # modality caveats appended at the report stage
    flip_matrix_extra: dict[str, Any] = field(default_factory=dict)  # extra keys merged into flip_matrix.json


class ModalityRunner(Protocol):
    """``run_<modality>(config, target, *, frame) -> ModalityResult``: the sample, clean_eval, attack and
    control stages of one modality, plus its explain closure (see the module docstring)."""

    def __call__(self, config: CampaignConfig, target: Target, *, frame: CampaignFrame) -> ModalityResult: ...


def resolve_runner(modality: str) -> ModalityRunner:
    """The runner registered for ``modality``, imported lazily. ``ModalityRunnerUnavailable`` names the missing
    module or attribute so the record (or the refusal) says why, before any stage runs."""
    spec = MODALITY_RUNNERS.get(modality)
    if spec is None:
        raise ModalityRunnerUnavailable(f"no modality runner is registered for {modality!r}; "
                                        f"registered: {sorted(MODALITY_RUNNERS)}")
    module_name, _, attr = spec.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ModalityRunnerUnavailable(f"the {modality!r} runner module {module_name!r} is not importable "
                                        f"({exc}); the modality is recorded unavailable") from exc
    runner = getattr(module, attr, None)
    if not callable(runner):
        raise ModalityRunnerUnavailable(f"{module_name!r} defines no callable {attr!r} for the {modality!r} runner")
    return cast(ModalityRunner, runner)


__all__ = [
    "CONTROL_ATTACK_ID",
    "CURVE_PNG_NAME",
    "DEFAULT_MAX_ADV_ARTIFACT_MB",
    "EXPLAIN_FIELDS",
    "EXPLAIN_MODULES",
    "MODALITY_RUNNERS",
    "NLTK_DATA_ENV",
    "REALIZABILITY_CAVEAT",
    "SLICE_FAMILY_ADVERSARIAL",
    "SLICE_FAMILY_CLEAN",
    "SLICE_FAMILY_CONTROL",
    "SLICE_NOT_RETAINED_NOTE",
    "SUBJECT_CENTERED_CAVEAT",
    "SURROGATE_NOTE_PREFIX",
    "SURROGATE_TRANSFER_LIMITATION_TEMPLATE",
    "TABULAR_LIMITATION",
    "TORCH_HOME_ENV",
    "CampaignFrame",
    "ModalityResult",
    "ModalityRunner",
    "ModalityRunnerUnavailable",
    "RobustnessCurve",
    "SurrogateTargetView",
    "as_float",
    "as_int",
    "call_supported",
    "control_tolerance",
    "control_verdict",
    "dataset_caveats",
    "explain_fields",
    "json_bytes",
    "manifest_get",
    "max_adv_artifact_bytes",
    "npz_bytes",
    "offline_env_pins",
    "pinned_offline_env",
    "resolve_runner",
    "sha256_indices",
    "sink_work_dir",
    "slice_bytes",
    "split_notes",
    "subject_centered",
    "surrogate_description",
    "surrogate_for_white_box",
    "uniq",
    "utcnow",
]
