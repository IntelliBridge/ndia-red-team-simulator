"""``defense_apply``: re-train a copy of a torch target with a ``kind: training`` defense (spec 16.5, 16.6).

The verify runner (``campaign._apply_defense``) calls :func:`apply_training_defense` inside
the sandbox child after ``load_target`` and before ``sample`` as
``hook(target, config.defense, config=config, sink=sink, seed=config.seed)`` and gets back a
:class:`DerivedTorchTarget`: the derived module behind the ``Target`` protocol for the whole
re-run (attacks, control, explanations), whose ``describe()`` is the :class:`TrainingRecord`'s
provenance (``Provenance.defense``) and whose ``manifest()`` keeps the parent's digest keys
(``Provenance.model_sha256`` stays the parent's, the 15.6 identity). :func:`train_defense` is
the same run returning ``(derived module, TrainingRecord)`` for callers that want the bare
module. With a ``sink`` the derived ``state_dict`` and the report are written as
``derived_model/weights.pt`` and ``derived_model/training_report.json`` so the worker parent
can register the derived target (:meth:`TrainingRecord.derived_from`).

What is and is not measured: the record carries the clean training-slice accuracy before
and after as ``k`` of ``n`` (the evaluation split is the campaign's business), the loss per
epoch, the epochs actually run against the wall budget and both weight digests. Nothing
about the hardening's effect on the evaluation split is claimed here; the re-run measures
it and the 15.6 rule reports the delta.

Targets without a trainable torch module (a tabular tree ensemble, register item
ATTACKS_HARDEN-20) are refused with a typed :class:`TrainingUnavailable`, which the caller
records; a missing training slice is the same type with ``infeasible: False``.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import io
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, Field

from redsim.ml.datasets.sampling import Sample, as_model_input, per_class_counts, stratified_sample
from redsim.ml.defenses import (
    ADVERSARIAL_TRAINING_LIMIT,
    DISTILLATION_ART_NOTE,
    DISTILLATION_BYPASS,
    DefenseSpec,
    get_defense,
    resolve_defense_params,
    resolve_defense_spec,
)
from redsim.ml.errors import MLError
from redsim.ml.schema import DefenseConfig, TargetInfo
from redsim.ml.targets.base import Target

Log = Callable[[str], None]
Clock = Callable[[], float]

WEIGHTS_ARTIFACT = "derived_model/weights.pt"                 # kind ml.derived_model (application/octet-stream)
REPORT_ARTIFACT = "derived_model/training_report.json"        # kind ml.training_report (application/json)

TREE_ENSEMBLE_REASON = (
    "tree ensembles have no gradient-based adversarial training in ART (AdversarialTrainer needs a loss-gradient "
    "estimator and DefensiveDistillation a trainable probabilistic student of the same family); retrain-time "
    "augmentation is outside the tool (spec 3.3 non-goal: training pipelines)")
NO_TORCH_MODULE_REASON = ("the target exposes no torch module (torch_model() is None or not implemented); only a "
                          "torch target can be fine-tuned")
NO_TRAIN_SLICE_REASON = ("no training slice: pass train_slice (a Sample, an (x, y) pair or an .npz with x, y) or give "
                         "the target a train_sample(n, seed) method (the bundled slice written by build-assets)")
_HEAD_ATTRS: tuple[str, ...] = ("fc", "classifier", "head", "linear", "output")


def _now() -> float:
    """The wall clock the trainers read (module attribute so tests can drive the budget deterministically)."""
    return time.monotonic()


def seed_everything(seed: int) -> None:
    """Seed numpy's global RNG (ART's shuffles and adversarial-row choice read it), ``random`` and torch (spec 12.7).

    Local to this package so the trainers never import the attack registry (its rows may reference schema
    literals a sibling wave is still landing)."""
    np.random.seed(int(seed) % (2**32))
    random.seed(int(seed))
    try:
        import torch
    except Exception:  # noqa: BLE001 - torch absent: the training defense is unavailable anyway
        return
    torch.manual_seed(int(seed))


def library_versions() -> dict[str, str]:
    """``art``, ``numpy`` and ``torch`` versions for the record (spec 12.5, 14.4)."""
    out: dict[str, str] = {}
    for key, dist in (("art", "adversarial-robustness-toolbox"), ("numpy", "numpy"), ("torch", "torch")):
        try:
            out[key] = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            continue
    return out


# --- typed unavailable ---------------------------------------------------------------------------


class TrainingUnavailable(BaseModel):
    """Why a training defense cannot run on this target: recorded, never worked around."""

    defense_id: str
    target_id: str
    domain: str | None = None
    code: Literal["training_defense_unavailable"] = "training_defense_unavailable"
    reason: str
    infeasible: bool                      # True: by construction of the target; False: environmental (no slice)
    register_item: str | None = None      # "ATTACKS_HARDEN-20" for the tree-ensemble case


class TrainingDefenseUnavailable(MLError):
    """Raised by :func:`apply_training_defense`; ``unavailable`` is the typed record to persist."""

    code = "training_defense_unavailable"

    def __init__(self, unavailable: TrainingUnavailable) -> None:
        super().__init__(f"{unavailable.defense_id} on {unavailable.target_id!r}: {unavailable.reason}")
        self.unavailable = unavailable


# --- record ----------------------------------------------------------------------------------


class TrainingRecord(BaseModel):
    """Provenance of one ``defense_apply`` run (spec 16.4 (4), 16.6)."""

    defense_id: str
    kind: Literal["training"] = "training"
    method: str
    target_id: str
    art_class: str | None = None
    art_class_role: Literal["implementation", "reference"] = "implementation"
    implementation: str
    params: dict[str, Any]                       # resolved; eps already substituted
    seed: int
    norm: str | None = None                      # adversarial training only
    inner_attack: dict[str, Any] | None = None   # adversarial training only
    temperature: float | None = None             # distillation only
    n_train: int
    n_train_available: int
    train_indices_sha256: str
    train_class_counts: dict[str, int]
    epochs_requested: int
    epochs_run: int
    budget_exhausted: bool
    wall_time_s: float
    wall_budget_s: float
    backbone_frozen: bool
    training_mode: str
    trainable_modules: list[str]
    n_params_total: int
    n_params_trainable: int
    parent_weights_sha256: str
    parent_manifest_sha256: str | None = None
    weights_sha256: str
    weights_changed: bool
    train_loss_per_epoch: list[float]
    train_loss_kind: str
    train_clean_correct_before: int
    train_clean_correct_after: int
    library_versions: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)     # {"weights": path, "training_report": path} via the sink
    weights_file_sha256: str | None = None                      # sha256 of the serialised state_dict file

    def defense_config(self) -> DefenseConfig:
        """The applied defense as the ``schema.DefenseConfig`` the verify campaign records (resolved params)."""
        return DefenseConfig(id=self.defense_id, art_class=self.art_class, params=dict(self.params))

    def provenance(self) -> dict[str, Any]:
        """``Provenance.defense`` for the verify run: ``DefenseConfig`` fields plus kind, digests and the report."""
        return {**self.defense_config().model_dump(mode="json"), "kind": self.kind, "method": self.method,
                "parent_sha256": self.parent_manifest_sha256 or self.parent_weights_sha256,
                "derived_sha256": self.weights_sha256, "training_report": self.model_dump(mode="json")}

    def derived_from(self) -> dict[str, Any]:
        """Lineage of the derived model (the ``MLModelManifest.derived_from`` shape: parent target and digest,
        defense id, training budget)."""
        return {"parent_target_id": self.target_id,
                "parent_sha256": self.parent_manifest_sha256 or self.parent_weights_sha256,
                "defense_id": self.defense_id,
                "training_budget": {"epochs_requested": self.epochs_requested, "epochs_run": self.epochs_run,
                                    "n_train": self.n_train, "wall_budget_s": self.wall_budget_s,
                                    "wall_time_s": self.wall_time_s, "budget_exhausted": self.budget_exhausted}}


@dataclass
class TrainingOutcome:
    """What a trainer hands back to :func:`apply_training_defense` (the module is trained in place)."""

    module: Any
    epochs_run: int
    budget_exhausted: bool
    wall_time_s: float
    train_loss_per_epoch: list[float]
    train_loss_kind: str
    trainable_modules: list[str]
    n_params_total: int
    n_params_trainable: int
    training_mode: str
    inner_attack: dict[str, Any] | None = None
    temperature: float | None = None
    notes: list[str] = field(default_factory=list)


def distillation_limitation(attack_ids: Sequence[str] = ()) -> str:
    """The distillation limitation text; names the C&W bypass and, when ``cw_l2`` ran, that the delta includes it."""
    text = ("Defensive distillation is bypassed by the Carlini-Wagner attack (Carlini & Wagner 2017); the derived "
            "model's measured delta MRI covers the evaluated attacks at this bounded budget only.")
    if "cw_l2" in set(attack_ids):
        text += " cw_l2 is in this run's attack set, so the measured delta already includes that attack."
    return text


# --- shared torch plumbing ------------------------------------------------------------------------


def state_dict_sha256(module: Any) -> str:
    """Canonical digest of a module's ``state_dict`` (sorted keys; dtype, shape and bytes of every tensor)."""
    import torch

    h = hashlib.sha256()
    sd = module.state_dict()
    for key in sorted(sd):
        t = sd[key]
        if not isinstance(t, torch.Tensor):
            h.update(f"{key}:{t!r}".encode())
            continue
        t = t.detach().cpu().contiguous()
        h.update(key.encode())
        h.update(str(t.dtype).encode())
        h.update(str(tuple(t.shape)).encode())
        arr = t.float().numpy() if t.dtype == torch.bfloat16 else t.numpy()
        h.update(np.ascontiguousarray(arr).tobytes())
    return h.hexdigest()


def _sha256_int_array(values: np.ndarray) -> str:
    arr = np.ascontiguousarray(np.asarray(values, dtype=np.int64))
    return hashlib.sha256(arr.tobytes()).hexdigest()


def _head_module(module: Any) -> tuple[str, Any]:
    from torch import nn

    for attr in _HEAD_ATTRS:
        sub = getattr(module, attr, None)
        if isinstance(sub, nn.Module) and any(True for _ in sub.parameters()):
            return attr, sub
    last: tuple[str, Any] | None = None
    for name, sub in module.named_modules():
        if name and not any(True for _ in sub.children()) and any(True for _ in sub.parameters(recurse=False)):
            last = (name, sub)
    if last is None:
        raise ValueError("the module has no parametrised leaf to fine-tune")
    return last


def select_trainable(module: Any, backbone_frozen: bool) -> tuple[list[str], int, int]:
    """Set ``requires_grad`` per the policy; ``(trainable module names, n_params_total, n_params_trainable)``.

    ``backbone_frozen``: only the classification head trains (a ``fc`` / ``classifier`` / ``head`` attribute,
    else the last parametrised leaf module); everything else, including normalisation statistics, stays fixed.
    """
    params = list(module.named_parameters())
    n_total = int(sum(p.numel() for _, p in params))
    if not backbone_frozen:
        for _, p in params:
            p.requires_grad_(True)
        names = [name for name, _ in module.named_children()] or ["<module>"]
        return names, n_total, n_total
    head_name, head = _head_module(module)
    head_ids = {id(p) for p in head.parameters()}
    for _, p in params:
        p.requires_grad_(id(p) in head_ids)
    n_trainable = int(sum(p.numel() for p in head.parameters()))
    return [head_name], n_total, n_trainable


def n_classes(module: Any, x: np.ndarray) -> int:
    import torch

    was_training = module.training
    module.eval()
    with torch.no_grad():
        out = module(torch.from_numpy(np.asarray(x[:1], dtype=np.float32)))
    module.train(was_training)
    return int(out.shape[1])


def count_correct(module: Any, x: np.ndarray, y: np.ndarray, batch_size: int = 64) -> int:
    """``k`` correct argmax predictions over ``x`` (eval mode; the module's mode is restored)."""
    import torch

    was_training = module.training
    module.eval()
    correct = 0
    with torch.no_grad():
        for start in range(0, len(x), batch_size):
            xb = torch.from_numpy(np.asarray(x[start:start + batch_size], dtype=np.float32))
            pred = module(xb).argmax(dim=1).numpy()
            correct += int((pred == np.asarray(y[start:start + batch_size])).sum())
    module.train(was_training)
    return correct


def mean_cross_entropy(module: Any, x: np.ndarray, y: np.ndarray, batch_size: int = 64) -> float:
    """Mean clean cross-entropy over ``x`` (eval mode; the module's mode is restored)."""
    import torch
    import torch.nn.functional as functional

    was_training = module.training
    module.eval()
    total = 0.0
    with torch.no_grad():
        for start in range(0, len(x), batch_size):
            xb = torch.from_numpy(np.asarray(x[start:start + batch_size], dtype=np.float32))
            yb = torch.from_numpy(np.asarray(y[start:start + batch_size], dtype=np.int64))
            total += float(functional.cross_entropy(module(xb), yb, reduction="sum"))
    module.train(was_training)
    return total / max(1, len(x))


def one_hot(y: np.ndarray, k: int) -> np.ndarray:
    labels = np.asarray(y, dtype=np.int64).reshape(-1)
    if labels.min() < 0 or labels.max() >= k:
        raise ValueError(f"labels must lie in [0, {k}); got [{labels.min()}, {labels.max()}]")
    return np.eye(k, dtype=np.float32)[labels]


def _torch_module(target: Target) -> Any | None:
    try:
        from torch import nn
    except Exception:  # noqa: BLE001 - torch absent: no training defense can run here
        return None
    try:
        module = target.torch_model()
    except NotImplementedError:
        return None
    return module if isinstance(module, nn.Module) else None


# --- availability and parameters --------------------------------------------------------------


def assess_training_target(target: Target, defense_id: str) -> TrainingUnavailable | None:
    """``None`` when ``defense_id`` can run on ``target``; else the typed reason (never raised here)."""
    spec = get_defense(defense_id)
    if spec["kind"] != "training":
        raise ValueError(f"defense {defense_id!r} is a {spec['kind']} defense, not a training defense")
    info = target.info()
    domain = str(info.domain)
    if domain not in spec["domains"]:
        if domain == "tabular":
            return TrainingUnavailable(defense_id=defense_id, target_id=target.id, domain=domain,
                                       reason=TREE_ENSEMBLE_REASON, infeasible=True,
                                       register_item="ATTACKS_HARDEN-20")
        return TrainingUnavailable(defense_id=defense_id, target_id=target.id, domain=domain,
                                   reason=f"training defenses apply to {list(spec['domains'])} targets, not "
                                          f"{domain!r}", infeasible=True)
    if _torch_module(target) is None:
        return TrainingUnavailable(defense_id=defense_id, target_id=target.id, domain=domain,
                                   reason=NO_TORCH_MODULE_REASON, infeasible=True)
    return None


def resolve_training_params(defense_id: str, params: Mapping[str, Any] | None, *,
                            reference_eps: float | None = None) -> dict[str, float | int | bool]:
    """Catalog defaults and bounds (``resolve_defense_params``) plus the eps rule: 0 or absent means the
    campaign's ``reference_eps``, which must then be given (``ValueError`` otherwise)."""
    resolved = resolve_defense_params(defense_id, params)
    if "eps" in resolved:
        eps = float(resolved["eps"])
        if eps <= 0.0:
            if reference_eps is None or float(reference_eps) <= 0.0:
                raise ValueError(f"{defense_id}.eps: 0 means 'the campaign reference eps' but no reference_eps was "
                                 "given; pass eps > 0 in params or reference_eps=<CampaignConfig.reference_eps>")
            resolved["eps"] = float(reference_eps)
    return resolved


# --- training slice ---------------------------------------------------------------------------


def _slice_arrays(train_slice: Any) -> tuple[np.ndarray, np.ndarray, np.ndarray | None, list[str] | None]:
    if isinstance(train_slice, Sample):
        return train_slice.x, train_slice.y, train_slice.indices, list(train_slice.class_names)
    if isinstance(train_slice, (str, Path)):
        path = Path(train_slice)
        if not path.is_file():
            raise FileNotFoundError(f"training slice not found: {path}")
        with np.load(path, allow_pickle=False) as npz:
            if "x" not in npz or "y" not in npz:
                raise ValueError(f"training slice {path} must carry 'x' and 'y'")
            x = np.asarray(npz["x"])
            y = np.asarray(npz["y"]).reshape(-1)
            idx = np.asarray(npz["indices"]).astype(np.int64) if "indices" in npz else None
            names = [str(s) for s in np.asarray(npz["class_names"]).tolist()] if "class_names" in npz else None
        return x, y, idx, names
    if isinstance(train_slice, Mapping):
        x = np.asarray(train_slice["x"])
        y = np.asarray(train_slice["y"]).reshape(-1)
        idx = train_slice.get("indices")
        names = train_slice.get("class_names")
        return (x, y, None if idx is None else np.asarray(idx, dtype=np.int64),
                None if names is None else [str(s) for s in names])
    if isinstance(train_slice, (tuple, list)) and len(train_slice) == 2:
        return np.asarray(train_slice[0]), np.asarray(train_slice[1]).reshape(-1), None, None
    raise TypeError(f"train_slice must be a Sample, an (x, y) pair, a mapping or an .npz path, not "
                    f"{type(train_slice).__name__}")


def load_train_slice(train_slice: Any, *, target: Target, defense_id: str, n: int, seed: int) -> tuple[Sample, int]:
    """``(seeded stratified slice of at most n rows as float32 in [0, 1], rows available)``.

    ``train_slice`` is a ``Sample``, an ``(x, y)`` pair, a mapping or an ``.npz`` path (``x`` uint8 or float,
    ``y``, optional ``indices`` and ``class_names``); ``None`` uses ``target.train_sample(n, seed)`` when the
    target has one, else the typed :class:`TrainingDefenseUnavailable` (``infeasible: False``).
    """
    if train_slice is None:
        train_sample = getattr(target, "train_sample", None)
        if not callable(train_sample):
            raise TrainingDefenseUnavailable(TrainingUnavailable(
                defense_id=defense_id, target_id=target.id, domain=str(target.info().domain),
                reason=NO_TRAIN_SLICE_REASON, infeasible=False))
        try:
            train_slice = train_sample(int(n), int(seed))
        except LookupError as exc:
            # The target has the accessor but its build recorded no training slice (``--no-train-slice``).
            raise TrainingDefenseUnavailable(TrainingUnavailable(
                defense_id=defense_id, target_id=target.id, domain=str(target.info().domain),
                reason=NO_TRAIN_SLICE_REASON, infeasible=False)) from exc
    x_raw, y_raw, idx, names = _slice_arrays(train_slice)
    x = as_model_input(x_raw)
    if x.ndim < 2 or len(x) == 0:
        raise ValueError("training slice is empty or not batched")
    if len(x) != len(y_raw):
        raise ValueError(f"training slice x has {len(x)} rows but y has {len(y_raw)}")
    if float(x.min()) < -1e-6 or float(x.max()) > 1.0 + 1e-6:
        raise ValueError("training slice values must lie in [0, 1] (uint8 images are scaled automatically)")
    x = np.clip(x, 0.0, 1.0).astype(np.float32, copy=False)
    y = np.asarray(y_raw, dtype=np.int64)
    if names is None:
        names = [str(i) for i in range(int(y.max()) + 1)]
    available = int(len(y))
    sample = stratified_sample(x, y, min(int(n), available), int(seed), names, source_indices=idx)
    return sample, available


# --- entry point --------------------------------------------------------------------------------


def _resolve_call(defense: DefenseSpec, params: Mapping[str, Any] | None, config: Any, seed: int | None,
                  reference_eps: float | None, norm: str | None) -> tuple[str, dict[str, Any], int, float | None,
                                                                          str, list[str]]:
    """``(defense_id, raw params, seed, reference_eps, norm, attack_ids)`` from either call shape: an id plus
    ``params``, or a ``DefenseConfig`` (params inside) with the ``CampaignConfig`` supplying eps, norm and seed."""
    defense_id, raw = resolve_defense_spec(defense, params)
    cfg_eps = getattr(config, "reference_eps", None) if config is not None else None
    cfg_norm = getattr(config, "norm", None) if config is not None else None
    cfg_seed = getattr(config, "seed", None) if config is not None else None
    eps = reference_eps if reference_eps is not None else (float(cfg_eps) if cfg_eps is not None else None)
    use_norm = norm if norm is not None else (str(cfg_norm) if cfg_norm else "linf")
    use_seed = int(seed) if seed is not None else (int(cfg_seed) if cfg_seed is not None else 0)
    attack_ids = [str(a) for a in (getattr(config, "attack_ids", None) or [])] if config is not None else []
    if use_norm not in ("linf", "l2"):
        raise ValueError(f"norm must be 'linf' or 'l2', not {use_norm!r}")
    return defense_id, raw, use_seed, eps, use_norm, attack_ids


def _write_artifacts(sink: Any, module: Any, record: TrainingRecord) -> None:
    """Serialise the derived ``state_dict`` and the report through the sink; paths and digest land on the record."""
    import torch

    buffer = io.BytesIO()
    torch.save({k: v.detach().cpu() for k, v in module.state_dict().items()}, buffer)
    weights = buffer.getvalue()
    record.artifacts["weights"] = str(sink.put(WEIGHTS_ARTIFACT, weights, "application/octet-stream"))
    record.weights_file_sha256 = hashlib.sha256(weights).hexdigest()
    report = record.model_dump_json(indent=2).encode("utf-8")
    record.artifacts["training_report"] = str(sink.put(REPORT_ARTIFACT, report, "application/json"))


def train_defense(target: Target, defense: DefenseSpec, params: Mapping[str, Any] | None = None,
                  train_slice: Any = None, seed: int | None = None, log: Log | None = None, *, config: Any = None,
                  sink: Any = None, reference_eps: float | None = None,
                  norm: str | None = None) -> tuple[Any, TrainingRecord]:
    """Re-train a deep copy of ``target``'s torch module with the training defense ``defense``.

    Returns ``(derived module in eval mode, TrainingRecord)``; the target's own module is never modified.
    ``defense`` is a catalog id with ``params``, or a ``DefenseConfig`` / its mapping (params inside).
    ``eps`` 0 or absent means the campaign's reference eps: pass ``reference_eps`` or ``config`` (a
    ``CampaignConfig``, which also supplies ``norm`` and ``seed`` when those are not given). ``train_slice`` see
    :func:`load_train_slice` (``None`` uses ``target.train_sample``). With ``sink`` the derived weights and the
    report are written as :data:`WEIGHTS_ARTIFACT` / :data:`REPORT_ARTIFACT`. ``log`` gets one line per epoch.

    Raises :class:`TrainingDefenseUnavailable` (typed, for the record) when the target has no trainable torch
    module or no training slice, ``ValueError`` on bad parameters or a preprocessing id.
    """
    defense_id, raw_params, use_seed, use_eps, use_norm, attack_ids = _resolve_call(
        defense, params, config, seed, reference_eps, norm)
    spec = get_defense(defense_id)
    if spec["kind"] != "training":
        raise ValueError(f"defense {defense_id!r} is a {spec['kind']} defense; apply it with "
                         "redsim.ml.defenses.apply_defense")
    unavailable = assess_training_target(target, defense_id)
    if unavailable is not None:
        raise TrainingDefenseUnavailable(unavailable)
    resolved = resolve_training_params(defense_id, raw_params, reference_eps=use_eps)
    parent = target.torch_model()
    parent_sha = state_dict_sha256(parent)
    manifest = dict(target.manifest() or {})
    parent_manifest_sha = next((str(manifest[k]) for k in ("model_sha256", "weights_sha256", "sha256")
                                if manifest.get(k)), None)
    sample, available = load_train_slice(train_slice, target=target, defense_id=defense_id,
                                         n=int(resolved["train_n"]), seed=use_seed)
    module = copy.deepcopy(parent)
    before = count_correct(module, sample.x, sample.y, int(resolved["batch_size"]))
    say: Log = log if log is not None else (lambda _line: None)
    epochs = int(resolved["epochs"])
    batch_size = int(resolved["batch_size"])
    lr = float(resolved["lr"])
    backbone_frozen = bool(resolved["backbone_frozen"])
    wall_budget_s = float(resolved["wall_budget_s"])
    limitations: list[str]
    if defense_id == "adversarial_training":
        from redsim.ml.harden.adversarial_training import adversarial_finetune

        outcome = adversarial_finetune(module, sample.x, sample.y, eps=float(resolved["eps"]), norm=use_norm,
                                       pgd_iters=int(resolved["pgd_iters"]),
                                       eps_step_ratio=float(resolved["eps_step_ratio"]),
                                       ratio=float(resolved["ratio"]), epochs=epochs, batch_size=batch_size, lr=lr,
                                       backbone_frozen=backbone_frozen, wall_budget_s=wall_budget_s,
                                       seed=use_seed, log=say, clock=_now)
        limitations = [ADVERSARIAL_TRAINING_LIMIT]
    elif defense_id == "defensive_distillation":
        from redsim.ml.harden.distillation import distill

        outcome = distill(module, sample.x, sample.y, temperature=float(resolved["temperature"]), epochs=epochs,
                          batch_size=batch_size, lr=lr, backbone_frozen=backbone_frozen,
                          wall_budget_s=wall_budget_s, seed=use_seed, log=say, clock=_now)
        limitations = [distillation_limitation(attack_ids), DISTILLATION_BYPASS, DISTILLATION_ART_NOTE]
    else:  # pragma: no cover - the catalog names exactly these two
        raise ValueError(f"no trainer for training defense {defense_id!r}")
    derived = outcome.module
    derived.eval()
    derived_sha = state_dict_sha256(derived)
    after = count_correct(derived, sample.x, sample.y, int(resolved["batch_size"]))
    record = TrainingRecord(
        defense_id=defense_id, method=defense_id, target_id=target.id, art_class=spec["art_class"],
        art_class_role=spec.get("art_class_role", "implementation"), implementation=str(spec["implementation"]),
        params=dict(resolved), seed=use_seed,
        norm=use_norm if defense_id == "adversarial_training" else None,
        inner_attack=outcome.inner_attack, temperature=outcome.temperature,
        n_train=int(len(sample.y)), n_train_available=available,
        train_indices_sha256=_sha256_int_array(sample.indices),
        train_class_counts=per_class_counts(sample.y, sample.class_names),
        epochs_requested=epochs, epochs_run=outcome.epochs_run,
        budget_exhausted=outcome.budget_exhausted, wall_time_s=round(outcome.wall_time_s, 3),
        wall_budget_s=wall_budget_s, backbone_frozen=backbone_frozen,
        training_mode=outcome.training_mode, trainable_modules=list(outcome.trainable_modules),
        n_params_total=outcome.n_params_total, n_params_trainable=outcome.n_params_trainable,
        parent_weights_sha256=parent_sha, parent_manifest_sha256=parent_manifest_sha,
        weights_sha256=derived_sha, weights_changed=(derived_sha != parent_sha),
        train_loss_per_epoch=[round(float(v), 6) for v in outcome.train_loss_per_epoch],
        train_loss_kind=outcome.train_loss_kind,
        train_clean_correct_before=before, train_clean_correct_after=after,
        library_versions=library_versions(), notes=list(outcome.notes), limitations=limitations,
    )
    if sink is not None:
        _write_artifacts(sink, derived, record)
    say(f"defense_apply {defense_id}: {record.epochs_run}/{record.epochs_requested} epochs, n_train {record.n_train}, "
        f"wall {record.wall_time_s:.1f}s of {record.wall_budget_s:.0f}s, derived sha256 {derived_sha[:12]}")
    return derived, record


def apply_training_defense(target: Target, defense: DefenseSpec, params: Mapping[str, Any] | None = None,
                           train_slice: Any = None, seed: int | None = None, log: Log | None = None, *,
                           config: Any = None, sink: Any = None, reference_eps: float | None = None,
                           norm: str | None = None) -> DerivedTorchTarget:
    """The ``defense_apply`` hook: :func:`train_defense` wrapped as the ``Target`` the verify re-run attacks.

    ``campaign._apply_defense`` calls it as ``hook(target, config.defense, config=config, sink=sink,
    seed=config.seed)``; the result's ``describe()`` is ``Provenance.defense`` and ``.module`` / ``.record`` are
    the bare outputs. Same errors as :func:`train_defense`.
    """
    module, record = train_defense(target, defense, params, train_slice, seed, log, config=config, sink=sink,
                                   reference_eps=reference_eps, norm=norm)
    return DerivedTorchTarget(target, module, record)


# --- derived target ----------------------------------------------------------------------------


class DerivedTorchTarget:
    """``Target`` over the derived module for the verify re-run (attacks, control, explanations).

    Samples and class names come from the parent; predictions, the fresh ART ``PyTorchClassifier`` (no
    optimizer) and ``torch_model()`` use the derived weights, so SHAP explains the model that was attacked.
    ``manifest()`` keeps the parent's digest keys (``Provenance.model_sha256`` stays the parent's: the 15.6
    identity) and adds the training record under ``defense``; ``describe()`` is the record's provenance, which
    ``campaign._defense_provenance`` reads into ``Provenance.defense``.
    """

    def __init__(self, base: Target, module: Any, record: TrainingRecord) -> None:
        self.base = base
        self.id = base.id
        self.module = module
        self.record = record
        self._spec = get_defense(record.defense_id)
        self._clf: Any = None

    def describe(self) -> dict[str, Any]:
        return {**self.record.provenance(), "name": self._spec["name"], "torch_model_defended": True}

    def defense_config(self) -> DefenseConfig:
        return self.record.defense_config()

    def info(self) -> TargetInfo:
        info = self.base.info()
        return info.model_copy(update={
            "name": f"{info.name} + {self._spec['name']} (derived {self.record.weights_sha256[:8]})",
            "metadata": {**info.metadata, "defense": self.describe()},
        })

    def load(self) -> None:
        self.base.load()

    def sample(self, n: int, seed: int) -> Sample:
        return self.base.sample(n, seed)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        import torch

        self.module.eval()
        with torch.no_grad():
            logits = self.module(torch.from_numpy(np.ascontiguousarray(np.asarray(x, dtype=np.float32))))
            return np.asarray(torch.softmax(logits, dim=1).numpy(), dtype=np.float32)

    def _input_shape(self) -> tuple[int, ...]:
        shape = getattr(self.base.art_classifier(), "input_shape", None)
        if shape:
            return tuple(int(d) for d in shape)
        return tuple(int(d) for d in self.base.sample(1, 0).x.shape[1:])

    def art_classifier(self) -> Any:
        if self._clf is None:
            from art.estimators.classification import PyTorchClassifier
            from torch import nn

            shape = self._input_shape()
            probe = np.zeros((1, *shape), dtype=np.float32)
            self._clf = PyTorchClassifier(model=self.module, loss=nn.CrossEntropyLoss(), input_shape=shape,
                                          nb_classes=n_classes(self.module, probe), clip_values=(0.0, 1.0),
                                          device_type="cpu")
        return self._clf

    def torch_model(self) -> Any:
        return self.module

    def manifest(self) -> dict[str, Any]:
        return {**self.base.manifest(), "defense": self.describe()}


__all__ = ["Clock", "DerivedTorchTarget", "Log", "NO_TORCH_MODULE_REASON", "NO_TRAIN_SLICE_REASON",
           "REPORT_ARTIFACT", "TREE_ENSEMBLE_REASON", "TrainingDefenseUnavailable", "TrainingOutcome",
           "TrainingRecord", "TrainingUnavailable", "WEIGHTS_ARTIFACT", "apply_training_defense",
           "assess_training_target", "count_correct", "distillation_limitation", "library_versions",
           "load_train_slice", "mean_cross_entropy", "n_classes", "one_hot", "resolve_training_params",
           "seed_everything", "select_trainable", "state_dict_sha256", "train_defense"]
