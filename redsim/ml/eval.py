"""Turn predictions into ``Measurement`` rows (spec section 12.5, 14.2).

Everything here is counting. A Measurement carries ``n`` and every denominator
it uses; rates are derived from the counts and never stored without them:

- ``accuracy = n_correct / n``.
- ``attack_success_rate = n_flipped_from_clean / n_clean_correct`` (evasion and
  control rows; ``None`` when the denominator is 0, never 0% or 100%).
- ``conf_gap_mean`` is the mean over ALL ``n`` samples of
  ``max(0, max_{j != y} p_j - p_y)`` on the perturbed input, with ``conf_gap_n = n``,
  so a robust model scores 0 rather than "undefined" (spec 12.5, 15.1).
- ``pert_first_success_mean`` / ``pert_first_success_n`` are computed by
  :func:`pert_first_success` from the per-eps flip matrix and belong on the
  attack's reference-eps row only (spec 15.1); the campaign sets them there.
- ``expl_shift_*`` are left ``None``; the explain stage fills them on the
  reference row (spec 13.5).

Severity is a Finding-level value (``redsim.ml.scoring.severity_for``), not a
Measurement field, so nothing here derives it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np

from redsim.ml.schema import Measurement, MeasurementFamily


def perturbation_norms(x_ref: np.ndarray, x_adv: np.ndarray) -> tuple[float, float]:
    """Mean per-sample L-inf and L2 norm of ``x_adv - x_ref``. Both are always recorded,
    whatever norm the attack optimised (spec 12.5)."""
    a = np.asarray(x_ref, dtype=np.float64)
    b = np.asarray(x_adv, dtype=np.float64)
    if a.shape != b.shape:
        raise ValueError(f"shape mismatch: x_ref {a.shape} vs x_adv {b.shape}")
    if a.shape[0] == 0:
        return 0.0, 0.0
    d = (b - a).reshape(a.shape[0], -1)
    linf = np.abs(d).max(axis=1)
    l2 = np.sqrt((d * d).sum(axis=1))
    return float(linf.mean()), float(l2.mean())


def per_sample_norm(x: np.ndarray, x_adv: np.ndarray, *, l2: bool = False) -> np.ndarray:
    """Per-sample perturbation norm, L-inf by default or L2 on request."""
    a = np.asarray(x, dtype=np.float64)
    b = np.asarray(x_adv, dtype=np.float64)
    if a.shape != b.shape:
        raise ValueError(f"shape mismatch: x {a.shape} vs x_adv {b.shape}")
    d = (b - a).reshape(a.shape[0], -1)
    return np.sqrt((d * d).sum(axis=1)) if l2 else np.abs(d).max(axis=1)


def attack_success_rate(y_true: np.ndarray, y_pred_clean: np.ndarray,
                        y_pred_adv: np.ndarray) -> tuple[int, int, float | None]:
    """``(n_flipped_from_clean, n_clean_correct, asr)`` per spec 12.5: numerator = correct on
    clean AND wrong on adv; denominator = correct on clean. ``asr`` is ``None`` when the
    denominator is 0 (never 0% or 100%)."""
    yt = np.asarray(y_true)
    yc = np.asarray(y_pred_clean)
    ya = np.asarray(y_pred_adv)
    clean_correct = yc == yt
    n_clean_correct = int(clean_correct.sum())
    n_flipped = int((clean_correct & (ya != yt)).sum())
    asr = (n_flipped / n_clean_correct) if n_clean_correct > 0 else None
    return n_flipped, n_clean_correct, asr


def conf_gap(proba_adv: np.ndarray, y_true: np.ndarray) -> float:
    """Mean over ALL n samples of ``max(0, max_{j != y} p_j - p_y)`` on the adversarial
    input (spec 12.5 / 15.1), so a robust model scores 0 rather than "undefined"."""
    p = np.asarray(proba_adv, dtype=np.float64)
    yt = np.asarray(y_true).astype(int)
    if p.ndim != 2 or p.shape[0] != yt.shape[0]:
        raise ValueError("proba_adv must be (n, n_classes) aligned with y_true")
    if p.shape[0] == 0:
        return 0.0
    n = p.shape[0]
    p_true = p[np.arange(n), yt]
    masked = p.copy()
    masked[np.arange(n), yt] = -np.inf
    p_other = masked.max(axis=1)
    gaps = np.maximum(0.0, p_other - p_true)
    return float(np.clip(gaps, 0.0, 1.0).mean())


def pert_first_success(flips: Mapping[float, np.ndarray],
                       norms: Mapping[float, np.ndarray]) -> tuple[float | None, int]:
    """``(pert_first_success_mean, pert_first_success_n)`` per spec 15.1.

    ``flips[eps]`` is the per-sample flipped mask at that grid eps and ``norms[eps]`` the
    per-sample achieved norm of the adversarial example at that eps. For every sample that
    flips at any grid eps, take the norm at the smallest eps at which it flips; the mean over
    those samples is returned with their count. ``(None, 0)`` when no sample flipped."""
    grid = sorted(float(e) for e in flips)
    if not grid:
        return None, 0
    first: list[float] = []
    n = int(np.asarray(flips[grid[0]]).shape[0])
    for i in range(n):
        for e in grid:
            if bool(np.asarray(flips[e])[i]):
                first.append(float(np.asarray(norms[e])[i]))
                break
    if not first:
        return None, 0
    return float(sum(first) / len(first)), len(first)


def _per_class(y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for idx, name in enumerate(class_names):
        mask = y_true == idx
        out[str(name)] = {"n": int(mask.sum()), "n_correct": int((mask & (y_pred == idx)).sum())}
    return out


def _scalar_params(params: Mapping[str, Any] | None, notes: list[str]) -> dict[str, float | int | bool | str]:
    """Keep the scalar params the schema admits (``float | int | bool | str``); note the rest."""
    out: dict[str, float | int | bool | str] = {}
    for k, v in (params or {}).items():
        if isinstance(v, (bool, int, float, str)) and not isinstance(v, complex):
            out[str(k)] = v
        elif isinstance(v, (np.integer, np.floating, np.bool_)):
            out[str(k)] = v.item()
        else:
            notes.append(f"param {k!r}={v!r} omitted from params (non-scalar)")
    return out


def measure(id: str, family: MeasurementFamily, y_true: np.ndarray, y_pred: np.ndarray,
            class_names: list[str], *, attack_id: str | None = None,
            params: Mapping[str, Any] | None = None, x_ref: np.ndarray | None = None,
            x_adv: np.ndarray | None = None, y_pred_clean: np.ndarray | None = None,
            proba: np.ndarray | None = None, queries_mean: float | None = None,
            wall_time_s: float = 0.0, notes: list[str] | None = None) -> Measurement:
    """Build one Measurement row from labels.

    - ``n``, ``n_correct``, ``accuracy = n_correct / n`` and ``per_class`` (one entry per class,
      so the per-class ``n`` sum to ``n``) are always filled.
    - ``n_flipped_from_clean``, ``n_clean_correct`` and ``attack_success_rate`` are filled when
      ``y_pred_clean`` is given (evasion / control rows). The rate is ``None`` with a note when
      ``n_clean_correct`` is 0.
    - ``conf_gap_mean`` / ``conf_gap_n`` are filled when ``proba`` (the class probabilities on the
      input this row measures) is given; ``conf_gap_n`` is ``n``.
    - ``linf_norm_mean`` / ``l2_norm_mean`` are filled when both ``x_ref`` and ``x_adv`` are given.
    - ``queries_mean`` is copied through (black-box attacks only).
    - ``pert_first_success_*`` and ``expl_shift_*`` stay ``None``: they belong on the reference
      row and are set by the campaign (perturbation) and the explain stage (attribution shift).
    """
    yt = np.asarray(y_true).astype(int).ravel()
    yp = np.asarray(y_pred).astype(int).ravel()
    if yt.shape != yp.shape:
        raise ValueError(f"y_true {yt.shape} and y_pred {yp.shape} differ in length")
    n = int(yt.shape[0])
    n_correct = int((yt == yp).sum())
    accuracy = (n_correct / n) if n > 0 else 0.0
    row_notes: list[str] = list(notes or [])
    if n == 0:
        row_notes.append("not computed (denominator 0): no samples evaluated")

    n_flipped: int | None = None
    n_clean_correct: int | None = None
    asr: float | None = None
    if y_pred_clean is not None:
        yc = np.asarray(y_pred_clean).astype(int).ravel()
        if yc.shape != yt.shape:
            raise ValueError("y_pred_clean must align with y_true")
        n_flipped, n_clean_correct, asr = attack_success_rate(yt, yc, yp)
        if asr is None:
            row_notes.append("attack_success_rate not computed (denominator n_clean_correct = 0)")

    gap: float | None = None
    gap_n: int | None = None
    if proba is not None:
        gap = conf_gap(proba, yt)
        gap_n = n

    linf: float | None = None
    l2: float | None = None
    if x_ref is not None and x_adv is not None:
        linf, l2 = perturbation_norms(x_ref, x_adv)

    clean_params = _scalar_params(params, row_notes)

    return Measurement(
        id=id, family=family, attack_id=attack_id, params=clean_params,
        n=n, n_correct=n_correct, accuracy=accuracy,
        n_flipped_from_clean=n_flipped, n_clean_correct=n_clean_correct, attack_success_rate=asr,
        linf_norm_mean=linf, l2_norm_mean=l2,
        conf_gap_mean=gap, conf_gap_n=gap_n,
        queries_mean=None if queries_mean is None else float(queries_mean),
        per_class=_per_class(yt, yp, class_names), wall_time_s=float(wall_time_s),
        notes=row_notes,
    )


def eps_tag(eps: float) -> str:
    """``0.03 -> "eps0.03"``; used for measurement ids ``m.evasion.<a>.eps0.03`` (spec 14.1)."""
    return f"eps{float(eps):g}"


def eps_of(m: Measurement) -> float | None:
    """The ``eps`` a row was measured at, from ``params`` (``None`` for the clean row)."""
    v = m.params.get("eps")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)
