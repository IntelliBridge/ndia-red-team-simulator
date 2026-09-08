"""Turn predictions into ``Measurement`` rows (spec section 12.5, 14.2).

Everything here is counting. A Measurement carries ``n`` and every denominator
it uses; rates are derived from the counts and never stored without them. The
schema in this branch has no dedicated fields for the attack success rate or
the confidence gap, so those are exposed as helpers (``attack_success_rate``,
``conf_gap``) for the scoring stage and written into ``Measurement.notes`` with
their numerator and denominator spelled out.

``Measurement.severity`` is NEVER set here; ``redsim.ml.scoring.severity_for``
derives it from the per-eps table (spec section 15.5).
"""

from __future__ import annotations

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


def _per_class(y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for idx, name in enumerate(class_names):
        mask = y_true == idx
        out[str(name)] = {"n": int(mask.sum()), "n_correct": int((mask & (y_pred == idx)).sum())}
    return out


def measure(id: str, family: MeasurementFamily, y_true: np.ndarray, y_pred: np.ndarray,
            class_names: list[str], *, attack_id: str | None = None,
            params: dict[str, Any] | None = None, x_ref: np.ndarray | None = None,
            x_adv: np.ndarray | None = None, y_pred_clean: np.ndarray | None = None,
            wall_time_s: float = 0.0, notes: list[str] | None = None) -> Measurement:
    """Build one Measurement row from labels.

    - ``n``, ``n_correct``, ``accuracy = n_correct / n`` and ``per_class`` (one entry per class,
      so the per-class ``n`` sum to ``n``) are always filled.
    - ``n_flipped_from_clean`` is filled when ``y_pred_clean`` is given (evasion / control rows):
      samples correct on clean and wrong here. The denominator ``n_clean_correct`` and the
      resulting rate are written to ``notes`` because the schema has no field for them.
    - ``linf_norm_mean`` / ``l2_norm_mean`` are filled when both ``x_ref`` and ``x_adv`` are given.
    - ``severity`` is left ``None``; it is derived later (spec 15.5).
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
    if y_pred_clean is not None:
        yc = np.asarray(y_pred_clean).astype(int).ravel()
        if yc.shape != yt.shape:
            raise ValueError("y_pred_clean must align with y_true")
        n_flipped, n_clean_correct, asr = attack_success_rate(yt, yc, yp)
        if asr is None:
            row_notes.append("attack_success_rate not computed (denominator n_clean_correct = 0)")
        else:
            row_notes.append(
                f"attack_success_rate = {n_flipped}/{n_clean_correct} = {asr:.4f} "
                f"(n_flipped_from_clean / n_clean_correct)")

    linf: float | None = None
    l2: float | None = None
    if x_ref is not None and x_adv is not None:
        linf, l2 = perturbation_norms(x_ref, x_adv)

    clean_params: dict[str, float | int | bool] = {}
    for k, v in (params or {}).items():
        if isinstance(v, (bool, int, float)) and not isinstance(v, complex):
            clean_params[str(k)] = v
        else:
            row_notes.append(f"param {k!r}={v!r} omitted from params (non-scalar)")

    return Measurement(
        id=id, family=family, attack_id=attack_id, params=clean_params,
        n=n, n_correct=n_correct, accuracy=accuracy,
        n_flipped_from_clean=n_flipped, linf_norm_mean=linf, l2_norm_mean=l2,
        per_class=_per_class(yt, yp, class_names), wall_time_s=float(wall_time_s),
        notes=row_notes,
    )


def eps_tag(eps: float) -> str:
    """``0.03 -> "eps0.03"``; used for measurement ids ``m.evasion.<a>.eps0.03`` (spec 14.1)."""
    return f"eps{float(eps):g}"
