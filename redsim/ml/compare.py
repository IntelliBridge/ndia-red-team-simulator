"""Pure N-run comparison over persisted campaign records (spec 15.6, 15.8; F007 US3).

Register rows REVIEW_REPORTS-26 and -30. Everything here is a function of the
``ml.run_record`` JSON of the compared runs (plus the mutable ``baseline_run_id``
overlay a campaign row may carry); nothing is recomputed from samples, nothing
touches a database or the web stack, so the pairwise route
(``GET /v1/runs/{id}/compare``), the N-run table (``GET /v1/runs/compare``) and
the batch compare of wave B3 share one definition of "comparable".

The rules, in the order they are applied:

* compatibility is decided variable by variable on the frozen campaign config
  (the fields the settings hash of spec 5.6 covers, except the model identity)
  plus ``sample_indices_sha256``; the ``scoring`` block is compared per sub-key
  so a differing weight vector is named ``scoring.weights`` (spec 15.3: two
  campaigns with different weight vectors are incomparable);
* a run whose score is absent or partial (``mri`` is ``None``) is refused,
  never compared on the subscores that do exist;
* a verify run and its baseline must share the model; the measured ΔMRI is the
  delta the worker persisted on the verify run or, failing that, the same
  ``redsim.ml.scoring.delta`` over the two stored records;
* the same settings on a different model is the side-by-side case: full
  scorecards, ``delta: None``;
* an N-run table lists rows in request order, carries a delta only on verify
  rows whose own baseline is in the set, and has no mean, rank, average or
  cross-model delta (D9 i).

The typed refusals :class:`Incompatible` and :class:`ScoreUnavailable` carry
the ``reasons`` list the API puts in the 17.3 envelope.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from redsim.ml.schema import MRIWeights

# Config fields outside the comparison. ``target_id`` is the Target row, whose model
# identity is compared through ``provenance.model_sha256`` instead (a side-by-side
# comparison is exactly "same settings, different model"); ``defense`` is the variable
# a verify run changes; the rest do not affect a measurement.
IGNORED_CONFIG_FIELDS: tuple[str, ...] = (
    "target_id", "defense", "llm_narrative", "auto_recommend", "target_snapshot", "attacks",
)
IGNORED_VARIABLES: tuple[str, ...] = (
    "llm_narrative", "auto_recommend", "target_snapshot", "attacks", "reviewer_notes",
)
SAMPLE_VARIABLE = "sample_indices_sha256"
MODEL_VARIABLE = "model_sha256"
#: Config blocks compared per sub-key so the mismatch names the field that differs.
NESTED_CONFIG_FIELDS: tuple[str, ...] = ("scoring",)

#: Bounds of the N-run table (F007 US3).
MIN_TABLE_RUNS = 2
MAX_TABLE_RUNS = 10

#: Keys that must never appear in a comparison payload (spec 15.8 i; D9 i).
FORBIDDEN_TABLE_KEYS: frozenset[str] = frozenset({"mean", "rank", "average", "aggregate", "ranking"})


class Incompatible(Exception):
    """Two (or more) runs differ in a compared variable; ``reasons`` names each one."""

    def __init__(self, reasons: Sequence[str], *, pairs: Sequence[dict[str, Any]] | None = None) -> None:
        self.reasons = list(reasons)
        self.pairs = list(pairs or [])
        super().__init__("campaigns differ in " + ", ".join(self.reasons))


class ScoreUnavailable(Exception):
    """A compared run has no complete MRI; ``reasons`` names the run and why."""

    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = list(reasons)
        super().__init__("; ".join(self.reasons))


# ---------------------------------------------------------------------------
# Record readers
# ---------------------------------------------------------------------------


def provenance(record: Mapping[str, Any]) -> dict[str, Any]:
    value = record.get("provenance")
    return dict(value) if isinstance(value, Mapping) else {}


def config(record: Mapping[str, Any]) -> dict[str, Any]:
    value = record.get("config")
    return dict(value) if isinstance(value, Mapping) else {}


def sample_hash(record: Mapping[str, Any]) -> Any:
    return provenance(record).get(SAMPLE_VARIABLE)


def model_hash(record: Mapping[str, Any]) -> Any:
    return provenance(record).get(MODEL_VARIABLE)


def settings_hash(record: Mapping[str, Any]) -> Any:
    """``CampaignRecord.settings_hash`` with the score and provenance fallbacks of older records."""
    score_value = record.get("score")
    prov = record.get("provenance")
    return (record.get("settings_hash")
            or (score_value.get("settings_hash") if isinstance(score_value, Mapping) else None)
            or (prov.get("settings_hash") if isinstance(prov, Mapping) else None))


def score(record: Mapping[str, Any]) -> dict[str, Any] | None:
    value = record.get("score")
    return dict(value) if isinstance(value, Mapping) else None


def compared_config(record: Mapping[str, Any]) -> dict[str, Any]:
    """The config fields that take part in the comparison, nested blocks flattened to ``block.key``."""
    out: dict[str, Any] = {}
    for key, value in config(record).items():
        if key in IGNORED_CONFIG_FIELDS:
            continue
        if key in NESTED_CONFIG_FIELDS and isinstance(value, Mapping):
            for sub_key, sub_value in value.items():
                out[f"{key}.{sub_key}"] = sub_value
            continue
        out[key] = value
    return out


# ---------------------------------------------------------------------------
# Weights (spec 15.3, 15.4; REVIEW_REPORTS-30)
# ---------------------------------------------------------------------------


def is_default_weights(weights: MRIWeights | Mapping[str, Any] | None) -> bool:
    """``True`` when ``weights`` equals the spec 15.3 default vector.

    Accepts the ``MRIWeights`` model or its dict form. ``None`` (no vector recorded)
    counts as default: nothing non-default was configured. Vectors are compared
    exactly, never renormalised.
    """
    default = MRIWeights().as_dict()
    if weights is None:
        return True
    if isinstance(weights, MRIWeights):
        return weights.as_dict() == default
    try:
        return {k: float(weights[k]) for k in default} == default
    except (KeyError, TypeError, ValueError):
        # A vector missing a key is not the default vector.
        return False


def record_weights(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """The weight vector the score was computed with, else the configured one."""
    score_value = score(record)
    if score_value is not None and isinstance(score_value.get("weights"), Mapping):
        return dict(score_value["weights"])
    scoring = config(record).get("scoring")
    if isinstance(scoring, Mapping) and isinstance(scoring.get("weights"), Mapping):
        return dict(scoring["weights"])
    return None


def non_default_weights(record: Mapping[str, Any]) -> bool:
    """The scorecard badge flag: the run was scored with a vector other than the default."""
    return not is_default_weights(record_weights(record))


# ---------------------------------------------------------------------------
# Compatibility (spec 15.6, 17.3 ``incompatible_campaigns``)
# ---------------------------------------------------------------------------


def compatibility(left: Mapping[str, Any], right: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """``(mismatched, unchanged)`` variable names, config field by config field plus the
    sampled-input digest. The model digest is reported separately: a different model
    with equal settings is the side-by-side case, not an incompatibility."""
    lc, rc = compared_config(left), compared_config(right)
    mismatched = [k for k in sorted(set(lc) | set(rc)) if lc.get(k) != rc.get(k)]
    unchanged = [k for k in sorted(lc) if k in rc and lc[k] == rc[k]]
    left_sample, right_sample = sample_hash(left), sample_hash(right)
    if not left_sample or not right_sample:
        mismatched.append(f"{SAMPLE_VARIABLE} (not recorded on both runs)")
    elif left_sample != right_sample:
        mismatched.append(SAMPLE_VARIABLE)
    else:
        unchanged.append(SAMPLE_VARIABLE)
    left_settings, right_settings = settings_hash(left), settings_hash(right)
    same_model = model_hash(left) is not None and model_hash(left) == model_hash(right)
    if same_model and not mismatched and left_settings and right_settings and left_settings != right_settings:
        # Same model, same compared config, different hash: the records disagree with
        # themselves, which is a refusal, not something to paper over.
        mismatched.append("settings_hash")
    if same_model:
        unchanged.append(MODEL_VARIABLE)
        if left_settings and left_settings == right_settings:
            unchanged.append("settings_hash")
    return mismatched, unchanged


def is_verify_pairing(left_id: str, left: Mapping[str, Any], left_overlay: Mapping[str, Any] | None,
                      right_id: str, right: Mapping[str, Any], right_overlay: Mapping[str, Any] | None) -> bool:
    """``True`` when one run is the other's verify run (``baseline_run_id`` names it)."""
    return bool(baseline_of(left, left_overlay) == right_id or baseline_of(right, right_overlay) == left_id)


def baseline_of(record: Mapping[str, Any], overlay: Mapping[str, Any] | None = None) -> Any:
    return record.get("baseline_run_id") or (overlay or {}).get("baseline_run_id")


def pair_reasons(left_id: str, left: Mapping[str, Any], left_overlay: Mapping[str, Any] | None,
                 right_id: str, right: Mapping[str, Any], right_overlay: Mapping[str, Any] | None,
                 ) -> tuple[list[str], list[str]]:
    """The full pairwise verdict: compatibility plus the verify-pairing model rule."""
    mismatched, unchanged = compatibility(left, right)
    pairing = is_verify_pairing(left_id, left, left_overlay, right_id, right, right_overlay)
    same_model = model_hash(left) is not None and model_hash(left) == model_hash(right)
    if pairing and not same_model:
        mismatched.append(f"{MODEL_VARIABLE} (a verify run and its baseline must share the model)")
    return mismatched, unchanged


def require_complete_score(run_id: str, record: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The score record of ``record`` when it is complete, else the reasons it is not."""
    score_value = score(record)
    if score_value is None:
        status = record.get("score_status")
        reason = status.get("reason") if isinstance(status, Mapping) else None
        return {}, [f"{run_id}: no score" + (f" ({reason})" if reason else "")]
    if score_value.get("mri") is None:
        missing = score_value.get("missing") or []
        detail = "; ".join(str(m) for m in missing) if isinstance(missing, list) and missing else "partial score"
        return score_value, [f"{run_id}: MRI not computed ({detail})"]
    return score_value, []


def changed_variables(left: Mapping[str, Any], right: Mapping[str, Any]) -> list[str]:
    changed: list[str] = []
    if model_hash(left) != model_hash(right):
        changed.append("model")
    if config(left).get("target_id") != config(right).get("target_id"):
        changed.append("target")
    if config(left).get("defense") != config(right).get("defense"):
        changed.append("defense")
    if not changed and (
        left.get("parent_run_id") == right.get("run_id")
        or right.get("parent_run_id") == left.get("run_id")
    ):
        changed.append("rerun")
    return changed


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def scorecard_projection(record: Mapping[str, Any], score_value: Mapping[str, Any]) -> dict[str, Any]:
    """A full MRIRecord with the tables it must never be shown without (spec 15.7, 15.8)."""
    target = record.get("target")
    return {
        **score_value,
        "run_id": record.get("run_id"),
        "model_sha256": model_hash(record),
        "target": dict(target) if isinstance(target, Mapping) else None,
        "measurements": list(record.get("measurements", [])),
        "curve": list(record.get("curve", [])),
        "limitations": list(record.get("limitations", [])),
        "non_default_weights": non_default_weights(record),
    }


def comparison_families(delta: Mapping[str, Any]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for item in delta.get("delta_families", []):
        if not isinstance(item, Mapping):
            continue
        before_value = item.get("before")
        after_value = item.get("after")
        before: dict[str, Any] = dict(before_value) if isinstance(before_value, Mapping) else {}
        after: dict[str, Any] = dict(after_value) if isinstance(after_value, Mapping) else {}
        flattened.append({
            "family": item.get("measurement_id"),
            "before": before.get("accuracy"),
            "after": after.get("accuracy"),
            "n_before": before.get("n"),
            "n_after": after.get("n"),
            "delta": item.get("delta"),
        })
    return flattened


def family_rows(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One row per measurement with every denominator (spec 14.2): ``k/n`` never a bare rate."""
    rows: list[dict[str, Any]] = []
    clean = next((m for m in record.get("measurements", []) if isinstance(m, Mapping) and m.get("family") == "clean"),
                 None)
    for m in record.get("measurements", []):
        if not isinstance(m, Mapping):
            continue
        n_clean_correct = m.get("n_clean_correct")
        if n_clean_correct is None and clean is not None and m.get("family") != "clean":
            n_clean_correct = clean.get("n_correct")
        raw_params = m.get("params")
        params: dict[str, Any] = dict(raw_params) if isinstance(raw_params, Mapping) else {}
        rows.append({
            "id": m.get("id"),
            "family": m.get("family"),
            "attack_id": m.get("attack_id"),
            "eps": params.get("eps"),
            "n": m.get("n"),
            "n_correct": m.get("n_correct"),
            "accuracy": m.get("accuracy"),
            "n_flipped_from_clean": m.get("n_flipped_from_clean"),
            "n_clean_correct": n_clean_correct,
            "asr": m.get("attack_success_rate"),
        })
    return rows


def measured_delta(
    *, verify: Mapping[str, Any], verify_score: Mapping[str, Any], baseline: Mapping[str, Any],
    baseline_score: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """The verify run's ΔMRI as a JSON dict and where it came from.

    Prefers the delta the worker persisted on the verify run's score record. Without
    one, the same ``redsim.ml.scoring.delta`` runs over the two stored records: it is a
    deterministic function of measured rows, so the result is still a measured delta.
    Its typed refusals become :class:`Incompatible` and :class:`ScoreUnavailable`.
    """
    persisted = verify_score.get("delta")
    if isinstance(persisted, Mapping):
        return dict(persisted), "persisted"
    from redsim.ml.schema import Measurement, MRIRecord
    from redsim.ml.scoring import IncompatibleCampaigns, delta

    try:
        before = MRIRecord.model_validate(dict(baseline_score))
        after = MRIRecord.model_validate(dict(verify_score))
        measured = delta(
            before, after, baseline_run_id=str(baseline.get("run_id")),
            measurements_before=[Measurement.model_validate(m) for m in baseline.get("measurements", [])],
            measurements_after=[Measurement.model_validate(m) for m in verify.get("measurements", [])],
            modality_before=config(baseline).get("modality"),
            modality_after=config(verify).get("modality"),
        )
    except IncompatibleCampaigns as exc:
        raise Incompatible(list(exc.reasons)) from exc
    except ValueError as exc:
        raise ScoreUnavailable([f"the verify delta could not be measured: {exc}"]) from exc
    return measured.model_dump(mode="json"), "computed"


# ---------------------------------------------------------------------------
# The N-run table (REVIEW_REPORTS-26)
# ---------------------------------------------------------------------------


def _table_row(run_id: str, record: Mapping[str, Any], score_value: Mapping[str, Any],
               overlay: Mapping[str, Any] | None) -> dict[str, Any]:
    target = record.get("target")
    subscores = score_value.get("subscores")
    return {
        "run_id": run_id,
        "kind": record.get("kind"),
        "created_at": record.get("created_at"),
        "completed_at": record.get("completed_at"),
        "model_sha256": model_hash(record),
        "target": dict(target) if isinstance(target, Mapping) else None,
        "settings_hash": settings_hash(record),
        "modality": config(record).get("modality"),
        "mri": score_value.get("mri"),
        "grade": score_value.get("grade"),
        "reading": score_value.get("reading"),
        "subscores": dict(subscores) if isinstance(subscores, Mapping) else None,
        "per_attack": dict(score_value.get("per_attack") or {}),
        "inputs": list(score_value.get("inputs") or []),
        "weights": record_weights(record),
        "non_default_weights": non_default_weights(record),
        "families": family_rows(record),
        "curve": list(record.get("curve", [])),
        "baseline_run_id": baseline_of(record, overlay),
        "defense": config(record).get("defense"),
        "delta": None,
        "delta_source": None,
        "delta_note": None,
        "limitations": list(record.get("limitations", [])),
    }


def comparison_table(
    runs: Sequence[tuple[str, Mapping[str, Any], Mapping[str, Any] | None]],
) -> dict[str, Any]:
    """The N-run comparison table over ``(run_id, record, campaign_overlay)`` triples.

    Rows come back in the order given. Every pair must be compatible (else
    :class:`Incompatible` with per-pair ``pairs``) and every run must carry a
    complete MRI (else :class:`ScoreUnavailable` naming the runs). A verify row
    whose own baseline is in the set carries its measured delta; every other
    row has ``delta: None``. No mean, rank or aggregate of any kind is computed.
    """
    if len(runs) < MIN_TABLE_RUNS:
        raise ValueError(f"a comparison table needs at least {MIN_TABLE_RUNS} runs")
    if len(runs) > MAX_TABLE_RUNS:
        raise ValueError(f"a comparison table takes at most {MAX_TABLE_RUNS} runs")
    ids = [run_id for run_id, _record, _overlay in runs]
    if len(set(ids)) != len(ids):
        raise ValueError("a run may appear only once in a comparison table")

    # Compatibility of every pair before any score is read.
    pairs: list[dict[str, Any]] = []
    reasons: list[str] = []
    unchanged_sets: list[set[str]] = []
    for i in range(len(runs)):
        for j in range(i + 1, len(runs)):
            left_id, left, left_overlay = runs[i]
            right_id, right, right_overlay = runs[j]
            mismatched, unchanged = pair_reasons(left_id, left, left_overlay, right_id, right, right_overlay)
            unchanged_sets.append(set(unchanged))
            if mismatched:
                pairs.append({"runs": [left_id, right_id], "reasons": mismatched})
                for reason in mismatched:
                    if reason not in reasons:
                        reasons.append(reason)
    if pairs:
        raise Incompatible(reasons, pairs=pairs)

    scores: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for run_id, record, _overlay in runs:
        score_value, why = require_complete_score(run_id, record)
        scores[run_id] = score_value
        missing.extend(why)
    if missing:
        raise ScoreUnavailable(missing)

    by_id = {run_id: (record, overlay) for run_id, record, overlay in runs}
    rows: list[dict[str, Any]] = []
    for run_id, record, overlay in runs:
        row = _table_row(run_id, record, scores[run_id], overlay)
        baseline_id = row["baseline_run_id"]
        if baseline_id in by_id and baseline_id != run_id:
            baseline_record, _baseline_overlay = by_id[baseline_id]
            delta_value, source = measured_delta(
                verify=record, verify_score=scores[run_id], baseline=baseline_record,
                baseline_score=scores[baseline_id],
            )
            row["delta"] = {
                "baseline_run_id": baseline_id,
                "mri_before": delta_value.get("mri_before"),
                "mri_after": delta_value.get("mri_after"),
                "delta_mri": delta_value.get("delta"),
                "delta_dimensions": delta_value.get("delta_subscores"),
                "delta_acc_clean": delta_value.get("delta_acc_clean"),
                "delta_families": comparison_families(delta_value),
            }
            row["delta_source"] = source
        elif baseline_id:
            row["delta_note"] = f"baseline run {baseline_id} is not in the compared set; no delta is shown"
        rows.append(row)

    first_id, first, _first_overlay = runs[0]
    changed_per_row = {
        run_id: ([] if run_id == first_id else changed_variables(first, record))
        for run_id, record, _overlay in runs
    }
    unchanged_all = sorted(set.intersection(*unchanged_sets)) if unchanged_sets else []
    caveats = sorted({str(lim) for _run_id, record, _overlay in runs for lim in record.get("limitations", [])})
    table = {
        "mode": "table",
        "compatible": True,
        "run_ids": list(ids),
        "rows": rows,
        "changed_variables_per_row": changed_per_row,
        "unchanged_variables": unchanged_all,
        "ignored_variables": list(IGNORED_VARIABLES),
        "caveats": caveats,
        "statement": ("Rows are listed in request order. Each MRI is shown with its subscores, denominators "
                      "and curve; no mean, rank or cross-model delta is computed (spec 15.8)."),
    }
    assert_no_aggregate_keys(table)
    return table


def assert_no_aggregate_keys(payload: Any, path: str = "") -> None:
    """Refuse a comparison payload that carries a mean, rank or average key (spec 15.8 i)."""
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key).lower() in FORBIDDEN_TABLE_KEYS:
                raise ValueError(f"comparison payload carries an aggregate key at {path}/{key}")
            assert_no_aggregate_keys(value, f"{path}/{key}")
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            assert_no_aggregate_keys(item, f"{path}[{index}]")


__all__ = [
    "FORBIDDEN_TABLE_KEYS",
    "IGNORED_CONFIG_FIELDS",
    "IGNORED_VARIABLES",
    "MAX_TABLE_RUNS",
    "MIN_TABLE_RUNS",
    "MODEL_VARIABLE",
    "NESTED_CONFIG_FIELDS",
    "SAMPLE_VARIABLE",
    "Incompatible",
    "ScoreUnavailable",
    "assert_no_aggregate_keys",
    "baseline_of",
    "changed_variables",
    "compared_config",
    "comparison_families",
    "comparison_table",
    "compatibility",
    "config",
    "family_rows",
    "is_default_weights",
    "is_verify_pairing",
    "measured_delta",
    "model_hash",
    "non_default_weights",
    "pair_reasons",
    "provenance",
    "record_weights",
    "require_complete_score",
    "sample_hash",
    "score",
    "scorecard_projection",
    "settings_hash",
]
