"""Per-model score summaries for the model catalog (owner request, 2026-09-09).

A model card shows the average of what its campaigns measured, broken out by
category: for a classifier the mean MRI and the mean of each of the five
subscores over its scored attack campaigns; for an LLM target the pooled hit
rate per probe family over its succeeded probe runs. Every summary carries the
number of campaigns or runs it averages and a note pointing at the per-run
scorecards, which keep the denominators. Nothing here is a new measurement;
a model with no scored run gets ``None``.

Pure aggregation helpers (``aggregate_mri``, ``aggregate_llm``) are separate
from the database reads so they can be tested on plain dicts.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

SUBSCORE_KEYS = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
MRI_NOTE = ("Mean over the scored attack campaigns of this model. Each campaign's scorecard "
            "carries its denominators and epsilon curve; the mean is a reading aid, not a new measurement.")
LLM_NOTE = ("Hit rate pooled over the succeeded probe runs of this model, per probe family: hits divided by "
            "evaluated replies. A hit is the detector's judgement, not a verified harm.")


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


def aggregate_mri(scores: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Average MRI and subscores over score dicts (``MRIRecord`` dumps). ``None`` without any."""
    rows = [s for s in scores if isinstance(s, Mapping)]
    if not rows:
        return None
    mris = [float(s["mri"]) for s in rows if isinstance(s.get("mri"), (int, float))]
    subs: dict[str, list[float]] = {k: [] for k in SUBSCORE_KEYS}
    for s in rows:
        raw = s.get("subscores")
        sub: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        for k in SUBSCORE_KEYS:
            v = sub.get(k)
            if isinstance(v, (int, float)):
                subs[k].append(float(v))
    return {
        "kind": "mri",
        "n_campaigns": len(rows),
        "mri_mean": _mean(mris),
        "subscores_mean": {k: _mean(v) for k, v in subs.items()},
        "note": MRI_NOTE,
    }


def aggregate_llm(scorecards: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Pooled hit rate per probe family over ``LLMProbeScorecard`` dumps. ``None`` without any."""
    cards = [c for c in scorecards if isinstance(c, Mapping)]
    if not cards:
        return None
    pooled: dict[str, dict[str, Any]] = {}
    for card in cards:
        for fam in card.get("families") or []:
            if not isinstance(fam, Mapping):
                continue
            name = str(fam.get("family") or "other")
            bucket = pooled.setdefault(name, {"family": name, "n_hits": 0, "n_evaluated": 0, "probes": set()})
            for probe in fam.get("probes") or []:
                if not isinstance(probe, Mapping) or probe.get("status") != "run":
                    continue
                for det in probe.get("detectors") or []:
                    if not isinstance(det, Mapping) or det.get("status", "run") != "run":
                        continue
                    n_eval = int(det.get("n_evaluated") or 0)
                    if n_eval <= 0:
                        continue
                    bucket["n_hits"] += int(det.get("n_hits") or 0)
                    bucket["n_evaluated"] += n_eval
                    bucket["probes"].add(str(probe.get("probe_id")))
    families = []
    for name in sorted(pooled):
        b = pooled[name]
        if b["n_evaluated"] <= 0:
            continue
        families.append({
            "family": name, "n_hits": b["n_hits"], "n_evaluated": b["n_evaluated"],
            "hit_rate": round(b["n_hits"] / b["n_evaluated"], 4), "n_probes": len(b["probes"]),
        })
    return {"kind": "llm", "n_runs": len(cards), "families": families, "note": LLM_NOTE}


# Per-process cache of summaries: the LLM branch reads one scorecard artifact
# per succeeded probe run from the blob store, which made the model list take
# seconds. A target's summary changes only when a run finishes, so it is kept
# for a short window and re-read after it.
_CACHE_TTL_S = 120.0
_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}


def cached_score_summary(session: Session, target: Any) -> dict[str, Any] | None:
    """``score_summary`` with a 120 s per-process cache keyed by target id."""
    import time

    now = time.monotonic()
    hit = _cache.get(str(target.id))
    if hit is not None and now - hit[0] < _CACHE_TTL_S:
        return hit[1]
    value = score_summary(session, target)
    _cache[str(target.id)] = (now, value)
    return value


def score_summary(session: Session, target: Any) -> dict[str, Any] | None:
    """The summary for one ``Target`` row, or ``None`` when nothing scored exists or a read fails."""
    try:
        if _is_llm(target):
            return _llm_summary(session, target.id)
        return _mri_summary(session, target.id)
    except Exception:  # noqa: BLE001 - the catalog must list the model even when its history cannot be read
        logger.info("score summary unavailable for %s", target.id, exc_info=True)
        return None


def _is_llm(target: Any) -> bool:
    raw_detail = getattr(target, "detail", None)
    detail: dict[str, Any] = raw_detail if isinstance(raw_detail, dict) else {}
    raw_endpoint = detail.get("endpoint")
    endpoint: dict[str, Any] = raw_endpoint if isinstance(raw_endpoint, dict) else {}
    return str(endpoint.get("kind") or detail.get("endpoint_kind") or "").lower() == "llm" or \
        str(detail.get("modality") or "").lower() == "llm"


def _mri_summary(session: Session, target_id: str) -> dict[str, Any] | None:
    from redsim.services.ml_models import _campaign_rows, _campaign_runs

    runs = [r for r in _campaign_runs(session, target_id) if r.status == "succeeded"]
    rows, available = _campaign_rows(session, [r.id for r in runs])
    if not available:
        return None
    scores = [rows[r.id]["score"] for r in runs if isinstance(rows.get(r.id), Mapping) and rows[r.id].get("score")]
    return aggregate_mri(scores)


def _llm_summary(session: Session, target_id: str) -> dict[str, Any] | None:
    from redsim.services.ml_llm import probe_history, read_llm_scorecard

    cards: list[Mapping[str, Any]] = []
    for entry in probe_history(session, target_id):
        if entry.get("status") != "succeeded":
            continue
        try:
            card, _meta = read_llm_scorecard(session, str(entry["run_id"]))
        except Exception:  # noqa: BLE001 - one unreadable scorecard must not hide the others
            logger.info("scorecard unreadable for %s", entry.get("run_id"), exc_info=True)
            continue
        cards.append(card)
    return aggregate_llm(cards)
