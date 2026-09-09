"""Model-card score summaries: means over scored campaigns, pooled rates per probe family."""
from __future__ import annotations

from redsim.services.ml_scores import aggregate_llm, aggregate_mri


def test_aggregate_mri_means_the_index_and_each_subscore() -> None:
    scores = [
        {"mri": 60, "subscores": {"S_acc": 70.0, "S_asr": 50.0, "S_eps": 40.0, "S_conf": None, "S_expl": 80.0}},
        {"mri": 40, "subscores": {"S_acc": 50.0, "S_asr": 30.0, "S_eps": 20.0, "S_conf": 90.0, "S_expl": None}},
        {"mri": None, "subscores": {}},
    ]
    out = aggregate_mri(scores)
    assert out is not None and out["kind"] == "mri" and out["n_campaigns"] == 3
    assert out["mri_mean"] == 50.0
    assert out["subscores_mean"] == {"S_acc": 60.0, "S_asr": 40.0, "S_eps": 30.0, "S_conf": 90.0, "S_expl": 80.0}
    assert "not a new measurement" in out["note"]
    assert aggregate_mri([]) is None


def test_aggregate_llm_pools_hits_per_family_over_runs() -> None:
    def card(fam: str, probe: str, hits: int, n: int, status: str = "run") -> dict:
        return {"families": [{"family": fam, "probes": [{"probe_id": probe, "status": status,
                "detectors": [{"detector": "d", "status": "run", "n_hits": hits, "n_evaluated": n}]}]}]}

    out = aggregate_llm([card("dan", "dan.A", 4, 16), card("dan", "dan.B", 2, 4), card("encoding", "enc.X", 0, 8),
                         card("skip", "skip.Y", 9, 9, status="not_run")])
    assert out is not None and out["kind"] == "llm" and out["n_runs"] == 4
    assert out["families"] == [
        {"family": "dan", "n_hits": 6, "n_evaluated": 20, "hit_rate": 0.3, "n_probes": 2},
        {"family": "encoding", "n_hits": 0, "n_evaluated": 8, "hit_rate": 0.0, "n_probes": 1},
    ]
    assert aggregate_llm([]) is None
