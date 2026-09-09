"""Admission mirrors two runner refusals so the sandbox child never sees them (wave-3 follow-ups).

Before this, ``POST /v1/models/{id}/attacks`` admitted two configurations that
``redsim.ml.campaign._resolve_attacks`` then refused inside the sandbox child,
turning a caller mistake into an enqueued job and a ``failed`` Run:

* ``noise_control`` in ``attack_ids``: the benign control is a ``control``
  adapter, runs automatically at every eps of the grid when ``include_control``
  is true (spec 12.4) and is never part of the attack set;
* ``fgsm`` under ``norm: "l2"``: FGSM is L-inf only (spec 12.2); only adapters
  that declare ``norm_l2`` (PGD, HopSkipJump) run under the L2 norm.

Both are now ``422 params_out_of_range`` at admission with the field that has to
change, one ``success=False`` ``attack.run`` row carrying ids only, and no
``Run`` / ``Job`` / ``ml_campaigns`` row or enqueue. The admissible pairings
(PGD under L-inf and L2, HopSkipJump under L2) stay ``202`` and the frozen
config passes the runner's own resolution, so admission and runner agree in
both directions. Offline, on the harness of ``tests/ml/test_campaign_routes.py``;
no sandbox child, no model bytes.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("numpy")

from redsim.db.models import Job
from redsim.ml.campaign import CONTROL_ATTACK_ID, _attack_params, _resolve_attacks
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.schema import CampaignConfig
from redsim.ml.scoring import DEFAULT_EPS_GRID_L2, DEFAULT_EPS_GRID_LINF, DEFAULT_REFERENCE_EPS
from tests.ml.test_campaign_routes import (
    MODEL,
    Harness,
    assert_refused,
    build_harness,
    launch,
    parent_config,
    seed_model,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


def frozen_config(harness: Harness, response: Any) -> CampaignConfig:
    """The immutable job input the worker parent hands to the sandbox child."""
    assert response.status_code == 202, response.text
    (job_id,) = response.json()["job_ids"]
    with harness.Session() as session:
        job = session.get(Job, job_id)
    assert job is not None and job.type == "attack.run"
    return CampaignConfig.model_validate(job.detail["campaign_config"])


def runner_accepts(config: CampaignConfig) -> dict[str, dict[str, Any]]:
    """The runner's pre-flight over a frozen config: attack resolution and the per-attack parameters."""
    adapters = _resolve_attacks(config, config.modality)
    return _attack_params(config, adapters)


def pre_fix_config(**overrides: Any) -> CampaignConfig:
    """The config the earlier admission froze for these requests (what the child then refused)."""
    return CampaignConfig.model_validate(parent_config(**overrides))


# --------------------------------------------------------------------------- (a) control in attack_ids

@pytest.mark.parametrize("attack_ids", [["noise_control"], ["fgsm", "noise_control"], ["noise_control", "pgd"]],
                         ids=["alone", "after_an_attack", "before_an_attack"])
def test_control_in_attack_ids_is_refused_at_admission(api: Harness, attack_ids: list[str]) -> None:
    assert CONTROL_ATTACK_ID == "noise_control"
    seed_model(api)

    detail = assert_refused(api, launch(api, {"attack_ids": attack_ids}), "params_out_of_range")

    assert detail["field"] == "attack_ids"
    assert "'noise_control'" in detail["message"] and "control" in detail["message"]
    assert "automatically" in detail["message"], "the message says the control runs on its own"
    assert "include_control" in detail["message"]
    assert detail["reasons"] == ["noise_control is family control, not evasion"]
    (refused,) = api.events("attack.run")
    assert refused.success is False and refused.detail["code"] == "params_out_of_range"
    assert refused.detail["attack_ids"] == attack_ids and refused.detail["target_id"] == MODEL
    assert "config" not in refused.detail and "message" not in refused.detail

    # The runner refuses exactly this configuration, so nothing admissible was lost.
    with pytest.raises(AttackNotApplicable, match="control runs automatically"):
        _resolve_attacks(pre_fix_config(attack_ids=attack_ids, attack_params={}), "image")


def test_control_still_runs_through_include_control_not_attack_ids(api: Harness) -> None:
    seed_model(api)

    config = frozen_config(api, launch(api, {"attack_ids": ["fgsm"], "include_control": True}))

    assert config.include_control is True and config.attack_ids == ["fgsm"]
    assert [a.id for a in config.attacks] == ["fgsm"], "the control is not an entry of the attack set"
    runner_accepts(config)


# --------------------------------------------------------------------------- (b) L-inf-only attack under l2

@pytest.mark.parametrize("attack_ids", [["fgsm"], ["pgd", "fgsm"]], ids=["alone", "beside_an_l2_capable_one"])
def test_fgsm_under_l2_norm_is_refused_at_admission(api: Harness, attack_ids: list[str]) -> None:
    seed_model(api)

    detail = assert_refused(api, launch(api, {"attack_ids": attack_ids, "norm": "l2"}), "params_out_of_range")

    assert detail["field"] == "norm"
    assert "'fgsm'" in detail["message"] and "L-inf" in detail["message"] and "'l2'" in detail["message"]
    assert "hopskipjump" in detail["message"] and "pgd" in detail["message"], "the L2-capable attacks are named"
    assert detail["reasons"] == ["fgsm declares no norm_l2 parameter"]
    (refused,) = api.events("attack.run")
    assert refused.success is False and refused.detail["attack_ids"] == attack_ids

    # Same refusal in the runner on the config the earlier admission would have frozen.
    with pytest.raises(AttackNotApplicable, match="L-inf norm only"):
        _resolve_attacks(pre_fix_config(attack_ids=attack_ids, attack_params={}, norm="l2",
                                        eps_grid=list(DEFAULT_EPS_GRID_L2),
                                        reference_eps=DEFAULT_EPS_GRID_L2[1]), "image")


def test_fgsm_under_l2_with_an_explicit_grid_is_refused_on_norm_not_the_grid(api: Harness) -> None:
    seed_model(api)
    detail = assert_refused(
        api, launch(api, {"attack_ids": ["fgsm"], "norm": "l2", "eps_grid": [0.25, 0.5], "reference_eps": 0.5}),
        "params_out_of_range",
    )
    assert detail["field"] == "norm", "a valid grid is not what has to change"


# --------------------------------------------------------------------------- admissible pairings stay admitted

def test_pgd_under_linf_is_admitted_and_the_runner_accepts_the_frozen_config(api: Harness) -> None:
    seed_model(api)

    config = frozen_config(api, launch(api, {"attack_ids": ["pgd"]}))

    assert config.norm == "linf" and config.eps_grid == list(DEFAULT_EPS_GRID_LINF)
    assert config.reference_eps == DEFAULT_REFERENCE_EPS
    assert config.attack_params == {"pgd": {}}
    assert runner_accepts(config) == {"pgd": {"norm_l2": False}}
    events = api.events("attack.run")
    assert len(events) == 1 and events[0].success and events[0].detail["norm"] == "linf"
    assert api.counts() == {"runs": 1, "jobs": 1, "campaigns": 1} and len(api.delay_calls) == 1


@pytest.mark.parametrize("attack_ids", [["pgd"], ["hopskipjump"], ["pgd", "hopskipjump"]],
                         ids=["pgd", "hopskipjump", "both"])
def test_l2_capable_attacks_under_l2_are_admitted(api: Harness, attack_ids: list[str]) -> None:
    seed_model(api)

    config = frozen_config(api, launch(api, {"attack_ids": attack_ids, "norm": "l2"}))

    assert config.norm == "l2" and config.eps_grid == list(DEFAULT_EPS_GRID_L2)
    assert config.reference_eps == DEFAULT_EPS_GRID_L2[1]
    params = runner_accepts(config)
    assert params == {aid: {"norm_l2": True} for aid in attack_ids}, "the runner derives norm_l2 from config.norm"
    assert all(not overrides for overrides in config.attack_params.values()), "no grid-owned key is frozen"


def test_fgsm_under_linf_is_still_admitted(api: Harness) -> None:
    seed_model(api)
    config = frozen_config(api, launch(api, {"attack_ids": ["fgsm", "pgd"], "norm": "linf"}))
    assert config.norm == "linf" and [a.id for a in config.attacks] == ["fgsm", "pgd"]
    assert runner_accepts(config) == {"fgsm": {}, "pgd": {"norm_l2": False}}
