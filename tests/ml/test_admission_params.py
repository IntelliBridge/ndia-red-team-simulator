"""Admission freezes runnable ``attack_params`` and reads applicability from capability tags.

Two defects that failed every API-launched campaign (track campaign-admission-params):

* ``create_attack_campaign`` froze ``adapter.resolve_params(...)`` into
  ``CampaignConfig.attack_params``, which carries the ``eps`` default (and PGD's
  ``norm_l2``); ``redsim.ml.campaign._attack_params`` refuses both in the sandbox
  child because eps comes from ``eps_grid`` and the norm from ``config.norm``.
* applicability compared ``AttackInfo.domain`` (the primary domain) with the
  model modality, refusing PGD by surrogate transfer on tabular targets although
  the adapter declares ``modality:tabular`` (spec 12.9).

Offline, on the harness of ``tests/ml/test_campaign_routes.py``. Runner-side
acceptance is checked with the real ``_resolve_attacks`` / ``_attack_params`` over
the frozen config plus the ``resolve_params`` pre-flight ``run_campaign`` performs
per grid member; no sandbox child is launched and no model is loaded.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.db.models import Job
from redsim.ml.attacks import get_attack
from redsim.ml.campaign import _attack_params, _resolve_attacks
from redsim.ml.schema import CampaignConfig
from redsim.services.ml_campaigns import _GRID_OWNED_PARAMS
from tests.ml.test_campaign_routes import (
    MODEL,
    Harness,
    assert_refused,
    build_harness,
    launch,
    parent_config,
    seed_campaign_run,
    seed_model,
)

pytestmark = pytest.mark.integration

GRID_OWNED = {"eps", "norm_l2"}
PGD_OVERRIDES: dict[str, Any] = {"max_iter": 5, "eps_step_ratio": 0.5}


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


def frozen_config(harness: Harness, response: Any) -> CampaignConfig:
    """The immutable job input the worker parent will hand to the sandbox child."""
    assert response.status_code == 202, response.text
    (job_id,) = response.json()["job_ids"]
    with harness.Session() as session:
        job = session.get(Job, job_id)
    assert job is not None and job.type == "attack.run"
    config = CampaignConfig.model_validate(job.detail["campaign_config"])
    row = harness.campaign_row(response.json()["run_id"])
    assert row is not None and row["config"]["attack_params"] == job.detail["campaign_config"]["attack_params"]
    return config


def runner_params(config: CampaignConfig) -> dict[str, dict[str, Any]]:
    """What ``run_campaign`` derives before the first attack cell, on the frozen config.

    ``_attack_params`` is the call that raised ``attack_params[...] must not set
    ['eps']`` on the pre-fix shape; the ``resolve_params`` loop mirrors the
    pre-flight ``run_campaign`` does per grid member (eps merged in for
    eps-taking attacks, bare parameters otherwise).
    """
    adapters = _resolve_attacks(config, config.modality)
    params = _attack_params(config, adapters)
    for adapter in adapters:
        if getattr(adapter, "takes_eps", True):
            for eps in config.eps_grid:
                adapter.resolve_params({**params[adapter.id], "eps": eps})
        else:
            adapter.resolve_params(params[adapter.id])
    return params


# --------------------------------------------------------------------------- (A) frozen attack_params

def test_grid_owned_set_matches_the_runner() -> None:
    assert set(_GRID_OWNED_PARAMS) == GRID_OWNED


def test_frozen_params_carry_no_grid_owned_keys_and_the_runner_accepts_them(api: Harness) -> None:
    seed_model(api)

    config = frozen_config(api, launch(api, {"attack_ids": ["fgsm", "pgd"],
                                             "attack_params": {"pgd": PGD_OVERRIDES}}))

    # Caller overrides only: no adapter default, no eps, no norm_l2, no derived eps_step.
    assert config.attack_params == {"fgsm": {}, "pgd": PGD_OVERRIDES}
    for attack_id, params in config.attack_params.items():
        assert not (set(params) & GRID_OWNED), attack_id
    # The runner derives eps from the grid and norm_l2 from the norm on top of the overrides.
    assert runner_params(config) == {"fgsm": {}, "pgd": {**PGD_OVERRIDES, "norm_l2": False}}


def test_the_pre_fix_shape_is_what_the_runner_refuses(api: Harness) -> None:
    """Guard on the guard: the frozen-default shape fails ``_attack_params`` the way the sandbox did."""
    seed_model(api)
    config = frozen_config(api, launch(api, {"attack_ids": ["fgsm", "pgd"]}))
    pre_fix = config.model_copy(update={"attack_params": {
        "fgsm": get_attack("fgsm").resolve_params({}),
        "pgd": get_attack("pgd").resolve_params({}),
    }})
    assert "eps" in pre_fix.attack_params["fgsm"] and "norm_l2" in pre_fix.attack_params["pgd"]
    with pytest.raises(ValueError, match=r"attack_params\['fgsm'\] must not set \['eps'\]"):
        _attack_params(pre_fix, _resolve_attacks(pre_fix, pre_fix.modality))
    assert runner_params(config) == {"fgsm": {}, "pgd": {"norm_l2": False}}


def test_caller_supplied_grid_owned_keys_are_stripped_and_other_keys_kept_coerced(api: Harness) -> None:
    seed_model(api)

    config = frozen_config(api, launch(api, {
        "attack_ids": ["fgsm", "pgd"],
        # eps / norm_l2 are the runner's; batch_size 32.0 is coerced to the schema's int; eps_step is
        # derived by the PGD adapter and never frozen.
        "attack_params": {"fgsm": {"eps": 0.5, "batch_size": 32.0},
                          "pgd": {"norm_l2": True, "eps": 0.9, "eps_step": 0.01, "max_iter": 3}},
    }))

    assert config.attack_params == {"fgsm": {"batch_size": 32}, "pgd": {"max_iter": 3}}
    assert isinstance(config.attack_params["fgsm"]["batch_size"], int)
    assert config.norm == "linf", "a stripped norm_l2 never overrides the campaign norm"
    assert runner_params(config) == {"fgsm": {"batch_size": 32}, "pgd": {"max_iter": 3, "norm_l2": False}}


@pytest.mark.parametrize(
    ("attack_params", "field"),
    [
        pytest.param({"pgd": {"eps": 0.5, "max_iter": 999}}, "attack_params.pgd", id="stripped_key_hides_nothing"),
        pytest.param({"fgsm": {"batch_size": 0}}, "attack_params.fgsm", id="below_min"),
        pytest.param({"fgsm": {"nonsense": 1}}, "attack_params.fgsm", id="unknown_key"),
    ],
)
def test_caller_values_are_still_validated(api: Harness, attack_params: dict[str, Any], field: str) -> None:
    seed_model(api)
    detail = assert_refused(api, launch(api, {"attack_ids": ["fgsm", "pgd"], "attack_params": attack_params}),
                            "params_out_of_range")
    assert detail["field"] == field


def test_rerun_of_a_parent_frozen_by_the_earlier_build_is_sanitized(api: Harness) -> None:
    """The parent carries the resolved defaults (eps, norm_l2, eps_step); the rerun must be runnable."""
    seed_model(api)
    # The pre-fix admission froze every adapter default (``parent_config`` now freezes the post-fix shape).
    parent = parent_config(attack_params={
        "fgsm": get_attack("fgsm").resolve_params({}),
        "pgd": get_attack("pgd").resolve_params({"max_iter": 5, "eps_step_ratio": 0.5}),
    })
    assert "eps" in parent["attack_params"]["fgsm"] and "norm_l2" in parent["attack_params"]["pgd"]
    seed_campaign_run(api, "run-parent-failed", status="failed", config=parent)

    response = launch(api, {"parent_run_id": "run-parent-failed"})
    config = frozen_config(api, response)

    assert config.attack_params == {
        "fgsm": {"batch_size": 64},
        "pgd": {"eps_step_ratio": 0.5, "max_iter": 5, "num_random_init": 0, "batch_size": 64},
    }
    assert config.seed == parent["seed"] == 7 and config.eps_grid == parent["eps_grid"]
    assert runner_params(config)["pgd"] == {"eps_step_ratio": 0.5, "max_iter": 5, "num_random_init": 0,
                                            "batch_size": 64, "norm_l2": False}
    row = api.campaign_row(response.json()["run_id"])
    assert row is not None and row["parent_run_id"] == "run-parent-failed"
    assert dict(api.campaign_row("run-parent-failed") or {})["config"] == parent, "the parent is untouched"


# --------------------------------------------------------------------------- (B) applicability

def test_pgd_by_surrogate_on_a_tabular_target_is_admitted(api: Harness) -> None:
    # A tabular tree ensemble exposes gradients only through its declared surrogate
    # (``redsim.ml.targets.tabular``: ``gradients = bool(surrogate)``), which is what the manifest says.
    seed_model(api, modality="tabular", gradients=True)

    config = frozen_config(api, launch(api, {"attack_ids": ["pgd", "hopskipjump"]}))

    assert config.modality == "tabular" and [a.id for a in config.attacks] == ["pgd", "hopskipjump"]
    assert config.attacks[0].domain == "image", "AttackInfo.domain is the primary domain; capabilities decide"
    assert config.attack_params == {"pgd": {}, "hopskipjump": {}}
    params = runner_params(config)
    assert params == {"pgd": {"norm_l2": False}, "hopskipjump": {"norm_l2": False}}
    events = api.events("attack.run")
    assert len(events) == 1 and events[0].success and events[0].detail["attack_ids"] == ["pgd", "hopskipjump"]


@pytest.mark.parametrize("attack_ids", [["fgsm"], ["pgd", "fgsm"]], ids=["alone", "beside_an_admissible_one"])
def test_image_only_attack_on_a_tabular_target_is_refused(api: Harness, attack_ids: list[str]) -> None:
    seed_model(api, modality="tabular", gradients=True)

    detail = assert_refused(api, launch(api, {"attack_ids": attack_ids}), "attack_modality_mismatch")

    assert detail["field"] == "attack_ids"
    assert "'fgsm'" in detail["message"] and "['image']" in detail["message"] and "'tabular'" in detail["message"]
    refused = api.events("attack.run")[0]
    assert refused.detail["attack_ids"] == attack_ids and refused.detail["target_id"] == MODEL
