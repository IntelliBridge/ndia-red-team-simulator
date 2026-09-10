"""Golden-record test for the ``run_campaign`` refactor (Phase B, MODALITIES-09; ``ml`` tier).

``redsim.ml.campaign.run_campaign`` was split into a shared frame plus a ``ModalityRunner`` with the
classification runner (image and tabular) carrying today's code. ``tests/ml/_campaign_pre_refactor.py`` is
the pre-refactor function frozen byte for byte from ``main`` at ``7706950``; every scenario below runs on
both and the records must agree on every non-volatile field: measurements (ids, denominators, counts,
norms, notes), observations, interpretation, recommendations, curve, score, limitations, ``stages_done``,
the artifact set and ``flip_matrix.json``. Both sides run in one process against the same tree, so a
sibling change to an adapter or an explainer cannot produce a false mismatch. Volatile fields
(run id, timestamps, wall times, hostname, library versions, thread env) are stripped by
:func:`normalize`; floats compare within ``rel_tol=1e-6``.

Delete this file and the frozen copy together once the Phase B modality runners have landed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("torch")
pytest.importorskip("art")

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.campaign import run_campaign
from redsim.ml.schema import CampaignConfig
from redsim.ml.targets.registry import TARGETS
from tests.ml import _campaign_pre_refactor as pre_refactor
from tests.ml.fakes import TABULAR_DATASET, TinyTabularTarget, TinyTarget
from tests.ml.test_campaign import EXPLAIN_MOD, RULES_MOD, SUMMARY_MOD, make_fake_explain

pytestmark = pytest.mark.ml

#: sha256 of the frozen copy: redsim/ml/campaign.py on main at 7706950 minus the defense branches, which left
#: with the verify paradigm on 2026-09-09 (``_defense_provenance``, ``DEFENSE_LIMITATION``, the ``apply_defense``
#: calls, ``baseline_run_id`` and the ``MLError`` import they used; nothing else changed).
PRE_REFACTOR_SHA256 = "fe86096a052a6cb8aaba656077a0f736a33b90ae7e538259f9029d3c853879ba"
PRE_REFACTOR_HEADER_LINES = 4
Runner = Callable[..., Any]
GRID = [0.01, 0.03, 0.1]
REF = 0.03

if TARGETS.maybe_get("tiny") is None:
    TARGETS.register(TinyTarget(seed=0))


# --- scenarios -----------------------------------------------------------------------------------------

def _image_config(**overrides: Any) -> CampaignConfig:
    cfg: dict[str, Any] = {"target_id": "tiny", "modality": "image", "attack_ids": ["fgsm", "pgd"],
                           "attack_params": {"pgd": {"max_iter": 3}}, "eps_grid": GRID, "reference_eps": REF,
                           "n_samples": 16, "seed": 0, "explain_k": 4, "dataset_id": "synthetic"}
    cfg.update(overrides)
    return CampaignConfig(**cfg)


def _tabular_config(**overrides: Any) -> CampaignConfig:
    cfg: dict[str, Any] = {"target_id": "tiny_tabular", "modality": "tabular", "attack_ids": ["pgd"],
                           "attack_params": {"pgd": {"max_iter": 3}},
                           "eps_grid": GRID, "reference_eps": REF, "n_samples": 24, "seed": 0, "explain_k": 4,
                           "dataset_id": TABULAR_DATASET}
    cfg.update(overrides)
    return CampaignConfig(**cfg)


#: name -> (config factory, run_campaign kwargs factory, sys.modules overrides). ``"__real__"`` means the
#: real module must be importable (a ``None`` entry left by another test is lifted for the run). HopSkipJump
#: is deliberately absent: ART draws its initial point from an unseeded ``RandomState`` (the adapter records
#: that nondeterminism), so it cannot be part of a golden record.
SCENARIOS: dict[str, dict[str, Any]] = {
    # image, fgsm + pgd, injected deterministic explainer, real rules and summary: complete MRI
    "image_fgsm_pgd_explain": {
        "config": lambda: _image_config(),
        "kwargs": lambda: {"explain": True},
        "modules": {EXPLAIN_MOD: "fake_explain", RULES_MOD: "__real__", SUMMARY_MOD: "__real__"},
    },
    # tabular, pgd by surrogate transfer, TreeExplainer on the real model, real rules and summary
    "tabular_pgd_explain": {
        "config": lambda: _tabular_config(),
        "kwargs": lambda: {"explain": True, "target_override": TinyTabularTarget(seed=0)},
        "modules": {RULES_MOD: "__real__", SUMMARY_MOD: "__real__"},
    },
    # tabular without a surrogate: pgd recorded not_run, clean and control rows only, no score
    "tabular_all_not_run": {
        "config": lambda: _tabular_config(),
        "kwargs": lambda: {"explain": False, "target_override": TinyTabularTarget(seed=0, surrogate=False)},
        "modules": {RULES_MOD: None},
    },
    # image, fgsm only, explain off, real rules: partial score, candidates from the rows alone
    "image_fgsm_no_explain": {
        "config": lambda: _image_config(attack_ids=["fgsm"], attack_params={}),
        "kwargs": lambda: {"explain": False},
        "modules": {RULES_MOD: "__real__"},
    },
}


@contextlib.contextmanager
def _modules(overrides: dict[str, Any]) -> Iterator[None]:
    saved = {name: sys.modules.get(name, "__absent__") for name in overrides}
    try:
        for name, value in overrides.items():
            if value == "__real__":
                if sys.modules.get(name, "x") is None:
                    del sys.modules[name]
            elif value == "fake_explain":
                sys.modules[name] = make_fake_explain(shift=0.4)
            else:
                sys.modules[name] = value
        yield
    finally:
        for name, before in saved.items():
            if before == "__absent__":
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = before


# --- normalisation -------------------------------------------------------------------------------------

_VOLATILE_TOP = ("run_id", "created_at", "completed_at")
_VOLATILE_PROVENANCE = ("started_at", "finished_at", "hostname", "thread_env", "redsim_version", "python", "torch",
                        "art", "shap", "numpy", "onnxruntime", "sklearn", "xgboost")
_VOLATILE_MANIFEST = ("library_versions", "python_executable")


def normalize(record: dict[str, Any]) -> dict[str, Any]:
    """The record without its volatile fields (ids, clocks, hosts, versions, wall times)."""
    out = json.loads(json.dumps(record, sort_keys=True, default=str))
    for key in _VOLATILE_TOP:
        out.pop(key, None)
    prov = out.get("provenance") or {}
    for key in _VOLATILE_PROVENANCE:
        prov.pop(key, None)
    manifest = prov.get("model_manifest") or {}
    for key in _VOLATILE_MANIFEST:
        manifest.pop(key, None)
    for m in out.get("measurements") or []:
        m.pop("wall_time_s", None)
        m["notes"] = [n for n in m.get("notes") or [] if not n.startswith("wall_time_s")]
    score = out.get("score")
    if isinstance(score, dict):
        score.pop("computed_at", None)
    return out


def capture(name: str, root: Path, run: Runner = run_campaign) -> dict[str, Any]:
    """Run scenario ``name`` into ``root`` with ``run`` (the refactored frame by default, or the frozen
    pre-refactor function) and return its golden view."""
    scenario = SCENARIOS[name]
    sink = FilesystemSink(root)
    with _modules(dict(scenario["modules"])):
        record = run(scenario["config"](), sink, **scenario["kwargs"]())
    art = Path(sink.root)
    # Phase B export slices (INTEROP-04: clean_slice.npz, control_slice/<eps>.npz) are written by the
    # classification runner only; the frozen pre-refactor function cannot write them, so they are
    # excluded from the artifact pin on both sides. Record, stages_done and flip_matrix stay exact.
    names = sorted(
        rel for p in art.rglob("*") if p.is_file()
        for rel in [str(p.relative_to(art)).replace(os.sep, "/")]
        if not rel.startswith(("artifacts/clean_slice", "artifacts/control_slice"))
    )
    flips = json.loads((art / "artifacts" / "flip_matrix.json").read_text(encoding="utf-8"))
    return {"record": normalize(record.model_dump(mode="json")), "artifacts": names, "flip_matrix": flips}


def assert_deep_close(expected: Any, actual: Any, path: str = "$") -> None:
    """Deep equality with a float tolerance; the first difference is reported with its path."""
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{path}: expected an object, got {type(actual).__name__}"
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        assert not missing and not extra, f"{path}: keys differ (missing={missing}, extra={extra})"
        for key in expected:
            assert_deep_close(expected[key], actual[key], f"{path}.{key}")
    elif isinstance(expected, list):
        assert isinstance(actual, list), f"{path}: expected a list, got {type(actual).__name__}"
        assert len(expected) == len(actual), f"{path}: length {len(expected)} != {len(actual)}"
        for i, (e, a) in enumerate(zip(expected, actual, strict=True)):
            assert_deep_close(e, a, f"{path}[{i}]")
    elif isinstance(expected, bool) or expected is None or isinstance(expected, str):
        assert expected == actual, f"{path}: {expected!r} != {actual!r}"
    elif isinstance(expected, (int, float)):
        assert isinstance(actual, (int, float)) and not isinstance(actual, bool), f"{path}: {expected!r} != {actual!r}"
        assert math.isclose(float(expected), float(actual), rel_tol=1e-6, abs_tol=1e-9), \
            f"{path}: {expected!r} != {actual!r}"
    else:  # pragma: no cover - the JSON view has no other types
        assert expected == actual, f"{path}: {expected!r} != {actual!r}"


# --- tests ----------------------------------------------------------------------------------------------

def test_frozen_copy_is_the_pre_refactor_function() -> None:
    """The reference is main's campaign.py at 7706950, byte for byte after the four header lines."""
    text = Path(pre_refactor.__file__).read_text(encoding="utf-8")
    body = "\n".join(text.split("\n")[PRE_REFACTOR_HEADER_LINES:])
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() == PRE_REFACTOR_SHA256
    assert pre_refactor.run_campaign is not run_campaign


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_refactored_campaign_matches_the_pre_refactor_record(name: str, tmp_path: Path) -> None:
    golden = capture(name, tmp_path / "pre", pre_refactor.run_campaign)
    current = capture(name, tmp_path / "new", run_campaign)
    assert golden["record"]["stages_done"] == current["record"]["stages_done"]
    assert golden["artifacts"] == current["artifacts"]
    assert_deep_close(golden["flip_matrix"], current["flip_matrix"], "flip_matrix")
    assert_deep_close(golden["record"], current["record"], "record")
    # the comparison is not vacuous: the measurement table, the curve and the limitations are populated
    rec = current["record"]
    assert rec["measurements"] and rec["limitations"] and rec["stages_done"][-1] == "report"
    assert rec["measurements"][0]["id"] == "m.clean" and rec["measurements"][0]["n"] > 0


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_normalisation_strips_every_volatile_field(name: str, tmp_path: Path) -> None:
    """Two runs of one scenario agree after normalisation, so a golden mismatch is a behaviour change."""
    first = capture(name, tmp_path / "a")
    second = capture(name, tmp_path / "b")
    assert first == second
    rec = first["record"]
    assert "run_id" not in rec and "created_at" not in rec and "hostname" not in rec["provenance"]
    assert all("wall_time_s" not in m for m in rec["measurements"])
