"""``redsim.ml.datasets`` imports cleanly before ``redsim.ml.targets``, with no ml extra installed.

Regression test for the collection error the ``Unit tests (py3.13)`` CI lane hit on ``main`` at
``bb43bd7``: ``tests/ml/test_cifar10_fixture.py`` imported ``redsim.ml.datasets.cifar10`` first, which
pulled ``redsim.ml.datasets.sampling`` -> ``redsim.ml.targets.base`` -> ``redsim.ml.targets`` (the
package ``__init__`` registers every target) -> ``redsim.ml.targets.bundled`` -> back into the
half-initialised ``redsim.ml.datasets.sampling``::

    ImportError: cannot import name 'as_model_input' from partially initialized module
    'redsim.ml.datasets.sampling' (most likely due to a circular import)

On 3.12 the cycle was masked because an ``ml``-marked module that imports ``redsim.ml.targets``
happened to be collected earlier. Without torch, those modules ``importorskip`` at the top and the
datasets package is the first thing imported, so the order below is exactly what the 3.13 lane sees.

Each case runs in a fresh interpreter with the ml libraries blocked (``sys.modules[name] = None``
makes ``import torch`` raise), so the test does not depend on what the current process has already
imported and it also proves that none of these modules needs the ml extra at import time.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("numpy")

ROOT = Path(__file__).resolve().parents[2]

BLOCKED = ("torch", "torchvision", "art", "shap", "sklearn", "onnx", "onnxruntime", "onnx2torch", "xgboost")

_PROBE = r"""
import importlib, json, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
for name in %r:
    importlib.import_module(name)
import redsim.ml.datasets.sampling as sampling
import redsim.ml.targets as targets
import redsim.ml.targets.base as base
print(json.dumps({
    "same_sample": base.Sample is sampling.Sample and targets.Sample is sampling.Sample,
    "loaded": sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None),
}))
"""

# Import orders that a real collection can produce. The first is the 3.13-lane order that failed;
# the second is the minimal cycle; the third is the order that always worked and must keep working.
ORDERS = {
    "datasets-first-like-py3.13": ("redsim.ml.datasets.cifar10", "redsim.ml.targets", "redsim.ml.datasets.sampling"),
    "sampling-first": ("redsim.ml.datasets.sampling", "redsim.ml.targets"),
    "targets-first": ("redsim.ml.targets", "redsim.ml.datasets.cifar10", "redsim.ml.datasets.sampling"),
}


def _probe(order: tuple[str, ...]) -> dict:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE % (BLOCKED, order)],
        capture_output=True, text=True, cwd=ROOT, env=env, timeout=120, check=False,
    )
    assert proc.returncode == 0, (
        f"importing {' -> '.join(order)} in a fresh interpreter without the ml extra failed:\n{proc.stderr}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("order", list(ORDERS.values()), ids=list(ORDERS))
def test_datasets_and_targets_import_in_any_order_without_the_ml_extra(order: tuple[str, ...]) -> None:
    out = _probe(order)
    # ``Sample`` is one class however it is reached: the dataclass the loaders build and the type the
    # ``Target`` protocol and every attack annotate against.
    assert out["same_sample"] is True
    assert out["loaded"] == [], f"an ml library was imported at module import time: {out['loaded']}"


def test_datasets_package_does_not_import_the_targets_package() -> None:
    """The layering the fix relies on: datasets never imports targets at module import time.

    ``redsim.ml.targets`` registers every target on import and reaches back into the datasets package, so
    a datasets module importing it (even for a type) recreates the cycle the moment datasets is imported
    first. Checked in a fresh interpreter so the assertion is about the import graph, not this process.
    """
    code = (
        "import sys; import redsim.ml.datasets.cifar10, redsim.ml.datasets.sampling; "
        "print(sorted(m for m in sys.modules if m.startswith('redsim.ml.targets')))"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, env=env, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "[]", f"redsim.ml.datasets imported the targets package: {proc.stdout}"
