"""Concrete targets. Importing this package registers every target into ``TARGETS``.

Registration is cheap and touches no file, blob or network: the bundled targets
read ``assets/MANIFEST.json`` lazily from ``info()`` / ``load()``, and torch, ART,
onnx and scikit-learn are imported inside methods only. ``import redsim.ml.targets``
therefore stays safe for the API process (spec section 9.1 rule 2).

Registered ids:

* ``vehicles_cnn``      bundled image CNN on ``leibnitz-lab/military_vehicles`` (demo)
* ``url_trees``         bundled URL maliciousness tree ensemble on lexical URL features (demo, tabular)
* ``cifar10_smallcnn``  CIFAR-10 small CNN, ``fixture_only`` (CI; never a demo target)
* ``endpoint_stub``     LLM / black-box endpoint, ``status="not_implemented"`` (Phase B)

``ArtifactTarget`` (uploads) is constructed per run by the worker and is not registered.
"""

from __future__ import annotations

from redsim.ml.targets import bundled as _bundled  # noqa: F401  (registers vehicles_cnn, cifar10_smallcnn)
from redsim.ml.targets import tabular as _tabular  # noqa: F401  (registers url_trees)
from redsim.ml.targets import unavailable as _unavailable  # noqa: F401  (registers endpoint_stub)
from redsim.ml.targets.artifact import ArtifactTarget
from redsim.ml.targets.base import Sample, Target
from redsim.ml.targets.bundled import BundledImageTarget
from redsim.ml.targets.registry import TARGETS, get_target, list_targets
from redsim.ml.targets.tabular import BundledTabularTarget
from redsim.ml.targets.unavailable import LLMEndpointStub

__all__ = [
    "TARGETS", "ArtifactTarget", "BundledImageTarget", "BundledTabularTarget", "LLMEndpointStub", "Sample",
    "Target", "get_target", "list_targets",
]
