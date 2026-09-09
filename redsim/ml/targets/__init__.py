"""Concrete targets. Importing this package registers every target into ``TARGETS``.

Registration is cheap and touches no file, blob or network: the bundled targets
read ``assets/MANIFEST.json`` lazily from ``info()`` / ``load()``, and torch, ART,
onnx, scikit-learn and joblib are imported inside methods only. ``import redsim.ml.targets``
therefore stays safe for the API process (spec section 9.1 rule 2; pinned by
``tests/test_api_process_has_no_ml.py`` and ``tests/ml/test_import_order.py``).

Registered ids:

* ``vehicles_cnn``        bundled image CNN on ``leibnitz-lab/military_vehicles`` (demo)
* ``url_trees``           bundled URL maliciousness tree ensemble on lexical URL features (demo, tabular)
* ``cifar10_smallcnn``    CIFAR-10 small CNN, ``fixture_only`` (CI; never a demo target)
* ``sms_tfidf_lr``        bundled TF-IDF + logistic-regression SMS spam classifier (demo, text; MODALITIES-14)
* ``assets_frcnn_mnv3``   bundled Faster R-CNN MobileNetV3 detector on the military-assets subset (demo, detection)
* ``endpoint_stub``       the LLM / black-box endpoint *domain* row, ``status="not_implemented"``: real endpoint
                          and LLM targets are per-project ``Target`` rows registered through ``POST /v1/models``
                          (``source=endpoint``), never registry entries (ENDPOINT-17, LLM-03)

``ArtifactTarget`` (uploads) is constructed per run by the worker and is not registered.
``EndpointTarget`` (``redsim.ml.targets.endpoint``) is constructed by the sandbox child from the
``target_endpoint`` request block and is not registered either.

Every loadable target's ``manifest()`` carries the ``schema.MLModelManifest`` fields (spec 5.5),
validated at load time, alongside target-specific provenance; ``MLModelManifest.model_validate``
accepts the dict as is.
"""

from __future__ import annotations

from redsim.ml.targets import bundled as _bundled  # noqa: F401  (registers vehicles_cnn, cifar10_smallcnn)
from redsim.ml.targets import detection as _detection  # noqa: F401  (registers assets_frcnn_mnv3)
from redsim.ml.targets import tabular as _tabular  # noqa: F401  (registers url_trees)
from redsim.ml.targets import text as _text  # noqa: F401  (registers sms_tfidf_lr)
from redsim.ml.targets import unavailable as _unavailable  # noqa: F401  (registers endpoint_stub)
from redsim.ml.targets.artifact import ArtifactTarget
from redsim.ml.targets.base import Sample, Target
from redsim.ml.targets.bundled import BundledImageTarget
from redsim.ml.targets.detection import BundledDetectionTarget
from redsim.ml.targets.registry import TARGETS, get_target, list_targets
from redsim.ml.targets.tabular import BundledTabularTarget
from redsim.ml.targets.text import BundledTextTarget
from redsim.ml.targets.unavailable import LLMEndpointStub

__all__ = [
    "TARGETS", "ArtifactTarget", "BundledDetectionTarget", "BundledImageTarget", "BundledTabularTarget",
    "BundledTextTarget", "LLMEndpointStub", "Sample", "Target", "get_target", "list_targets",
]
