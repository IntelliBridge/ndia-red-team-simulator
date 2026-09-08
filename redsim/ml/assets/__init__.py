"""Bundled-asset build for the adversarial-ML vertical (``redsim ml build-assets``).

Modules:

- ``manifest``: the ``MANIFEST.json`` schema (datasets, models, hashes, metrics,
  library versions) plus load / write / verify helpers. Each model entry is a
  ``redsim.ml.schema.MLModelManifest`` extended with the build record.
- ``datasets``: fetchers for the HuggingFace hub (CIFAR-10 parquet, imagefolder
  layouts) and the Kaggle malicious-URLs file, with the committed CI sample as
  the no-token fallback.
- ``train_cnn``: seeded CPU training of ``SmallCNN`` on an image split.
- ``train_url_classifier``: the URL maliciousness tree ensemble on lexical
  features, with its PGD surrogate.
- ``build``: the orchestration entrypoint used by ``redsim/cli/ml.py``.

Only ``build`` and ``datasets`` touch the network, and only when invoked by the
CLI. Tests exercise the trainers and the manifest on synthetic data.

This package module stays import-light (no torch, numpy or httpx) so the CLI
parser can read the id tables below without loading the ``ml`` extra.
"""

from __future__ import annotations

# ``--dataset`` vocabulary of ``redsim ml build-assets``.
DATASET_CHOICES: tuple[str, ...] = ("image", "tabular", "cifar10", "all")

# Dataset selection -> bundled model id (plan 02 section 4: ``vehicles_cnn``, ``cifar10_smallcnn``).
MODEL_IDS: dict[str, str] = {
    "image": "vehicles_cnn",
    "cifar10": "cifar10_smallcnn",
    "tabular": "url_classifier",
}

# Model id -> dataset selection, the vocabulary of ``--only``.
ASSET_IDS: dict[str, str] = {model_id: dataset for dataset, model_id in MODEL_IDS.items()}

# ``MLModelManifest.name`` for each bundled model.
MODEL_NAMES: dict[str, str] = {
    "vehicles_cnn": "Military vehicles SmallCNN (coarse 7-class, ground-level photographs)",
    "cifar10_smallcnn": "CIFAR-10 SmallCNN (CI fixture, never a demo target)",
    "url_classifier": "URL maliciousness classifier (tree ensemble on lexical URL features)",
}

__all__ = ["ASSET_IDS", "DATASET_CHOICES", "MODEL_IDS", "MODEL_NAMES"]
