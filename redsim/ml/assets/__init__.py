"""Bundled-asset build for the adversarial-ML vertical (``redsim ml build-assets``).

Modules:

- ``manifest``: the ``MANIFEST.json`` schema (datasets, models, hashes, metrics,
  library versions) plus load / write / verify helpers. Each model entry is a
  ``redsim.ml.schema.MLModelManifest`` extended with the build record.
- ``datasets``: fetchers for the HuggingFace hub (CIFAR-10 parquet, imagefolder
  layouts) and the Kaggle malicious-URLs file, with the committed CI sample as
  the no-token fallback.
- ``train_cnn``: seeded CPU training of a catalog image architecture
  (``small_cnn`` or ``resnet18``) on an image split.
- ``train_url_classifier``: the URL maliciousness tree ensemble on lexical
  features, with its PGD surrogate.
- ``build``: the orchestration entrypoint used by ``redsim/cli/ml.py``,
  including the ``--fixture`` build of the committed CIFAR-10 test slice.

Only ``build`` and ``datasets`` touch the network, and only when invoked by the
CLI. Tests exercise the trainers and the manifest on synthetic data.

This package module stays import-light (no torch, numpy or httpx) so the CLI
parser can read the id tables below without loading the ``ml`` extra.

The model ids here are the ids the target registry (``redsim.ml.targets``)
serves: ``vehicles_cnn``, ``cifar10_smallcnn`` and ``url_trees``. Earlier
builds wrote the tabular model as ``url_classifier``; that id stays readable
(``LEGACY_MODEL_IDS``) so an existing asset tree still loads, and a rebuild
replaces the legacy entry with ``url_trees``.
"""

from __future__ import annotations

# ``--dataset`` vocabulary of ``redsim ml build-assets``.
DATASET_CHOICES: tuple[str, ...] = ("image", "tabular", "cifar10", "all")

# Dataset selection -> bundled model id (the ids registered in redsim.ml.targets).
MODEL_IDS: dict[str, str] = {
    "image": "vehicles_cnn",
    "cifar10": "cifar10_smallcnn",
    "tabular": "url_trees",
}

# Ids earlier builds wrote -> the id the registry serves today. Read on load; never written again.
LEGACY_MODEL_IDS: dict[str, str] = {"url_classifier": "url_trees"}

# Model id -> dataset selection, the vocabulary of ``--only`` (legacy spellings accepted).
ASSET_IDS: dict[str, str] = {model_id: dataset for dataset, model_id in MODEL_IDS.items()}
ASSET_IDS.update({legacy: ASSET_IDS[current] for legacy, current in LEGACY_MODEL_IDS.items()})

# ``MLModelManifest.name`` for each bundled model.
MODEL_NAMES: dict[str, str] = {
    "vehicles_cnn": "Military vehicles CNN (coarse 7-class, ground-level photographs)",
    "cifar10_smallcnn": "CIFAR-10 SmallCNN (CI fixture, never a demo target)",
    "url_trees": "URL maliciousness classifier (tree ensemble on lexical URL features)",
}

# ``--arch`` vocabulary: catalog ids of redsim.ml.targets.architectures (aliases resolve there).
ARCH_CHOICES: tuple[str, ...] = ("small_cnn", "resnet18")


def canonical_model_id(model_id: str) -> str:
    """The registry id a (possibly legacy) bundled model id stands for."""
    return LEGACY_MODEL_IDS.get(model_id, model_id)


__all__ = [
    "ARCH_CHOICES", "ASSET_IDS", "DATASET_CHOICES", "LEGACY_MODEL_IDS", "MODEL_IDS", "MODEL_NAMES",
    "canonical_model_id",
]
