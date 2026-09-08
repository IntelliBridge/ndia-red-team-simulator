"""Bundled-asset build for the adversarial-ML vertical (``redsim ml build-assets``).

Modules:

- ``manifest``: the ``MANIFEST.json`` schema (datasets, models, hashes, metrics,
  library versions) plus load / write / verify helpers.
- ``datasets``: fetchers for the HuggingFace hub (CIFAR-10 parquet, imagefolder
  layouts) and the Kaggle malicious-URLs file, with the committed CI sample as
  the no-token fallback.
- ``train_cnn``: seeded CPU training of ``SmallCNN`` on an image split.
- ``train_url_classifier``: the URL maliciousness tree ensemble on lexical
  features, with its PGD surrogate.
- ``build``: the orchestration entrypoint used by ``redsim/cli/ml.py``.

Only ``build`` and ``datasets`` touch the network, and only when invoked by the
CLI. Tests exercise the trainers and the manifest on synthetic data.
"""
