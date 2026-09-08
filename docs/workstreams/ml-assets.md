# Workstream: ML assets: dataset fetch + bundled model training + manifest

Status: in progress (opened 2026-09-08). Branch feat/ml-assets, PR #9.

Implements `redsim ml build-assets` per spec sections 11 and 20: fetch the military-vehicle image dataset (`leibnitz-lab/military_vehicles`) and the CIFAR-10 fixture from the HuggingFace hub by pinned commit sha, the malicious-URLs dataset from Kaggle when a token is present (else the committed CI sample), train the bundled SmallCNN and the URL classifier with its PGD surrogate on CPU, and write `assets/MANIFEST.json` with dataset ids, revision hashes, splits, weight sha256s, clean metrics and library versions. Layout and schema: `assets/README.md`.

Code: `redsim/ml/targets/architectures.py` (SmallCNN), `redsim/ml/datasets/url_features.py`, `redsim/ml/assets/`, `redsim/cli/ml.py`. Tests: `tests/ml/test_url_features.py`, `tests/ml/test_assets_manifest.py`, `tests/ml/test_url_classifier_training.py` (offline, synthetic data or the committed sample).

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
