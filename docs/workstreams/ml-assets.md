# Workstream: ML assets: dataset fetch + bundled model training + manifest

Status: in progress (opened 2026-09-08). Branch feat/ml-assets, PR #9.

Implements `redsim ml build-assets` per spec sections 11 and 20: fetch the military-vehicle image dataset (`leibnitz-lab/military_vehicles`) and the CIFAR-10 fixture from the HuggingFace hub by pinned commit sha, the malicious-URLs dataset from Kaggle when a token is present (else the committed CI sample), train the bundled SmallCNN and the URL classifier with its PGD surrogate on CPU, and write `assets/MANIFEST.json` with dataset ids, revision hashes, splits, weight sha256s, clean metrics and library versions. Layout and schema: `assets/README.md`.

Adapted to the P0 / M0 contract (main `4350d38`): the CLI exposes P0's `add_ml_subparser`, `cmd_ml` and `cmd_ml_build_assets` with `BUILD_ASSETS_STATUS = "implemented"`, and every `models[<id>]` entry in `assets/MANIFEST.json` is a `redsim.ml.schema.MLModelManifest` plus the build record (`ModelEntry` subclasses it; `manifest_sha256` is the digest of the projection).

Kaggle access (2026-09-08 evening): `KAGGLE_API_TOKEN` from the environment or a `.env` file (`REDSIM_ENV_FILE`, reusing `redsim.llm.pythia`'s discovery) is sent as a bearer token, the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair stays as the basic-auth fallback, the 302 to Google Cloud Storage is followed without the credential, and the zip and CSV digests are recorded (`download.json` in the cache, `archive_sha256` / `source_file_sha256` in the manifest). `tests/ml/fixtures/malicious_urls_sample.csv` is now a seeded stratified draw of the real file (`redsim/ml/assets/fixture_sample.py`; sidecar carries the source digests and row indices, `synthetic: false`).

Code: `redsim/ml/targets/architectures.py` (SmallCNN), `redsim/ml/datasets/url_features.py`, `redsim/ml/assets/` (`datasets`, `manifest`, `build`, `train_cnn`, `train_url_classifier`, `fixture_sample`), `redsim/cli/ml.py`. Tests: `tests/ml/test_url_features.py`, `tests/ml/test_assets_manifest.py`, `tests/ml/test_url_classifier_training.py`, `tests/ml/test_kaggle_download.py`, `tests/ml/test_fixture_sample.py`, `tests/ml/test_cli_ml.py` (offline: synthetic data, the committed sample, or an httpx mock transport).

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
