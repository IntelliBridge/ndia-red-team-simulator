# Workstream: ML assets: dataset fetch + bundled model training + manifest

Status: merged. PR #9 `feat/ml-assets` landed on 2026-09-08 as `1725728`,
extended by wave 1 (`f8693c2`: loaders read the builder manifest, onnx2torch,
`--fixture`, `resnet18`), wave 2 (`e49f160`: dataset caveats and
`subject_centered`) and wave 3 (`39126ce`: the `resnet18` fine-tune recipe,
`3ab9de7` and `98a8733`: `redsim ml seed`). State described here is `main`
at `58461cc`.

Implements `redsim ml build-assets` per spec sections 11 and 20: fetch the
military-vehicle image dataset (`leibnitz-lab/military_vehicles`) and the
CIFAR-10 fixture from the HuggingFace hub by pinned revision, the
malicious-URLs dataset from Kaggle when a token is present (else the committed
CI sample), train the bundled image model and the URL classifier with its PGD
surrogate on CPU, and write `assets/MANIFEST.json` with dataset ids, revision
hashes, splits, weight sha256s, clean metrics with `n`, dataset caveats,
`subject_centered`, the surrogate block and library versions. Layout and
schema: `assets/README.md`. Every `models[<id>]` entry is a
`redsim.ml.schema.MLModelManifest` plus the build record (`ModelEntry`
subclasses it, `manifest_sha256` is the digest of the projection), and the
loaders in `redsim/ml/targets/` read exactly that shape (weights from
`entry.file.path`, architecture kwargs from `entry.architecture`, the
evaluation slice from `datasets[].splits[].file`, the surrogate from
`surrogate.file`).

CLI flags: `--dataset {all,vehicles,cifar10,urls}`, `--only <model_id>`,
`--arch {small_cnn,resnet18}` (default `small_cnn`), `--epochs`, `--image-size`,
`--seed`, `--out`, `--cache-dir`, `--max-train`, `--max-eval`, `--workers`,
`--xgboost` / `--no-xgboost` (the `url_trees` asset is scikit-learn
`HistGradientBoosting` by default), and `--fixture` with `--fixture-out`,
`--fixture-sidecar` and `--fixture-synthetic-ok` for the committed 500-image
CIFAR-10 slice `tests/ml/fixtures/cifar10_test_500.npz` and its sidecar of
digests and indices.

Kaggle access: `KAGGLE_API_TOKEN` from the environment or a `.env` file
(`REDSIM_ENV_FILE`, reusing `redsim.llm.pythia`'s discovery) is sent as a
bearer token, the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair stays as the
basic-auth fallback, the 302 to Google Cloud Storage is followed without the
credential, and the zip and CSV digests are recorded (`download.json` in the
cache, `archive_sha256` / `source_file_sha256` in the manifest).
`tests/ml/fixtures/malicious_urls_sample.csv` is a seeded stratified draw of
the real file (`redsim/ml/assets/fixture_sample.py`, whose sidecar carries the
source digests and row indices, `synthetic: false`).

Local build on 2026-09-09 (gitignored, illustrative figures read from that
manifest, not results): `url_trees` clean accuracy 0.9087 on `n = 128224`
with surrogate agreement 0.7891, `vehicles_cnn` as `resnet18` (the `39126ce`
recipe: ImageNet initialisation from the local torch hub cache, fine-tune lr
3e-4 cosine, random flip and reflect-pad crop augmentation, best epoch by a
per-class 10 percent validation slice held out of the training split, so the
evaluation split is never used for selection, every choice recorded in the
manifest `training` block) 0.7687 on `n = 1621` (`test_coarse`), where the earlier
`small_cnn` recipe reached 0.5151, and `cifar10_smallcnn` 0.6872, fixture only.

Serving the assets: `GET /v1/datasets` and `GET /v1/models` read the manifest
from `REDSIM_ML_ASSETS_DIR` (default `./assets`), and
`redsim.services.ml_models.register_bundled_model(session, project_id,
bundled_id, actor)` verifies weights and split digests, writes the
`model.register` audit row, copies the weights into the blob store under
`bundled/<id>/…` and creates the per-project `Target` (`<bundled_id>-<8 hex>`,
`value = bundled:<id>`, `status = available`). `redsim ml seed` (`3ab9de7`, `98a8733`) calls the same
function for every non-fixture model, audit-first and one commit per model,
reporting `already present` for a live duplicate and exiting 1 on any other
refusal. The compose
file does not mount `assets/` for the containers, see
[`docs/dev/local-stack.md`](../dev/local-stack.md).

Code: `redsim/ml/targets/architectures.py` (`SmallCNN`, `resnet18`),
`redsim/ml/datasets/url_features.py`, `redsim/ml/assets/` (`datasets`,
`manifest`, `build`, `train_cnn`, `train_url_classifier`, `fixture_sample`),
`redsim/cli/ml.py`. Tests: `tests/ml/test_url_features.py`,
`test_assets_manifest.py`, `test_assets_roundtrip.py`, `test_build_assets.py`,
`test_cifar10_fixture.py`, `test_url_classifier_training.py`,
`test_kaggle_download.py`, `test_hub_download.py`, `test_fixture_sample.py`,
`test_cli_ml.py` (offline: synthetic data, the committed sample, or an httpx
mock transport).

Open: the UNSW-NB15 tabular fallback named in spec 11 is not built or wired
(fallback datasets are excluded from this completion pass), and the spec 26.18
upload sign-off needs a named human reviewer.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
