# Bundled ML assets

This directory is populated by `redsim ml build-assets` (`redsim/cli/ml.py`,
orchestration in `redsim/ml/assets/build.py`). Everything in it except this
README is generated and gitignored: dataset caches, bundled weights and
evaluation slices are fetched or trained on the build machine and, in a
deployment, seeded into the blob store under `ml/assets/` and `bundled/`
(spec section 11.5 and 20.1 step 3). Nothing here is baked into an image.

```
redsim ml build-assets [--dataset image|tabular|cifar10|all] [--epochs N] [--out assets/]
                       [--seed N] [--image-size N] [--max-train N] [--max-eval N]
                       [--image-revision REV] [--cifar10-revision REV] [--no-xgboost]
```

## Layout

```
assets/
  MANIFEST.json                       the record described below (only source of clean-accuracy numbers)
  bundled/<model_id>/weights.pt       SmallCNN state_dict (image models)
  bundled/<model_id>/model.joblib     URL classifier (or model.json when built with xgboost)
  bundled/<model_id>/surrogate.joblib PGD surrogate for the tabular model
  datasets/<dataset id>/<revision>/   bundled evaluation slices (npz for images, eval.csv for URLs)
  cache/                              raw downloads keyed by hub commit sha or Kaggle slug
```

Model ids: `vehicles_cnn` (image demo, `leibnitz-lab/military_vehicles`,
coarse 7-class task), `url_classifier` (tabular demo, Kaggle
`sid321axn/malicious-urls-dataset`), `cifar10_smallcnn` (CI fixture only,
`uoft-cs/cifar10`; `fixture_only: true`, never a demo target).

## Datasets and credentials

- HuggingFace datasets are resolved through the hub API to a commit sha and
  fetched from `resolve/<sha>/...` URLs with `httpx`; the sha is the recorded
  `revision`. CIFAR-10 comes from the `uoft-cs/cifar10` parquet files, not from
  torchvision's Toronto mirror (unreachable through the corporate proxy).
- The malicious-URLs file needs a Kaggle API token in `KAGGLE_USERNAME` and
  `KAGGLE_KEY` for the one-off build run only. Without it the build prints a
  clear message and trains on the committed CI sample
  `tests/ml/fixtures/malicious_urls_sample.csv`, marking the resulting dataset
  and model `fixture_only`. The token is never logged or written anywhere.
- URL strings are data: the feature extractor is a pure string function and
  nothing in the build fetches, resolves or renders a URL.
- Python TLS on the hackathon machines goes through an inspecting proxy; the
  build calls `truststore.inject_into_ssl()` when `truststore` is installed.

## MANIFEST.json

Schema: `redsim/ml/assets/manifest.py` (`AssetManifest`). Top level:
`schema_version`, `builder`, `built_at`, `redsim_version`, `python`, `platform`,
`library_versions`, `datasets`, `models`.

Each `datasets[<id>]` entry records `source` (huggingface, kaggle, local),
`revision` (hub commit sha, or the sha256 of `malicious_phish.csv`), `license`
and `license_note` as declared, `class_names`, the downloaded `source_files`
with sha256 and size (provenance; they live in the cache, not under the root), `splits` (name, `n`, per-class `n`, split seed, sha256 of the
source indices, the bundled slice file), `preprocessing`, `fixture_only` and
caveat `notes`.

Each `models[<id>]` entry records `modality`, `format` (torch_state_dict,
sklearn_joblib, xgboost_json), `architecture_id` and constructor arguments,
the weights `file` (path, sha256, size), `dataset_id` and `dataset_revision`,
train and eval split names, `class_names`, `seed`, `epochs`, the `training`
recipe (optimizer, learning rate, batch size, thread count, wall time, input
mean and std), measured `metrics` (`n`, `n_correct`, `clean_accuracy`,
`macro_f1`, per-class `n` and `n_correct`, loss history), the lexical
`features` with dtype, `perturbable` flag and training-split range plus the
`surrogate` block (kind, file, agreement with the ensemble) for the tabular
model, and `library_versions`.

`redsim.ml.assets.manifest.verify_files(manifest, root)` re-hashes every
bundled file (weights, surrogates, evaluation slices); a run refuses to start on a mismatch (spec 9.5, 11.3.3).
