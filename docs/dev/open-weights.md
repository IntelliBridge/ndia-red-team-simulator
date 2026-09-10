# Scanning open weights from Hugging Face

redsim evaluates uploaded weights, not only running models. This page is the
recipe for taking a public checkpoint from Hugging Face, registering it through
`POST /v1/models` with `source: upload`, letting the worker validate it in the
sandbox child, and running an evasion campaign on it. Every step is the code
the deployed stack runs. Nothing here is a fixture.

## What an upload needs

An uploaded model is evaluated on a dataset redsim has built. The
binding, not the architecture, decides which public checkpoints fit:

| Bundled dataset | Built by | Public checkpoints that fit |
|---|---|---|
| `hf:leibnitz-lab/military_vehicles` (7 classes, 128 px) | `redsim ml build-assets --dataset image` | none found on the Hub |
| `hf:uoft-cs/cifar10` (10 classes, 32 px) | `redsim ml build-assets --dataset cifar10` | ResNet-18 safetensors, MLCommons ResNet-8 ONNX and many more |
| `kaggle:sid321axn/malicious-urls-dataset` | `--dataset tabular` | none: the feature extractor is redsim's own |

CIFAR-10 is a fixture-only dataset: a campaign on it carries
the fixture caveat in the report and its findings are not evidence about any
mission dataset. It is the honest public benchmark for this demonstration.
ImageNet-trained checkpoints, the bulk of the Hub, need an ImageNet-labelled
evaluation set and a class-index mapping that the tree does not have.

Formats: `onnx`, `torch_state_dict` and `safetensors_state_dict`.
Full pickles are refused before deserialisation. A state_dict needs an
`architecture_id` from the catalog (`small_cnn`, `resnet18`). Modality `image`
or `tabular`.

## The input contract

The campaign perturbs `[0, 1]` NCHW pixels at the evaluation split's
resolution, so epsilon means the same thing for every target. Public
checkpoints were trained on other contracts. Declare the contract at upload
and the loader folds it into the model boundary:

| Field | Meaning | Example |
|---|---|---|
| `input_resize` | bilinear resize before the model, 8 to 1024 px | `224` for a timm ResNet trained on upsampled CIFAR-10 |
| `input_scale` | multiply the pixels | `255` for a model that consumes raw pixel values |
| `input_mean`, `input_std` | per-channel `(x - mean) / std`, in the model's units, always together | `0.485,0.456,0.406` and `0.229,0.224,0.225` |
| `input_layout` | `NCHW` or `NHWC` (ONNX only; sniffed when absent) | `NHWC` for a graph exported from TensorFlow |

Order of application: resize, scale, mean and std, layout. The values are
recorded in the manifest as `input_preprocessing`; the loader also records
`state_dict_layout` (`redsim` or `torchvision`) and `onnx.input_layout`.
Nothing is guessed. Without a contract the model receives `[0, 1]` NCHW pixels
and the validate job records the clean accuracy that earns. Read the values
from the model card or `config.json` (`pretrained_cfg.mean`, `.std`,
`.input_size`), never from a hunch.

A Hugging Face `model.safetensors` of a ResNet names its tensors in the
torchvision layout (`conv1.weight` .. `fc.bias`). The loader maps that layout
onto the catalog's `resnet18` when every key fits one-to-one. A checkpoint of
the CIFAR variant (a 3x3 stem, no max-pool) does not fit and is refused as
`architecture_mismatch` on the worker.

## The four checkpoints

`scripts/hf_open_weights_fetch.sh` downloads them at pinned commits into
`assets/hf/` (gitignored) and writes `REVISIONS.txt` and `SHA256SUMS`.

| Repository | Licence | File | Contract declared | Expected |
|---|---|---|---|---|
| `SamAdamDay/resnet18_cifar10` | MIT | `model.safetensors` (timm, torchvision keys) | resize 224, the CIFAR-10 mean and std from its card | available, gradients |
| `FredMell/resnet18-cifar10` | Apache-2.0 | `model.safetensors` | resize 224, ImageNet mean and std from its `config.json` | available, gradients |
| `ketiswp/mlcommons-ResNet8-CIFAR10-fp32-onnx` | Apache-2.0 | `model.onnx` (`[N, 32, 32, 3]`, from TFLite) | scale 255; NHWC sniffed | available, gradients through onnx2torch |
| `edadaltocg/resnet18_cifar10` | MIT | `pytorch_model.bin` (CIFAR variant) | mean and std from its card | refused on the worker |

## Running it

```bash
# 1. the evaluation split (fetches uoft-cs/cifar10 from the Hub; behind a TLS proxy set SSL_CERT_FILE)
.venv/bin/redsim ml build-assets --dataset cifar10 --out assets --cache-dir /tmp/hf-cache --epochs 1 --max-train 2000

# 2. the checkpoints
scripts/hf_open_weights_fetch.sh assets/hf

# 3. register and scan through the real API, worker task and sandbox child (e2e harness, sqlite, eager Celery)
PYTHONPATH=. .venv/bin/python scripts/hf_open_weights_demo.py --models assets/hf --assets assets --out assets/hf/runs
```

The demo writes, per model, `register.json`, the validated `model.json`, the
campaign record, `report.md`, `report.json` and the audit chain verification
under `assets/hf/runs/<timestamp>/`, plus `summary.json`. Quote the numbers of
the run in hand and label them as one laptop's run on a fixture dataset.

Against a deployed stack the same fields go through the `/models` page
("Input contract" on the upload form) or `curl`:

```bash
curl -sS -X POST "$REDSIM_API_URL/v1/models" -H "Authorization: Bearer $TOKEN" \
  -F source=upload -F project_id=default -F name=SamAdamDay/resnet18_cifar10 \
  -F declared_format=safetensors_state_dict -F architecture_id=resnet18 -F modality=image \
  -F dataset_id=hf:uoft-cs/cifar10 -F dataset_split=test \
  -F "license_statement=MIT (model card)" \
  -F input_resize=224 -F input_mean=0.49139968,0.4821582,0.44653124 \
  -F input_std=0.24703233,0.24348505,0.26158768 \
  -F file=@assets/hf/SamAdamDay_resnet18_cifar10/model.safetensors
```

The deployed host needs the CIFAR-10 assets built under its
`REDSIM_ML_ASSETS_DIR` first. The worker reads the manifest at use, so no
restart is needed.

## What is not covered

- ImageNet-trained checkpoints (no ImageNet-labelled evaluation set, no
  class-index mapping).
- Transformers architectures (ViT, ConvNeXt) as state_dicts: not in the
  catalog. Export them to ONNX first, then upload the graph.
- Text and detection uploads answer `501 not_implemented`.
- Tabular checkpoints from the Hub: none match redsim's URL feature extractor.
