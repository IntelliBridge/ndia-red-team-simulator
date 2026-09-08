> **SUPERSEDED / RECONCILED (2026-09-08 spec update).** This file was written for v1 against the deleted `redsim/` package. It now maps to: **Milestones M1/M4/M5b**; feature **F002 Evaluation Catalog**.
>
> Substrate corrections (see `00-master-plan.md` §2 and the canonical spec): targets under `aegis/ml/targets/`; assets seeded by the `aegis ml build-assets` CLI into S3 (`ml/assets/`, `bundled/`), not baked ad-hoc; demo data is `leibnitz-lab/military_vehicles` + `lacg030175/UNSW-NB15` — **CIFAR-10 is a CI fixture only**; upload is admin-gated, ONNX/state_dict only, loaded in the sandboxed worker.
>
> Use this file for the parallel-execution shape only, not the literal paths, signatures, or mechanisms below.

# P1 — Targets & assets (CIFAR-10 image + tabular)

Owner: Dev A. Wave: 1 (parallel). Depends on: P0 contracts. Feeds: P2, P3, P4.

Read `docs/plans/00-master-plan.md` section 6 first. Its contracts are
canonical. This plan builds against `redsim/targets/base.py` and
`redsim/schema.py`, which already exist, so work can start at once.

---

## 1. Objective

Ship the target layer: the concrete models the simulator evaluates, the
offline asset builder that produces the image model, and the registry that
lists every target for the API.

Deliverables:

- A real CIFAR-10 image target that satisfies the full `Target` Protocol and
  reports `status == "available"`.
- An offline `setup_assets.py` that trains the small CNN once, records its
  provenance, and writes `assets/cifar10_smallcnn.pt` and
  `assets/MANIFEST.json`. Weights ship as an asset. They are never trained at
  container start.
- A real tabular target on a public benign dataset, wrapped for ART.
- An LLM stub target that stays honest: `status == "not_implemented"` with a
  reason, and `load()` raises `NotImplementedError`.
- The `TARGETS` registry, populated at import.

The image path is the demo spine. Build it first.

---

## 2. Scope

### In scope

- `redsim/setup_assets.py` — CIFAR-10 download, CNN training, manifest write.
- `redsim/targets/image_cifar10.py` — the live image target.
- `redsim/targets/tabular_*.py` — a real tabular target (see step order for the
  chosen dataset and model).
- `redsim/targets/llm_stub.py` — the not-implemented LLM target.
- `redsim/targets/registry.py` — `TARGETS`, a `Registry[Target]`.
- Unit tests for the registry, the image target, and the tabular target.

### Out of scope

- Attacks and MRI scoring (P2).
- SHAP, interpretation, recommendations (P3). P1 only exposes `torch_model()`
  and `art_classifier()` so P3 can attach.
- Orchestration, `runs.py`, `jobs.py`, HTTP routes (P4). P1 does not touch the
  API.
- ONNX ingest as a target (P6).
- Any change to `redsim/schema.py` or `redsim/targets/base.py`. Those are P0
  contracts. If a field is missing, raise it in master-plan section 6.1 first.

---

## 3. Prerequisites & dependencies

- **From P0 (already present):** the `Target` Protocol and `Sample` dataclass
  in `redsim/targets/base.py`; `TargetInfo` and `Provenance` in
  `redsim/schema.py`; `Registry` in `redsim/registry.py`. All exist today, so
  P1 starts immediately with no wait on P0.
- **Runtime libraries** (already declared in `pyproject.toml`, design spec
  2.1): `torch` (CPU), `torchvision`, `numpy`,
  `adversarial-robustness-toolbox`, and for the tabular target either
  `scikit-learn` or `torch`. Confirm `scikit-learn` is on the dependency list
  before choosing the sklearn route; if it is absent, use a torch MLP so no new
  dependency is added.
- **Asset directory:** `assets/`. The design spec (section 6) gitignores it
  except the manifest. Confirm `.gitignore` keeps `assets/cifar10_smallcnn.pt`
  out of git and keeps `assets/MANIFEST.json` in.
- **Network:** `setup_assets.py` needs internet once to download CIFAR-10. The
  targets themselves load from disk and run fully offline, which the test suite
  requires (design spec section 7: all tests offline, < 60 s).

No dependency on P2, P3, P4, P5, P6, or P7.

---

## 4. Interfaces consumed & exposed

### Consumed (do not modify)

`Sample` (dataclass, `redsim/targets/base.py`):

- `x: np.ndarray` — float32 in [0, 1], NCHW for images.
- `y: np.ndarray` — int labels, shape `(n,)`.
- `indices: np.ndarray` — index into the source split, for reproducibility.
- `class_names: list[str]`.

`TargetInfo` (`redsim/schema.py`): `id`, `name`, `domain`
(`"image" | "tabular" | "llm"`), `status` (`"available" | "not_implemented"`),
`reason: str | None`, `metadata: dict[str, Any]`.

`Provenance` (`redsim/schema.py`): P1 does not build a `Provenance` (P4 does),
but the manifest supplies the values P4 later copies into it: `torch`,
`model_sha256`, `dataset`, `dataset_split`, `model_manifest`, and the seeds
that go into `nondeterminism`.

### Exposed

`TARGETS: Registry[Target]` from `redsim/targets/registry.py`, populated at
import with every target. Consumers use `.get(id)`, `.maybe_get(id)`, `.ids()`,
`.items()`, iteration, and `in`. Never `.list()` — that method does not exist.

Every registered target implements the full `Target` Protocol exactly:

| Member | Signature | P1 obligation |
|---|---|---|
| `id` | `str` attribute | Unique, stable. `cifar10_smallcnn`, a tabular id, `llm_pythia`. |
| `info()` | `-> TargetInfo` | Live targets report `status="available"`; the stub reports `"not_implemented"` with a `reason`. `metadata` carries dataset name, split, and clean accuracy from the manifest. |
| `load()` | `-> None` | Idempotent. Loads weights and the eval split from disk. The stub raises `NotImplementedError`. |
| `sample(n, seed)` | `-> Sample` | Stratified by class, seeded, reproducible. |
| `predict_proba(x)` | `-> np.ndarray` | Shape `(n, n_classes)`, rows sum to 1. |
| `art_classifier()` | `-> Any` | ART estimator wrapping the model. Reports input range and `nb_classes` to ART (see below). |
| `torch_model()` | `-> Any` | The `torch.nn.Module` in eval mode for SHAP. The tabular sklearn target may raise `NotImplementedError`; coordinate with P3 (tabular SHAP uses `KernelExplainer`, not a gradient explainer). |
| `manifest()` | `-> dict[str, Any]` | Dataset and weights provenance: names, versions, sha256, training config. Read from `assets/MANIFEST.json` for the image target. |

**ART wiring convention (image target):** wrap the CNN in ART's
`PyTorchClassifier` with `clip_values=(0.0, 1.0)` (the [0, 1] input range),
`nb_classes=10`, `input_shape=(3, 32, 32)`, the model's loss, and no ART
preprocessing normalization. The classifier receives x already float32 in
[0, 1], NCHW, matching `Sample.x`. Any per-channel normalization the CNN needs
lives inside the `nn.Module` (a first normalization layer), so ART and SHAP
both see the raw [0, 1] tensor and the L-infinity budget is measured in that
same space. This keeps the perturbation budget that P2 applies consistent with
the range ART clips to.

**ART wiring convention (tabular target):** wrap with `SklearnClassifier` for a
sklearn model, or `PyTorchClassifier` for a torch MLP. Set `clip_values` to the
observed feature min/max of the training data (record these in the manifest),
and set `nb_classes` to the label count. Tabular x is float32, shape
`(n, n_features)`, not NCHW.

---

## 5. Ordered implementation steps

1. **CNN architecture.** Define `SmallCNN(nn.Module)` in a shared spot both
   `setup_assets.py` and `image_cifar10.py` import (put it in
   `image_cifar10.py` and import it into the builder). Two conv blocks
   (`Conv2d -> ReLU -> MaxPool2d`, e.g. 3->32 then 32->64) then two FC layers
   to 10 logits. Put the CIFAR channel normalization as the first step inside
   `forward` (register mean/std as buffers) so the module accepts x in [0, 1]
   NCHW and every consumer sees the same input contract.

2. **`setup_assets.py` — download.** Use `torchvision.datasets.CIFAR10` to pull
   the train split (for training) and the test split (the eval slice). Set
   every seed before any randomness: `torch.manual_seed`, `numpy`, and Python
   `random`; set `torch.use_deterministic_algorithms(True)` where feasible and
   record any residual nondeterminism source in the manifest.

3. **`setup_assets.py` — train.** Train `SmallCNN` on the train split for a
   fixed epoch count with a fixed seed. Target clean test accuracy 65-75 %
   (design spec 2.2). Keep it small: a handful of epochs on CPU is enough at
   this accuracy band. Evaluate on the full test split and record the achieved
   clean accuracy. Never hard-code the accuracy in docs; the manifest holds the
   real number.

4. **`setup_assets.py` — write assets.** Save weights to
   `assets/cifar10_smallcnn.pt` (`state_dict` only, not the pickled module).
   Compute the sha256 of the written weight bytes. Write `assets/MANIFEST.json`
   with: dataset name (`CIFAR-10`), dataset version/source, split
   (`test` for eval, `train` for training), model arch label, epochs, seed(s),
   achieved clean test accuracy, `torch.__version__`, and the weight sha256.
   Make the script idempotent and re-runnable, and print the manifest summary
   at the end. Add a `--force` flag to retrain over existing assets.

5. **`image_cifar10.py` — load.** Implement `load()` to read the test split
   from a local torchvision cache (offline), build `SmallCNN`, load the
   `state_dict` from `assets/cifar10_smallcnn.pt`, and set the module to
   `eval()`. Idempotent: a second call is a no-op. Cache the test tensors and
   labels as float32 [0, 1] NCHW and int labels.

6. **`image_cifar10.py` — sample.** Implement `sample(n, seed)` to draw a
   stratified slice: split `n` across the 10 classes as evenly as possible,
   pick per-class indices with a seeded `numpy.random.default_rng(seed)`, and
   return a `Sample` with `x` float32 [0, 1] NCHW, int `y`, the source
   `indices`, and `class_names` in CIFAR label order. Same `(n, seed)` must
   return identical `indices` every call.

7. **`image_cifar10.py` — predict & wrappers.** Implement `predict_proba(x)`
   (softmax over logits, shape `(n, 10)`), `art_classifier()` (the
   `PyTorchClassifier` per the convention above, built once and cached),
   `torch_model()` (the module in eval mode), `info()` (status `"available"`,
   metadata from the manifest: dataset, split, clean accuracy), and
   `manifest()` (parsed `assets/MANIFEST.json`).

8. **`tabular_*.py` — build the target.** Pick a small public benign dataset
   (e.g. scikit-learn's bundled `load_breast_cancer` or `load_wine`, which ship
   with the library and need no download, keeping the target offline). Train a
   small model at import-safe cost, or ship a tiny pre-fit artifact the same way
   as the CNN. Prefer sklearn (`LogisticRegression` or a small
   `MLPClassifier`) wrapped in ART `SklearnClassifier`; if `scikit-learn` is
   not a dependency, use a torch MLP wrapped in `PyTorchClassifier`. Record the
   dataset name, feature count, class count, and feature min/max in a manifest
   dict returned by `manifest()`.

9. **`tabular_*.py` — Protocol.** Implement `info()` (status `"available"`,
   domain `"tabular"`), `load()`, `sample(n, seed)` (stratified, seeded, x
   shape `(n, n_features)`), `predict_proba(x)`, `art_classifier()`, and
   `manifest()`. `torch_model()` may raise `NotImplementedError` for the
   sklearn route; leave a comment that P3 uses `KernelExplainer` for tabular
   SHAP so a torch module is not required.

10. **`llm_stub.py`.** A registered target with a stable `id` (e.g.
    `llm_pythia`), `domain == "llm"`, `info().status == "not_implemented"`, and
    a `reason` naming the Pythia connection shape (design spec 2.1). `load()`
    raises `NotImplementedError`. `sample`, `predict_proba`, `art_classifier`,
    `torch_model`, and `manifest` may raise `NotImplementedError`; the API
    never calls them because the run is rejected with 501 upstream.

11. **`registry.py`.** Create `TARGETS = Registry[Target]("target", Target)`
    and register the image, tabular, and LLM-stub instances at module import.
    The Protocol check in `Registry.register` enforces conformance at import,
    so a target that misses a method fails loudly at load, not mid-run. Confirm
    `Target` is a `runtime_checkable` Protocol (it is) so the isinstance check
    holds.

12. **Wire imports.** Make `redsim/targets/__init__.py` (or the registry
    module) import each target module so registration runs when `TARGETS` is
    imported. Keep import side effects cheap: register lightweight instances
    and defer weight loading to `load()`, so importing the registry does not
    read `assets/` or the dataset.

---

## 6. Files to create or modify

Create:

- `redsim/setup_assets.py`
- `redsim/targets/image_cifar10.py`
- `redsim/targets/tabular_sklearn.py` (name reflects the chosen route; use
  `tabular_torch.py` if the torch MLP route is taken)
- `redsim/targets/llm_stub.py`
- `redsim/targets/registry.py`
- `assets/MANIFEST.json` (generated by `setup_assets.py`)
- `assets/cifar10_smallcnn.pt` (generated; gitignored)
- `tests/test_targets.py`

Modify:

- `redsim/targets/__init__.py` — import target modules so registration fires.
- `.gitignore` — confirm it excludes `assets/cifar10_smallcnn.pt` and any
  torchvision download cache, and keeps `assets/MANIFEST.json`.

Do not modify: `redsim/targets/base.py`, `redsim/schema.py`,
`redsim/registry.py`.

---

## 7. Testing & validation

`tests/test_targets.py`, all offline, fast (design spec section 7). The test
run assumes `assets/cifar10_smallcnn.pt` and the CIFAR test cache exist; gate
the image tests behind a skip if the asset is missing so CI without the asset
still passes, and document that the asset must be built once with
`python -m redsim.setup_assets`.

1. **Registry lists targets.** `TARGETS.ids()` contains the image, tabular,
   and LLM-stub ids. `TARGETS.get(id)` returns each. Each item satisfies the
   `Target` Protocol (the registry already enforced this at import; assert
   `isinstance(t, Target)`).

2. **Stub is honest.** The LLM target's `info().status == "not_implemented"`,
   its `reason` is a non-empty string, and `load()` raises
   `NotImplementedError`.

3. **Image target loads and predicts a batch.** `load()` is idempotent (call
   twice). `sample(20, seed=0)` returns a `Sample` with `x.dtype == float32`,
   `x` in [0, 1], shape `(20, 3, 32, 32)`, `y` length 20, `indices` length 20,
   and `class_names` length 10. `predict_proba(sample.x)` has shape `(20, 10)`
   and rows sum to ~1.

4. **Sample is stratified, seeded, reproducible.** `sample(20, 0).indices`
   equals a second `sample(20, 0).indices` exactly. The class histogram of
   `sample(50, 0).y` is even across the 10 classes (each class within one of
   `50 // 10`). A different seed yields different `indices`.

5. **ART classifier reports the right contract.** The image
   `art_classifier()` returns an object whose `nb_classes == 10` and whose
   `clip_values == (0.0, 1.0)`; `input_shape == (3, 32, 32)`. It predicts on
   `sample.x` without error and returns shape `(n, 10)`.

6. **Tabular target predicts.** `load()`, `sample(n, seed)` returns x shape
   `(n, n_features)`, `predict_proba` returns `(n, n_classes)` summing to ~1,
   `sample` is seeded and reproducible, and `art_classifier()` predicts a batch.

7. **Manifest round-trip.** `image_target.manifest()` parses and contains
   dataset, split, seed, epochs, clean accuracy, torch version, and the weight
   sha256; the sha256 matches the bytes of `assets/cifar10_smallcnn.pt`.

Run `make test` and `make typecheck`; both must stay green. Do not rely on
`lint-py`, which has known pre-existing findings (see CLAUDE.md).

---

## 8. Acceptance criteria / Definition of done

- `python -m redsim.setup_assets` runs offline-after-download, trains the CNN
  to a recorded clean test accuracy in the 65-75 % band, and writes
  `assets/cifar10_smallcnn.pt` plus `assets/MANIFEST.json` with every required
  field (dataset name/version, split, arch, epochs, seed, clean accuracy, torch
  version, weight sha256).
- `from redsim.targets.registry import TARGETS` returns a `Registry[Target]`
  with the image target (`status="available"`), the tabular target
  (`status="available"`), and the LLM stub (`status="not_implemented"` with a
  reason).
- The image target implements every `Target` Protocol member. `sample` is
  stratified, seeded, and reproducible. `x` is float32 in [0, 1], NCHW.
  `art_classifier()` reports `clip_values=(0.0, 1.0)`, `nb_classes=10`,
  `input_shape=(3, 32, 32)`. `torch_model()` returns the module in `eval()`.
- The tabular target predicts and wraps for ART; `torch_model()` either returns
  a module or raises `NotImplementedError` with a note pointing P3 at
  `KernelExplainer`.
- The LLM stub's `load()` raises `NotImplementedError`; nothing is faked.
- Seeds used for training and sampling are recorded in the manifest so P4 can
  copy them into `Provenance.model_manifest` and `Provenance.nondeterminism`.
- `tests/test_targets.py` passes; `make test` and `make typecheck` stay green.

---

## 9. Effort estimate & special considerations

**Effort:** ~1.5 to 2 developer-days. The image target and `setup_assets.py`
are the bulk; the tabular target and stub are half a day together.

**Offline training time.** The small CNN at 65-75 % accuracy needs only a few
epochs. On a laptop CPU this is minutes, not hours. Keep the epoch count in the
manifest so the number is auditable. This runs once; the weights ship as an
asset. Never train at container start (master-plan risk 9, design spec 2.1).

**Asset size.** A 2-conv + 2-FC state_dict is small (well under ~5 MB). It is
safe to bake into the container image rather than fetch from S3, which removes
an S3 round-trip from cold start. The CIFAR test split the target loads is
~30 MB; bake the needed test tensors (or the torchvision cache) into the image
too so the target loads fully offline. If image bloat becomes a problem later,
move `assets/` to S3 and pull on first boot behind `REDSIM_S3_BUCKET`
(master-plan section 6.8), but the baked-in path is the default and keeps the
demo self-contained.

**Where assets live for ECS.** Default: baked into `deploy/Dockerfile.api` at
build time under `assets/`, read-only at runtime. This matches the "bake
trained CNN weights as an asset" mitigation in master-plan risk 9. The run
output directory (`REDSIM_OUTPUT_DIR`, an EFS mount) is separate and writable;
`assets/` is not written at runtime. Coordinate with P7 so the Dockerfile
copies `assets/` and the build either runs `setup_assets.py` or restores a
committed/cached weight file. Do not run training in the image build if it slows
CI past the layer-cache budget; prefer committing the weight artifact or caching
it in GHA.

**Reproducibility.** Record every seed (training seed, sampling is caller-seeded
per call) in the manifest. Note residual nondeterminism (for example CPU
float32 reductions) so P4 can list it in `Provenance.nondeterminism`. Same
`(n, seed)` into `sample()` must return identical `indices`, which the tests
enforce.

**Normalization convention (restated, load-bearing).** x is float32 in [0, 1],
NCHW. Channel normalization lives inside the `nn.Module`, so ART's
`clip_values=(0.0, 1.0)` and the L-infinity budget P2 applies are both measured
in the [0, 1] space, and SHAP sees the same raw tensor. Do not normalize in
`sample()` or before ART; keep one input contract end to end.

**Coordination seams.** P2 consumes `art_classifier()` and `sample()`; P3
consumes `torch_model()` (image) and calls `predict_proba` through
`KernelExplainer` (tabular). Keep the tabular `torch_model()` behavior explicit
so P3 knows which SHAP explainer to pick. Flag any needed schema field in
master-plan section 6.1 before adding it; do not edit `schema.py` or `base.py`
in this phase.
