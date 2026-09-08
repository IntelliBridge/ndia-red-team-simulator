> **Phase P1 · Milestones M1/M4/M5b · Feature F002 (v2, aegis substrate)**
>
> This plan is rebased on the aegis platform. It replaces the v1 body, which
> was written against the deleted `redsim/` package. Read `docs/plans/00-master-plan.md`
> (sections 2, 5, 7) and the canonical spec
> `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md` (sections 5,
> 9, 11, 12.2) first. Where this plan and those disagree, they win.
>
> Substrate in one line: targets live under `aegis/ml/targets/`; assets are
> seeded by the `aegis ml build-assets` CLI into the blob store under
> `ml/assets/` and `bundled/`; the demo data is `leibnitz-lab/military_vehicles`
> (image) and `lacg030175/UNSW-NB15` (tabular); CIFAR-10 is a CI fixture only;
> uploads are admin-gated, ONNX or `state_dict` only, and loaded only in the
> sandboxed worker.

# P1 — Targets and assets (Evaluation Catalog)

Owner: Dev A (WS1). Wave: Slice 1 (foundation). Depends on: WS0 (M0 scaffold and
migration `0010_ml_vertical`). Feeds: WS2 (attacks), WS3 (explain), WS4 (API and
campaign service).

---

## 1. Objective

Ship the target layer and the catalog surface: the concrete models a campaign
evaluates, the offline asset builder that produces them, the registry that lists
them, and the admin-gated upload path that admits a caller's own model without
ever loading it in the API.

Deliverables:

- A live **image** target on `leibnitz-lab/military_vehicles` (7-class coarse
  task): a small CNN shipped as a `state_dict` plus an in-tree architecture, and
  exported to ONNX. `info().status == "available"`.
- A live **tabular** target on `lacg030175/UNSW-NB15` (config `standard`, binary
  `label` task): a bundled RandomForest or XGBoost tree ensemble with a
  build-time differentiable **PGD surrogate**, wrapped for ART. `status ==
  "available"`.
- A **CIFAR-10** small CNN target kept for CI and fixtures only. It never appears
  in the demo catalog and never populates a `Finding`.
- An **endpoint / LLM** stub target: `status == "not_implemented"` with a reason;
  `load()` raises `NotImplementedError`.
- The `TARGETS` registry under `aegis/ml`, populated at import.
- The `aegis ml build-assets` CLI: fetch each dataset by pinned HuggingFace
  revision, train and export the bundled models with a fixed seed, write each
  model plus `MANIFEST.json` plus the evaluation-slice to the blob store, and
  register a `Target` row of kind `ml_model_artifact`.
- The `POST /v1/models` upload path with the sandboxed `model.validate` job:
  ONNX preferred, PyTorch `state_dict` with a declared architecture accepted,
  full pickles refused, and every model loaded only in the child subprocess.

The image path is the demo spine (D8 step 1). Build it first. The tabular path is
D8 step 4; ONNX upload is D8 step 5.

---

## 2. Scope

### In scope

- `aegis/ml/targets/architectures.py` — the in-tree architecture catalog.
- `aegis/ml/targets/image_vehicles.py` — the live vehicle-imagery CNN target.
- `aegis/ml/targets/tabular_unsw.py` — the live UNSW-NB15 tree-ensemble target.
- `aegis/ml/targets/image_cifar10.py` — the CIFAR-10 CNN, CI fixture only.
- `aegis/ml/targets/endpoint.py` — the `not_implemented` endpoint / LLM stub.
- `aegis/ml/targets/registry.py` — `TARGETS`, a `Registry[Target]`.
- `aegis/ml/loaders.py` — file-signature format detection, worker-side only.
- `aegis/ml/sandbox.py` and `aegis/ml/sandbox_worker.py` — the ML model sandbox
  and its `validate` stage.
- `aegis/cli/ml.py` — the `build-assets` subcommand (registered in
  `aegis/cli/main.py`).
- `aegis/services/ml_models.py` — the model admission service (register bundled,
  admit upload, enqueue `model.validate`).
- `aegis/api/v1/models.py` — `POST /v1/models`, `DELETE /v1/models/{id}`,
  `GET /v1/models`, mounted on `aegis/api/app.py`.
- `MLModelManifest` in `aegis/ml/schema.py` (the typed `targets.detail` payload).
- Tests under `tests/ml/`.

### Out of scope

- Attacks, the ε sweep, MRI scoring (WS2). P1 exposes `art_classifier()` and
  `sample()` so WS2 can attach.
- SHAP, interpretation, recommendations (WS3). P1 exposes `torch_model()`.
- The campaign chain, `attack.run`, run-state writes, the campaign service (WS4).
  P1 admits models and runs `model.validate` only.
- The web `/models` list and detail launcher. That is P5 (WS5); P1 stops at the
  API.
- Black-box endpoint execution against `ml_model_endpoint` (Phase B).
- Dataset upload or export. Phase A has no dataset upload path (section 11.1).
- The migration `0010_ml_vertical` itself and the `ml` dependency group. Those
  are WS0 (M0). If `targets.detail` or a schema field is missing, raise it with
  WS0, do not add it here.

---

## 3. Prerequisites and dependencies

**From WS0 / M0 (must land first):**

- Migration `0010_ml_vertical` adds `targets.detail` (JSONB) and the
  `ml_campaigns` table. P1 writes only `targets.detail`.
- API-side validation of the two new `Target.kind` values, `ml_model_artifact`
  and `ml_model_endpoint` (`Target.kind` is a free `String(32)`, so no column
  change; section 5.1).
- The `ml` dependency group: `torch` (CPU), `torchvision`,
  `adversarial-robustness-toolbox`, `shap`, `numpy`, `scikit-learn`, `xgboost`,
  `onnx`, `onnxruntime`, `onnx2torch`, `safetensors`, `datasets`,
  `huggingface_hub`. The API process imports none of them (section 9.1 rule 2).
- The `aegis ml` CLI skeleton (`aegis/cli/ml.py` registered in
  `aegis/cli/main.py`).

**Already present in aegis (consume, do not modify):**

- The `Target` Protocol and `Sample` dataclass in `aegis/ml/targets/base.py`.
- `TargetInfo`, `Domain`, `Provenance` in `aegis/ml/schema.py`.
- `Registry[T]` in `aegis/registry.py` (duplicate-id detection).
- `BlobStore` in `aegis/storage/blobs.py` (`put`/`get`; `AEGIS_BLOB_BACKEND=s3`
  for MinIO/S3; content-addressed, so a second put of identical bytes is a
  no-op).
- The sandbox primitives in `aegis/scanners/sandbox.py` (rlimits, process group,
  minimal env, wall-clock kill). The ML sandbox reuses these conventions.
- The audit chain (`aegis/audit/chain.py`, `resolve_writer`) and
  `aegis.safety.authorize` (the only audit emitter).
- The admin-gated target surface (`aegis/api/v1/targets.py`,
  `aegis/services/targets.py`, `aegis/api/policy.py`).
- `tests/ml/fakes.py::TinyTarget` (a full `Target` on 8x8x3, 3 classes, no
  network, no assets).

**Network.** `build-assets` needs internet once, at build time, to fetch each
dataset by pinned revision. The targets themselves and the whole test suite run
offline (section 22).

---

## 4. Interfaces consumed and exposed

### Consumed (do not modify)

`Sample` (dataclass, `aegis/ml/targets/base.py`):

- `x: np.ndarray` — float32 in [0, 1], NCHW for images; `(n, n_features)` for
  tabular.
- `y: np.ndarray` — int labels, shape `(n,)`.
- `indices: np.ndarray` — index into the source split, for reproducibility.
- `class_names: list[str]`.

`TargetInfo` (`aegis/ml/schema.py`): `id`, `name`, `domain` (the `Domain`
literal `image | tabular | llm`), `status` (`available | not_implemented`),
`metadata: dict`. `Provenance` is built by WS4 from the manifest, not by P1.

### Exposed

`TARGETS: Registry[Target]` from `aegis/ml/targets/registry.py`, populated at
import with every target. Consumers use `.get(id)`, `.ids()`, iteration, and the
methods `aegis/registry.py` exposes. Registration runs the `Registry` conformance
check at import, so a target that misses a member fails loudly at load, not
mid-campaign.

Every registered target implements the full `Target` Protocol:

| Member | P1 obligation |
|---|---|
| `id` (`str`) | Unique, stable. `vehicles_cnn`, `unsw_trees`, `cifar10_smallcnn`, `endpoint_stub`. |
| `info() -> TargetInfo` | Live targets report `status="available"`; the stub reports `"not_implemented"` with a reason. `metadata` carries dataset id, split, and clean accuracy read from the manifest. |
| `load() -> None` | Idempotent. Reads weights and the evaluation split from the blob store. The stub raises `NotImplementedError`. |
| `sample(n, seed) -> Sample` | Stratified by class, seeded, reproducible: equal per-class allocation, remainder redistributed when a class is exhausted (section 11.5). Same `(n, seed)` returns identical `indices`. |
| `predict_proba(x) -> np.ndarray` | Shape `(n, n_classes)`, rows sum to 1. |
| `art_classifier() -> Any` | The ART estimator wrapping the model (below). Built once and cached. |
| `torch_model() -> Any` | The `torch.nn.Module` in eval mode, for SHAP. The tree target raises `NotImplementedError` (WS3 uses `TreeExplainer`, not a gradient explainer). |
| `manifest() -> dict` | Dataset and weights provenance parsed from the asset `MANIFEST.json`. |

**ART wiring (image target).** Wrap the CNN in `PyTorchClassifier` with
`clip_values=(0.0, 1.0)`, `nb_classes=7`, `input_shape=(3, 128, 128)`, the
model's loss, no ART preprocessing. Channel normalisation lives inside the
`nn.Module`, so ART and SHAP both see the raw [0, 1] tensor and the L∞ budget is
measured in that space (section 11.3.1 preprocessing rule).

**ART wiring (tabular target).** Wrap the tree ensemble in ART's
`XGBoostClassifier` or `SklearnClassifier` over `predict` for HopSkipJump (no
gradients). PGD runs against the build-time surrogate
(`ScikitlearnLogisticRegression` or a small torch MLP in `PyTorchClassifier`) and
is scored on the real model (section 12.2). ε is per-feature-scaled from the
training-split range recorded in the manifest (section 12.9). Perturbable
features are declared in the manifest; categorical columns and the label are
frozen.

`MLModelManifest` (the typed `targets.detail` payload for `ml_model_*` kinds,
section 5.5). P1 defines it in `aegis/ml/schema.py` and writes it at
registration. Fields include `name`, `modality`, `format`
(`onnx | torch_state_dict | safetensors_state_dict | sklearn_joblib |
xgboost_json | endpoint`), `sha256`, `size_bytes`, `architecture_id`,
`input_shape`, `n_classes`, `class_names`, `features` (tabular), `surrogate`
(tabular trees), `dataset_id`, `dataset_revision`, `dataset_split`,
`clean_accuracy`, `status` (`registered | validating | available | refused`),
`refusal_reason`, `gradients`, `bundled`, `license`, `source_url`, and
`manifest_sha256`. Reads stay lenient the way `AegisFinding.from_dict` is;
validation happens at write time.

---

## 5. Ordered implementation steps

1. **Architecture catalog.** Define the in-tree architectures in
   `aegis/ml/targets/architectures.py`, keyed by `architecture_id`: the vehicle
   CNN and the CIFAR-10 small CNN as named `nn.Module` classes. Free-form
   uploaded code is never accepted; a `state_dict` upload names one of these ids
   (section 9.2). Put the channel normalisation as the first step inside
   `forward` (mean/std as buffers) so every consumer sees x in [0, 1] NCHW.

2. **`MLModelManifest`.** Add the model manifest and (with WS0) the
   `Provenance.dataset_revision` field to `aegis/ml/schema.py`. This is the
   contract `build-assets` writes and every consumer reads.

3. **Image target — build path.** In `aegis/cli/ml.py`, fetch
   `leibnitz-lab/military_vehicles` at a pinned revision with
   `snapshot_download(..., repo_type="dataset", revision=<sha>,
   allow_patterns=["train_coarse/*", "test_coarse/*"])`, then
   `datasets.load_dataset("imagefolder", ...)`. Set every seed before any
   randomness. Preprocess per section 11.3.1: resize the shorter side to 128 and
   center-crop square, float32 [0, 1], NCHW, no external normalisation. Train the
   catalog CNN on `train_coarse` to a recorded clean accuracy (measured, never
   documented as a fixed number), evaluate on the full `test_coarse` split,
   export the `state_dict` and the ONNX graph, and bundle the `test_coarse`
   evaluation slice.

4. **Image target — runtime.** In `aegis/ml/targets/image_vehicles.py`,
   implement `load()` (fetch `state_dict` and the evaluation slice from the blob
   store, build the catalog CNN, `eval()`, idempotent), `sample(n, seed)`
   (stratified, seeded, reproducible), `predict_proba`, `art_classifier` (the
   `PyTorchClassifier` above), `torch_model`, `info`, and `manifest`.

5. **Tabular target — build path.** In `aegis/cli/ml.py`, load
   `lacg030175/UNSW-NB15` config `standard` at a pinned revision. Fit the
   categorical encoder (`proto`, `service`, `state`) on the train split, record
   its vocabularies. Train the RandomForest or XGBoost on the train split for the
   binary `label` task. Fit the **PGD surrogate** on the train split to the
   bundled model's predicted labels, record its kind, sha256, and clean-slice
   agreement rate. Bundle the full `standard` test split as the evaluation split,
   the encoder, the per-feature min/max, and the declared perturbable features.

6. **Tabular target — runtime.** In `aegis/ml/targets/tabular_unsw.py`,
   implement `load()`, `sample`, `predict_proba`, `art_classifier` (tree wrapper
   for HopSkipJump; surrogate exposed for WS2's PGD), `info`, and `manifest`.
   `torch_model()` raises `NotImplementedError` with a note that WS3 uses
   `TreeExplainer` on the real model.

7. **CIFAR-10 target (CI only).** In `aegis/ml/targets/image_cifar10.py`,
   implement the small CNN target against the vendored 500-image fixture
   (`tests/ml/fixtures/cifar10_test_500.npz`, seed-0 stratified, 50 per class;
   section 11.3.5). It loads offline from the fixture, never from the network.
   Register it, but keep it out of the demo catalog: mark
   `metadata["fixture_only"] = True` so WS4/WS5 exclude it.

8. **Endpoint / LLM stub.** In `aegis/ml/targets/endpoint.py`, register a target
   with a stable id, `domain="llm"`, `info().status == "not_implemented"`, and a
   reason naming the Phase B endpoint shape (`AuthProfile` credentials, target
   allowlist). `load()` raises `NotImplementedError`; the API rejects any
   campaign against it with HTTP 501 upstream (section 9.1 rule 4).

9. **Loaders (worker-side).** In `aegis/ml/loaders.py`, implement format
   detection by file signature and the per-format load (ONNX via `onnx.load` +
   `onnx.checker` + `onnxruntime`; `torch_state_dict` via
   `torch.load(weights_only=True)` + catalog instantiation +
   `load_state_dict(strict=True)`; `safetensors` via `safetensors.torch`). This
   module imports torch/onnx and therefore runs only in the sandbox child, never
   in the API (section 9.2).

10. **ML sandbox.** In `aegis/ml/sandbox.py` and `aegis/ml/sandbox_worker.py`,
    build the `validate` stage on the `aegis/scanners/sandbox.py` primitives with
    the ML differences of section 9.4: child entry `python -m
    aegis.ml.sandbox_worker --stage validate`; env limits from
    `AEGIS_ML_SANDBOX_*` (timeout 1200 s, cpu 900 s, memory 4096 MB, threads 2),
    network never enabled; the **parent** populates the per-job work dir with the
    model file fetched from S3 and digest-checked against the manifest; the child
    reaches no S3, Postgres, Redis, or dataset source. The child returns a typed
    envelope (format detected, shapes, `gradients`, `onnx_torch_argmax_agreement`,
    refusal reason); the parent validates it and writes the outcome.

11. **`build-assets` CLI.** Wire steps 3 and 5 into `aegis ml build-assets`
    (`aegis/cli/ml.py`). Fetch each dataset by pinned revision, train and export
    with a fixed seed, write each model plus `MANIFEST.json` plus the evaluation
    slice to the blob store under `ml/assets/<dataset_id>/<revision>/` (datasets)
    and `bundled/<model_id>/` (models), and call `register_bundled_model` so a
    `Target` of kind `ml_model_artifact` is inserted with the manifest as
    `detail` and `status="available"`. Idempotent and re-runnable; add `--force`
    to rebuild. Print the manifest summary. This is the "seed sample models and
    datasets into S3 on first deploy" step; it is a one-off worker/CLI task, not
    baked into the image (section 11.5).

12. **Model admission service.** In `aegis/services/ml_models.py`, add
    `register_bundled_model(...)` (audit `model.register` `source=bundled`, seed
    `available`) and `admit_upload(...)`. `admit_upload` streams bytes to the
    blob store, sniffs the first 16 bytes against the section 9.2 table, computes
    sha256 without deserialising, refuses pickles and format mismatches, writes
    the `model.register` audit row **before** the `Target` row, inserts the
    `Target` (kind `ml_model_artifact`, manifest `status="registered"`), then
    creates an `ml.ingest` Run and a `model.validate` Job and enqueues it
    (status becomes `validating`). No loading happens in the API.

13. **`POST /v1/models` router.** In `aegis/api/v1/models.py`, add the multipart
    upload endpoint (fields `declared_format`, `architecture_id` when required,
    `modality`, `dataset_id`, `license_statement`). Gate it at `admin`
    (`target.manage` tier; add `Action.MODEL_REGISTER` at `admin` rank in
    `aegis/api/policy.py`). Enforce `Content-Length` and the streaming cap
    `AEGIS_ML_UPLOAD_MAX_MB` (413 over cap). Refuse pickles with 415, format
    mismatch or missing/unknown `architecture_id` with 422, all with an audit
    `model.register` `success=false`. Add `GET /v1/models` (RLS- and
    membership-gated read) and `DELETE /v1/models/{id}` (admin; audit before
    mutate; FK to `runs` blocks deletion of a referenced model; the blob is never
    deleted here). Mount the router in `aegis/api/app.py`.

14. **Wire the registry.** Make `aegis/ml/targets/__init__.py` import each target
    module so registration fires when `TARGETS` is imported. Keep import side
    effects cheap: register lightweight instances and defer all blob reads to
    `load()`, so importing the registry touches neither S3 nor a dataset.

---

## 6. Files to create or modify

Create:

- `aegis/ml/targets/architectures.py`
- `aegis/ml/targets/image_vehicles.py`
- `aegis/ml/targets/tabular_unsw.py`
- `aegis/ml/targets/image_cifar10.py`
- `aegis/ml/targets/endpoint.py`
- `aegis/ml/targets/registry.py`
- `aegis/ml/loaders.py`
- `aegis/ml/sandbox.py`
- `aegis/ml/sandbox_worker.py`
- `aegis/cli/ml.py` (the `build-assets` subcommand)
- `aegis/services/ml_models.py`
- `aegis/api/v1/models.py`
- `tests/ml/test_targets.py`
- `tests/ml/test_build_assets.py`
- `tests/ml/test_models_upload.py`
- `tests/ml/test_sandbox.py`

Modify:

- `aegis/ml/targets/__init__.py` — import target modules so registration fires.
- `aegis/ml/schema.py` — add `MLModelManifest` (and, with WS0,
  `Provenance.dataset_revision`).
- `aegis/api/app.py` — mount the `/v1/models` router.
- `aegis/api/policy.py` — add `Action.MODEL_REGISTER` at `admin` rank.
- `aegis/cli/main.py` — register the `ml build-assets` subcommand.

Do not modify: `aegis/ml/targets/base.py`, `aegis/registry.py`,
`aegis/scanners/sandbox.py`. Do not add the `0010_ml_vertical` migration here; it
is WS0.

---

## 7. Testing and validation

All tests under `tests/ml/`, offline, using the sqlite harness in
`tests/conftest.py` and the `ml` pytest marker. Image and tabular tests that need
bundled assets skip cleanly when the asset is absent, so CI without the built
assets still passes; `TinyTarget` covers the protocol path with no assets.

1. **Registry lists targets.** `TARGETS.ids()` contains `vehicles_cnn`,
   `unsw_trees`, `cifar10_smallcnn`, and the endpoint stub. Each item satisfies
   the `Target` protocol (`isinstance(t, Target)`), and importing the registry
   reads no blob and hits no network.

2. **Stub is honest.** The endpoint target's `info().status ==
   "not_implemented"`, its reason is a non-empty string, and `load()` raises
   `NotImplementedError`.

3. **Protocol over `TinyTarget`.** `TinyTarget` (`tests/ml/fakes.py`) exercises
   `sample`, `predict_proba`, and `art_classifier` with no assets: `sample(20,
   0).indices` equals a second `sample(20, 0).indices`; `predict_proba` rows sum
   to ~1; `art_classifier()` predicts a batch and reports `nb_classes` and
   `clip_values=(0.0, 1.0)`.

4. **Image target (asset-gated).** `load()` is idempotent; `sample(20, 0)`
   returns float32 x in [0, 1], shape `(20, 3, 128, 128)`, `y` length 20,
   stratified across the 7 coarse classes; `art_classifier()` reports
   `nb_classes=7`, `input_shape=(3, 128, 128)`, `clip_values=(0.0, 1.0)`.

5. **Tabular target (asset-gated).** `sample` returns x shape `(n, n_features)`;
   `predict_proba` sums to ~1; the ART tree wrapper predicts a batch;
   `torch_model()` raises `NotImplementedError`; the manifest carries the
   surrogate block (kind, sha256, agreement) and the per-feature ranges.

6. **`build-assets` writes the manifest.** After a run against a tiny fixture
   dataset, `MANIFEST.json` is present in the blob store and parses; it contains
   dataset id, resolved revision, license, split, per-class `n`, seed, model
   architecture, weight sha256, measured clean accuracy, and (tabular) the
   surrogate. A `Target` of kind `ml_model_artifact` exists with `status ==
   "available"`.

7. **Upload refuses a pickle.** `POST /v1/models` with a pickle-opcode body
   (`\x80` at byte 0) or a `.pkl`/`.joblib` name returns 415, retains no bytes,
   and writes a `model.register` audit row with `success=false`. A `state_dict`
   without `architecture_id`, or an unknown id, returns 422. A non-admin caller
   is denied.

8. **Sandbox isolation.** Launch the real `aegis.ml.sandbox_worker --stage
   validate` child on a `TinyTarget`-style file and on a deliberately malformed
   file. The child loads the model only in the subprocess; the parent never
   imports torch/onnx; a malformed file yields a typed `{"ok": false}` envelope
   and a `refused` outcome, not a crash and not a fake result.

Run `make test` and `make typecheck`; both must stay green. Do not rely on
`lint-py`, which has known pre-existing findings.

---

## 8. Acceptance criteria / Definition of done

- `aegis ml build-assets` runs offline-after-fetch, trains and exports the
  vehicle CNN (`state_dict` + ONNX) and the UNSW-NB15 tree ensemble with a fixed
  seed, writes each model plus `MANIFEST.json` plus its evaluation slice to the
  blob store under `ml/assets/` and `bundled/`, and registers each as a `Target`
  of kind `ml_model_artifact`, `status="available"`.
- `from aegis.ml.targets.registry import TARGETS` returns a `Registry[Target]`
  with the vehicle image target and the UNSW-NB15 tabular target
  (`status="available"`), the CIFAR-10 CNN (registered, `fixture_only`), and the
  endpoint stub (`status="not_implemented"` with a reason).
- Each live target implements every `Target` member. `sample` is stratified,
  seeded, and reproducible; image x is float32 [0, 1] NCHW; the image
  `art_classifier()` reports `nb_classes=7`, `input_shape=(3, 128, 128)`,
  `clip_values=(0.0, 1.0)`.
- The tabular manifest declares the perturbable features, per-feature ranges, and
  the PGD surrogate (kind, sha256, clean-slice agreement); `torch_model()` raises
  `NotImplementedError`.
- `POST /v1/models` accepts ONNX and `state_dict`-with-architecture, refuses
  pickles (415) and format mismatches (422), never loads a model in the API, is
  gated at `admin`, and writes the `model.register` audit row before the `Target`
  row. The admission service enqueues a `model.validate` Job whose sandboxed
  outcome moves the manifest status to `available` or `refused`.
- The `model.validate` job loads the model only in the sandbox child; the API
  process imports no ML library.
- CIFAR-10 is present as a CI fixture only and never enters the demo catalog or a
  `Finding`.
- `tests/ml/` passes; `make test` and `make typecheck` stay green.

---

## 9. Effort and special considerations

**Effort:** ~3 to 4 developer-days. The image target with `build-assets` and the
sandboxed upload path are the bulk; the tabular target with its surrogate is a
day; the CIFAR-10 fixture target and the stub are half a day together.

**Asset seeding is a one-off task to S3, not baked into the image.** Dataset and
model bytes are fetched once by `aegis ml build-assets` and written to the blob
store under `ml/assets/` and `bundled/` (section 11.5). The worker reads them
from S3/MinIO; the API and web containers never hold them. This is the "seed
sample models and datasets into S3 on first deploy" step. Do not train at
container start and do not bake the datasets into the image. Coordinate the
deploy hook with WS7.

**CIFAR-10 is fixture-only.** The 500-image seed-0 subset
(`tests/ml/fixtures/cifar10_test_500.npz`) and the small CNN exist so CI runs
offline and deterministically. They never appear in the demo catalog, never
populate a `Finding`, and never render as evidence (section 11.1). Keep them
behind the `fixture_only` flag.

**Never load a model in the API.** The API streams bytes, sniffs a signature,
computes sha256, and writes rows; it imports no torch, onnx, onnxruntime, ART, or
SHAP (section 9.1 rule 2). Every load — validation, clean eval, attack, explain,
verify — runs in `aegis.ml.sandbox_worker`, one path for bundled models and
uploads alike, so the demo exercises the boundary rather than bypassing it. The
ML sandbox is defense-in-depth (process isolation, rlimits, wall-clock kill,
minimal env, no credentials), not a network or filesystem jail; the Fargate
target has no gVisor equivalent, which is a recorded risk (section 25).

**Normalisation convention (load-bearing).** x is float32 in [0, 1], NCHW.
Channel normalisation lives inside the `nn.Module`, so ART's
`clip_values=(0.0, 1.0)` and the L∞ budget WS2 applies are both measured in the
[0, 1] space and SHAP sees the same raw tensor. Do not normalise in `sample()` or
before ART; keep one input contract end to end.

**Tabular ε semantics.** Mixed categorical/numeric features make L∞ ε awkward, so
perturbation is restricted to the declared continuous features with per-feature
scaling from the training-split range, and this is a standing limitation of every
tabular campaign (section 12.9). The surrogate is never introduced silently: PGD
runs on the surrogate, is scored on the real model, and is labelled in
`Measurement.notes`; HopSkipJump runs directly on the tree model.

**Reproducibility and provenance.** Record every seed (training seed, split seed,
sampling is caller-seeded per call), the resolved HuggingFace revision, the split
name, and the evaluation-slice indices in the manifest. WS4 copies them into
`Provenance.model_manifest`, `Provenance.dataset_revision`, and
`Provenance.sample_indices_sha256`. Same `(dataset_revision, split, n, seed)`
into `sample()` must return identical rows, which the tests enforce.

**Coordination seams.** WS2 consumes `art_classifier()` and `sample()` and the
tabular surrogate; WS3 consumes `torch_model()` (image) and `TreeExplainer` on
the real tree model (tabular), so keep the tabular `torch_model()` refusal
explicit. WS4 owns the campaign admission and the `Provenance` build; P1 stops at
`model.validate`. WS5 owns web `/models` (P5). Raise any missing schema field or
`targets.detail` shape with WS0 before adding it; do not edit
`aegis/ml/targets/base.py` or `aegis/registry.py` in this phase.
