> **SUPERSEDED / RECONCILED (2026-09-08 spec update).** This file was written for v1 against the deleted `redsim/` package. It now maps to: **No canonical feature** — interop was dropped in the consolidation.
>
> Substrate corrections (see `00-master-plan.md` §2 and the canonical spec): **this whole phase is currently out of scope.** Croissant export, dataset endpoints, and MITRE ATLAS are absent from the canonical spec and F001–F008; ONNX survives only as an ingest loader in F002. To keep interop it must be re-proposed as a feature (see `00-master-plan.md` §6). Do not build this without that decision.
>
> Use this file for the parallel-execution shape only, not the literal paths, signatures, or mechanisms below.

# P6 — Interoperability (Croissant + ONNX ingest)

Status: v1, 2026-09-08. Owner: rotates in after P4 (suggested Dev A, since ONNX
ingest is a target). Wave 2. Not on the critical path.

Read `00-master-plan.md` first, then this file. This phase makes redsim a good
citizen in a data exchange. It publishes a run's adversarial examples as a
Croissant dataset another team can pull, and it accepts another team's ONNX
model as an attackable target. It closes the interoperability loop the hackathon
spec section 14.1 and 14.2 ask for.

---

## 1. Objective

Give redsim two-way interoperability around a completed run.

1. **Contribute.** Turn a finished run's adversarial examples into an open,
   content-addressed dataset. The payload is Parquet. The metadata is a
   Croissant (MLCommons JSON-LD) manifest that describes the payload and cites
   it by `sha256`. A partner team pulls the dataset and loads it with the
   `datasets` or `mlcroissant` loader, then adversarially trains on it or adds
   it to a regression suite.
2. **Consume.** Load an arbitrary uploaded ONNX model as a `Target`, wrap it for
   ART, and let redsim attack it like any built-in target.
3. **Surface ATLAS.** Carry the per-attack MITRE ATLAS technique (produced in
   P3) into the dataset manifest as an `atlas_coverage` block, and document an
   optional ATLAS case-study export format.

Everything here is opt-in and off by default. A run does not build a dataset
until `POST /v1/runs/{id}/dataset` is called. An ONNX target does not exist
until a model is uploaded.

## 2. Scope

### In scope

- `redsim/interop/croissant.py`: `build_dataset()` builds a Parquet payload plus
  a Croissant JSON-LD manifest from a completed `RunRecord` and its persisted
  adversarial tensors.
- Content addressing: the Parquet payload is hashed with `sha256`, and the
  manifest references it by that hash.
- Local storage under `REDSIM_OUTPUT_DIR/runs/<id>/dataset/`, plus optional
  upload to `s3://REDSIM_S3_BUCKET/datasets/<run-id>/` with `boto3` when the
  bucket is configured.
- Two API routes added to `redsim/api/routes.py` (coordinate with P4):
  `POST /v1/runs/{id}/dataset` and `GET /v1/datasets/{id}`.
- `redsim/targets/onnx_target.py`: an ONNX `Target` loaded with `onnxruntime`
  and wrapped for ART, plus its registration so an uploaded model appears in
  `GET /v1/targets`.
- ATLAS surfacing: the dataset manifest carries `atlas_coverage`, consumed from
  P3's mapping. An optional ATLAS case-study export format is documented, not
  built.

### Out of scope

- **Palantir Foundry integration (spec 14.3).** Explicitly out. Do not build the
  Foundry REST push.
- **Anduril Lattice integration (spec 14.3).** Explicitly out. Do not build the
  Lattice attestation.
- The ATLAS `attack_id -> technique` mapping table itself. That is P3's. P6
  consumes it, never duplicates it.
- MRI scoring. That is P2. P6 reads `RunRecord.scoring` if present and copies its
  summary into the manifest, but it does not compute it.
- A Hugging Face `datasets` dataset card as a distinct artifact. The Parquet plus
  Croissant manifest is the deliverable. The `datasets` loader reads Croissant
  directly, so a separate card is a later nicety, not P6.
- The SHAP explanation, recommendations, and report builders. Those are P3 and
  P4. P6 only reads their outputs.

## 3. Prerequisites and dependencies

P6 is a Wave 2 phase. It builds on completed run outputs, so it starts after P4
wires the pipeline.

| Needs | From | What exactly |
|---|---|---|
| Completed run outputs | **P4** | A `RunRecord` written to `run.json`, `status == "succeeded"`, with `provenance`, `measurements`, `observations`, and (if scored) `scoring` and `atlas_coverage`. |
| Persisted adversarial tensors | **P4 / P2** | The attack stage must persist the clean and adversarial tensor arrays for every attacked sample, plus per-sample predicted label and the applied eps. See the coordination note below. |
| `Target` Protocol | **P1** | `redsim/targets/base.py` — the `Target` Protocol and `Sample` dataclass the ONNX target must satisfy. |
| Targets registry | **P1** | `redsim/targets/registry.py` (`TARGETS`) so an uploaded ONNX model registers as a target. |
| ATLAS mapping | **P3** | `attack_id -> (atlas_technique_id, atlas_technique_name)`, already stamped onto `AttackInfo.atlas_technique_id` / `atlas_technique_name` and aggregated on `RunRecord.atlas_coverage`. Consume it. |
| S3 bucket + credentials | **P7** | `REDSIM_S3_BUCKET` env var and the ECS task role that grants `s3:PutObject` / `s3:GetObject` on `datasets/*`. |
| API router | **P4 / P0** | `redsim/api/routes.py` and the `create_app()` factory in `redsim/api/app.py`. |

### Coordination note — where the adversarial tensors come from

`RunRecord` does not persist full tensor arrays. `Observation` rows exist only
for the `explain_k` sampled examples, and they hold PNG artifact paths, not raw
tensors. A dataset that covers every attacked sample needs the arrays.

Agree this seam with P4 and P2 before P6 starts:

- The attack stage writes, per run, a compact artifact holding the clean tensor
  `x`, the adversarial tensor `x_adv`, the source-slice `indices` (from
  `Sample.indices`), the true labels `y`, the clean predicted labels, the
  adversarial predicted labels, and the applied eps per sample. A single
  `.npz` under `artifacts/attack/` is enough (for example
  `artifacts/attack/adversarial.npz`).
- P6 reads that artifact through `RunStore.resolve(...)`. If it is absent, P6
  degrades to the `explain_k` observations only and marks the dataset partial in
  the manifest and in the `POST` response.

This is the one contract P6 cannot invent alone. Raise it in master section 6
if the array names or the artifact path change.

## 4. Interfaces consumed and exposed

### 4.1 HTTP routes exposed (master section 6.7)

| Method | Path | Returns |
|---|---|---|
| `POST` | `/v1/runs/{id}/dataset` | `202`/`200` `{dataset_id}`. Builds the Parquet payload and the Croissant manifest, writes them locally, uploads to S3 when configured, and registers the dataset. `404` if the run is unknown. `409` if the run is not `succeeded`. Idempotent: a second call returns the same `dataset_id`. |
| `GET` | `/v1/datasets/{id}` | The Croissant JSON-LD manifest, `content-type: application/ld+json`. `404` if unknown. |

`dataset_id` is the run id. The dataset is one-to-one with a run, so reusing the
run id keeps the mapping trivial and the `POST` idempotent.

### 4.2 Function shape consumed and exposed

```python
# redsim/interop/croissant.py

@dataclass
class DatasetResult:
    dataset_id: str
    manifest_path: str          # run-relative, e.g. "dataset/croissant.jsonld"
    payload_path: str           # run-relative, e.g. "dataset/adversarial.parquet"
    payload_sha256: str
    n_rows: int
    partial: bool               # True when only explain_k rows were available
    s3_uri: str | None          # set when REDSIM_S3_BUCKET is configured

def build_dataset(record: RunRecord, store: RunStore) -> DatasetResult:
    """Build the Parquet payload and the Croissant manifest for a completed run.

    Reads the persisted adversarial tensors through ``store``. Writes both files
    under ``store.run_path / "dataset"``. Content-addresses the payload with
    sha256 and cites that hash from the manifest. Uploads to S3 when
    ``REDSIM_S3_BUCKET`` is set. Pure with respect to the RunRecord: it never
    mutates it.
    """
```

The route layer loads `run.json` through `RunStore.open(run_id)`, validates it
into a `RunRecord`, calls `build_dataset`, and returns `{dataset_id}`.

**Parquet columns** (one row per attacked sample):

| Column | Source |
|---|---|
| `sample_index` | `Sample.indices` (persisted array), same as `Observation.sample_index`. |
| `x_clean` | clean tensor, flattened, plus a `shape` column. |
| `x_adv` | adversarial tensor, flattened. |
| `true_label` | int and string form. Mirrors `Observation.true_label`. |
| `pred_clean` | clean prediction. Mirrors `Observation.pred_clean`. |
| `pred_adv` | adversarial prediction. Mirrors `Observation.pred_adv`. |
| `flipped` | `pred_clean != pred_adv`. Mirrors `Observation.flipped`. |
| `attack_id` | `RunRecord.config.attack_id`. |
| `eps` | applied budget per sample, from the persisted array or `config.params`. |

**Croissant manifest** references the Parquet file as a `FileObject` with its
`sha256`, describes each column as a `Field` under a `RecordSet`, and carries a
`redsim` metadata block:

- `model_provenance`: the whole `RunRecord.provenance` object. Names the model by
  `provenance.model_sha256`, the data by `provenance.dataset` and
  `provenance.dataset_split`, and copies `provenance.model_manifest`.
- `library_versions`: `provenance.redsim_version`, `provenance.python`,
  `provenance.torch`, `provenance.art`, `provenance.shap`, `provenance.numpy`.
- `atlas_coverage`: `RunRecord.atlas_coverage` plus, per attack, the
  `AttackInfo.atlas_technique_id` and `AttackInfo.atlas_technique_name` from
  `RunRecord.attack`.
- `scoring_summary`: `RunRecord.scoring.mri` and `RunRecord.scoring.grade` when
  `RunRecord.scoring` is present, else omitted.
- `limitations`: `RunRecord.limitations`, so a consumer reads the honesty labels
  with the data.

### 4.3 ONNX target registration

```python
# redsim/targets/onnx_target.py

class OnnxTarget:            # satisfies redsim.targets.base.Target
    id: str                  # e.g. "onnx.<sha256[:12]>"
    def info(self) -> TargetInfo: ...        # status "available"
    def load(self) -> None: ...              # onnxruntime.InferenceSession
    def sample(self, n: int, seed: int) -> Sample: ...
    def predict_proba(self, x: np.ndarray) -> np.ndarray: ...
    def art_classifier(self) -> Any: ...     # ART estimator over the ONNX model
    def torch_model(self) -> Any: ...        # raises NotImplementedError; SHAP path documented below
    def manifest(self) -> dict[str, Any]: ...
```

- `art_classifier()` wraps the session. Preferred is ART's ONNX-aware estimator
  path, `art.estimators.classification.BlackBoxClassifierNeuralNetwork` fed by a
  predict callable over the `onnxruntime` session, so gradient-free attacks run.
  Where a white-box gradient attack is needed, note that ONNX gives no autograd,
  so `torch_model()` raises `NotImplementedError` and SHAP uses the black-box
  `KernelExplainer` path already anticipated in the spec, or is skipped. State
  this limitation on the target `info().reason` field when SHAP is unavailable.
- The uploaded model plus its eval slice is the ingest. The eval slice comes in
  as Croissant or Parquet from the partner team, mirroring the contribute side.
  For P6 the slice may reuse a bundled slice keyed by declared input shape, and
  a Croissant/Parquet slice loader is a documented follow-on if time is short.
- Registration: add the ONNX target to `TARGETS` at upload time so it lists in
  `GET /v1/targets`. Model files are untrusted. ONNX loads no arbitrary code, so
  it is the safe format, but still validate the file signature and never load it
  in the API process path that serves other tenants.

## 5. Ordered implementation steps

1. **Confirm the tensor seam.** Agree the `artifacts/attack/adversarial.npz`
   contents and path with P4/P2. Record it in master section 6 if it moves.
2. **Add dependencies.** Add `onnxruntime` and `boto3` to `pyproject.toml`
   dependencies. `pyarrow` is already present. Pin versions. Note that
   `onnxruntime` is CPU-only for the demo.
3. **Create `redsim/interop/__init__.py`** and `redsim/interop/croissant.py`.
   Implement `build_dataset`:
   1. Read the persisted arrays through `store.resolve(...)`. Fall back to
      `record.observations` when the arrays are absent and set `partial=True`.
   2. Build the Arrow table and write `dataset/adversarial.parquet` with
      `pyarrow.parquet.write_table`.
   3. Compute the payload `sha256` over the written bytes.
   4. Build the Croissant JSON-LD dict, cite the payload by `sha256`, embed the
      `redsim` metadata block from section 4.2.
   5. Write `dataset/croissant.jsonld`.
   6. Upload both files to S3 when `REDSIM_S3_BUCKET` is set (step 6).
   7. Return `DatasetResult`.
4. **Add the S3 helper.** A small `redsim/interop/s3.py` (or a function inside
   `croissant.py`) that uploads a local file to
   `s3://REDSIM_S3_BUCKET/datasets/<run-id>/<name>`. When `REDSIM_S3_BUCKET` is
   unset or empty, it is a no-op and returns `None`. Use `boto3` default credential
   resolution (the ECS task role), never static keys.
5. **Wire the routes** into `redsim/api/routes.py` (coordinate with P4). Add
   `POST /v1/runs/{id}/dataset` and `GET /v1/datasets/{id}`. The `GET` reads the
   stored `dataset/croissant.jsonld` from local disk first, then S3 if configured
   and missing locally.
6. **Create `redsim/targets/onnx_target.py`.** Implement `OnnxTarget` against the
   `Target` Protocol. Add a registration hook that inserts an uploaded model into
   `TARGETS`. Provide the ART wrapper.
7. **Document the ATLAS case-study export.** Add a short section to this file's
   appendix or to the report docs describing the optional ATLAS case-study JSON
   shape. Do not build an exporter.
8. **Tests.** Write the pytest modules in section 7.
9. **Round-trip check.** Load the built dataset with `mlcroissant` (or the
   `datasets` loader) in a test or a manual check, and confirm labels round-trip.

## 6. Files to create and modify

### Create

- `docs/plans/07-p6-interoperability.md` (this file).
- `redsim/interop/__init__.py`
- `redsim/interop/croissant.py`
- `redsim/interop/s3.py` (S3 upload helper; may instead live inside `croissant.py`)
- `redsim/targets/onnx_target.py`
- `tests/test_interop_croissant.py`
- `tests/test_onnx_target.py`

### Modify

- `pyproject.toml` — add `onnxruntime` and `boto3` to `dependencies`. `pyarrow`
  is already declared.
- `redsim/api/routes.py` — add the two dataset routes (coordinate with P4; P0
  reserves the shapes in master section 6.7).
- `redsim/targets/registry.py` — register uploaded ONNX targets (P1 owns this
  file; coordinate the registration hook).
- `docs/plans/00-master-plan.md` — only if the tensor-artifact seam names change
  (section 6 note).

## 7. Testing and validation

All pytest. Keep models and slices tiny so tests run on CPU in seconds.

1. **`build_dataset` writes valid Parquet.**
   - Construct a small `RunRecord` and a `RunStore` with a synthetic
     `artifacts/attack/adversarial.npz` (a handful of samples).
   - Call `build_dataset`. Assert `dataset/adversarial.parquet` exists and reads
     back with `pyarrow.parquet.read_table`, with the expected columns and row
     count.
2. **The Croissant manifest references the payload by sha256.**
   - Assert `dataset/croissant.jsonld` parses as JSON-LD.
   - Assert the manifest's `FileObject` `sha256` equals `DatasetResult.payload_sha256`
     and equals the actual sha256 of the written Parquet bytes.
   - Assert the `redsim` block carries `model_provenance` from
     `record.provenance` and the `library_versions` keys.
3. **Labels round-trip.**
   - Read the Parquet back and assert `true_label`, `pred_clean`, and `pred_adv`
     match the source `RunRecord`/npz values row for row.
   - When `mlcroissant` is available, load through it and assert the same. Skip
     with `pytest.importorskip("mlcroissant")` when it is not installed, since it
     is a consumer-side dependency, not a redsim runtime dependency.
4. **ONNX target loads and predicts.**
   - Build a tiny ONNX model in the test (for example export a 2-layer torch net
     with `torch.onnx.export`, or hand-write a minimal graph).
   - Instantiate `OnnxTarget`, `load()`, and assert `predict_proba(x)` returns
     shape `(n, n_classes)` that sums to about 1 per row.
   - Assert `info().status == "available"` and the target registers into `TARGETS`.
   - Assert `art_classifier()` returns an object an ART evasion attack accepts.
5. **S3 upload is skipped cleanly when unconfigured.**
   - With `REDSIM_S3_BUCKET` unset, assert `build_dataset` returns
     `s3_uri is None`, writes the local files, and makes no `boto3` call.
   - With the bucket set, assert the upload helper targets
     `datasets/<run-id>/...` and passes no static credentials (mock `boto3`).
6. **Partial fallback.** With the npz absent, assert `build_dataset` builds from
   `record.observations`, sets `partial=True`, and the manifest marks the dataset
   partial.
7. **Route tests.** `POST /v1/runs/{id}/dataset` returns `{dataset_id}` and is
   idempotent. `GET /v1/datasets/{id}` returns the manifest with
   `application/ld+json`. Unknown ids return `404`. A non-succeeded run returns
   `409`.

## 8. Acceptance criteria (Definition of Done)

1. `POST /v1/runs/{id}/dataset` on a succeeded run writes
   `dataset/adversarial.parquet` and `dataset/croissant.jsonld` under the run
   directory, and returns `{dataset_id}`.
2. When `REDSIM_S3_BUCKET` is set, both files land at
   `s3://REDSIM_S3_BUCKET/datasets/<run-id>/`, uploaded through the task role.
   When it is unset, the build still succeeds locally and skips S3 cleanly.
3. `GET /v1/datasets/{id}` returns the Croissant JSON-LD manifest.
4. A partner team pulls the dataset and reads it with the `datasets` or
   `mlcroissant` loader. The adversarial and clean tensors, the true and
   predicted labels, the per-sample `attack_id` and `eps`, and the source-slice
   indices all load, and the labels match the run.
5. The manifest carries model provenance from `RunRecord.provenance`, the library
   versions, and the `atlas_coverage` block from P3. It cites the Parquet payload
   by `sha256`, and that hash verifies against the file.
6. An uploaded ONNX model registers as a target, lists in `GET /v1/targets` with
   `status == "available"`, and is attackable: a redsim run against it produces
   `measurements` and, where the black-box SHAP path applies, `observations`.
7. `pytest` passes for `tests/test_interop_croissant.py` and
   `tests/test_onnx_target.py`, and `make check` stays green.

## 9. Effort estimate and special considerations

**Effort.** Roughly 1.5 to 2.5 developer-days. The Croissant manifest builder and
the Parquet writer are half a day. The ONNX target and its ART wrapper are the
larger and riskier half, because the black-box SHAP and gradient-free attack path
needs care. S3 and the routes are a few hours each.

**Special considerations.**

- **Croissant schema conformance.** Croissant is a JSON-LD profile with a fixed
  `@context` and required `RecordSet` / `Field` / `FileObject` shapes. Validate
  the built manifest against the MLCommons Croissant validator (or by loading it
  with `mlcroissant`) rather than by eye. A manifest that a human reads fine but
  the loader rejects fails acceptance criterion 4. Pin the Croissant context
  version you target and record it in the manifest.
- **`onnxruntime` dependency.** It is not yet in `pyproject.toml`. Add it. It is
  CPU-only for the demo, consistent with the no-GPU rule. It enlarges the worker
  image, so keep it out of the web image.
- **`boto3` dependency.** Also not yet declared. Add it. Its only job here is the
  optional dataset upload.
- **S3 credentials via the task role, not static keys.** Use `boto3` default
  credential resolution so the ECS task role supplies credentials. Never read an
  access key or secret from the environment or the code. The task role (P7)
  grants `s3:PutObject` and `s3:GetObject` scoped to `datasets/*`.
- **Untrusted model files.** ONNX runs no arbitrary code on load, which is why it
  is the accepted format. Still validate the file signature, cap the file size,
  and keep model loading off the API request path that serves other tenants.
- **Partial datasets are honest.** When only `explain_k` observations are
  available, the dataset is a small sample, not the full slice. Mark it `partial`
  in the response and the manifest rather than shipping a full-looking dataset
  that is not.
- **Tensor size in Parquet.** Flattened image tensors are wide. For CIFAR-10 at
  200 samples this is small, but store the `shape` alongside so a consumer
  reshapes correctly, and consider a fixed-size list column rather than a Python
  list per cell.

### Appendix — optional ATLAS case-study export (documented, not built)

A program may contribute a sanitized case study back to the MITRE ATLAS
community. The export is a JSON document, one per run, holding: the technique ids
from `RunRecord.atlas_coverage`, the attack name and family from
`RunRecord.attack`, the summary metrics from `RunRecord.measurements` (accuracy
drop and flip rate, no raw data), the MRI and grade from `RunRecord.scoring`
when present, and the standing `RunRecord.limitations`. It carries no tensors and
no dataset payload, only the technique-to-outcome narrative. Building an exporter
is a follow-on, not P6.
