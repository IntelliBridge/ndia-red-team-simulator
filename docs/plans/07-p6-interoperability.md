# P6 / Phase B2 · Interoperability (spec section 27, as built)

Status: v2, 2026-09-09. Rewritten by the Phase B wave B4 documentation pass
onto the vocabulary of spec section 27 and onto the tree at `main` `703f8f6`
plus wave B4. It replaces the v1 body of 2026-09-08, which planned this phase
against the deleted standalone `redsim/` substrate (`redsim/interop/`,
`RunStore`, `mlcroissant`, `boto3`); none of those paths, signatures or
mechanisms exists. The narrative of the same work is `docs/interop.md`, the
route contracts are `docs/api/v1.md` under "Interoperability (wave B3)" and
"Batch and bulk operations (wave B3)", and the tree is the source where this
file and the tree disagree.

Read `docs/plans/00-master-plan.md` section 6 (the decision that adopted
interoperability as Phase B2) and spec section 27 first. This phase was built
as Phase B wave B3 (`docs/plans/12-phase-b-plan.md`, tracks
`interop-contribute`, `interop-consume`, `atlas-foundry`), proven end to end
in wave B4 (`tests/e2e/test_ml_interop.py`) and closed out by the wave B4 fix
pass. It was not on the Phase A critical path and it changed nothing in
D1 to D14.

---

## 1. Objective

Make redsim a good citizen in a data exchange without weakening any Phase A
rule. Four capabilities, every one opt-in and off by default (spec 27 rule 1),
data and REST only with no LLM call (rule 2), no standing credential (rule 3):

1. **Contribute.** Turn a terminal campaign or verify run's adversarial
   examples into an open, content-addressed dataset: Parquet shards described
   by an MLCommons Croissant 1.0 JSON-LD manifest whose own sha256 is the
   dataset version. Another team pulls it and loads it with a Croissant-aware
   loader.
2. **Consume.** Accept another team's evaluation slice (Parquet with an
   optional Croissant manifest) as an `ml_datasets` row a model upload and a
   campaign can bind to, and another team's model as an ONNX upload through the
   existing `POST /v1/models` path (section 9 rules unchanged).
3. **Surface ATLAS.** Stamp the MITRE ATLAS technique on every new finding,
   expose it on the attack catalog and give each campaign a number-free
   coverage view.
4. **Push.** An operator-configured Palantir Foundry instance receives a
   scorecard (always with its subscores, denominators, eps grid,
   `settings_hash` and the grade sentence). Anduril Lattice stays text only
   under the D3 bound.

## 2. Scope as built

### In scope (on the tree)

| Capability | Modules | Routes | Tasks |
|---|---|---|---|
| Contribute | `redsim/ml/interop/{parquet,croissant,card}.py`, `redsim/services/ml_datasets_export.py` | `POST /v1/runs/{run_id}/dataset` (membership, `dataset.export`, remediator), `GET /v1/datasets/{id}` (the manifest as `application/ld+json`) | `redsim.dataset_export` (`scans` queue, `max_retries=2`) |
| Consume | `redsim/services/ml_datasets.py` (stdlib static checks and the binding helpers), `redsim/ml/interop/consume.py` (the parse child, `load_consumed_slice`), the binding hooks in `redsim/services/ml_models.py` (`check_upload_dataset` falling back to `consumed_upload_binding`, `materialize_consumed_slice`) and `redsim/ml/targets/artifact.py` (`consumed_eval_slice`), the campaign hook in `redsim/services/ml_campaigns.py` | `POST /v1/datasets` (multipart; membership, `dataset.register`, remediator), the consumed rows on `GET /v1/datasets`, the record on `GET /v1/datasets/{id}` | `redsim.ml_dataset_validate` (`scans`, `max_retries=2`) |
| ATLAS | `redsim/ml/atlas_data.py` (release `v2026.08` vendored with digests), `redsim/ml/atlas.py` (`STAMP_TECHNIQUE_IDS`, `technique_for_attack`, `attack_atlas_row`, `coverage`), the one-line stamp in `redsim/services/ml_findings.py` (campaign findings and, since wave B4, analyst drafts through `redsim/services/finding_review.py`), the block on `GET /v1/attacks` | `GET /v1/runs/{run_id}/atlas-coverage` (membership) | none |
| Push | `redsim/integrations/foundry.py` (settings from the process environment, roster block, `build_scorecard_payload`, the D9 guard `validate_push_payload` / `assert_push_payload`, `scrub_detail`, the Datasets v2 client), `redsim/integrations/__init__.py` (`create_foundry_push`, `LATTICE_STATUS`), `tests/ml/fake_foundry_server.py` | `GET /v1/integrations` (authenticated roster), `POST /v1/runs/{run_id}/integrations/foundry` (membership, `integration.push`, admin) | `redsim.integration_push` (`default` queue, the pool with egress, `max_retries=0`) |

The API process imports none of `pyarrow`, `mlcroissant` or an ML library for
any of this (`tests/test_api_process_has_no_ml.py`); Parquet is opened only in
the sandbox child and the worker. `redsim/ml/interop/parquet.py` imports
`pyarrow` inside functions.

### Out of scope (by decision, recorded)

- **Anduril Lattice.** Text only. The roster entry answers `not_implemented`
  with the D3 reason; no setting, route, task or client exists (owner decision
  INTEROP-27 / TESTS_DOCS-41; constitution Principle II).
- **The dataset push to Foundry.** `PUSH_PAYLOADS` is `("scorecard",)`; the
  second half of INTEROP-23 is not built.
- **A push against a real Foundry instance.** Proven against
  `tests/ml/fake_foundry_server.py` only (owner default INTEROP-26); a real push
  needs an operator-configured non-operational instance and the owner's
  confirmation.
- **Imagery exports outside the artifacts bucket.** They stay in the team
  bucket while D006 (export redaction) is open (owner default INTEROP-34);
  tabular exports only are published to the public data repository.
- **Regenerating a slice inside the sandbox child** for a run whose slices
  were not retained (spec 12.8 / 17.4 wording). The export answers
  `409 export_unavailable` instead and never fabricates a row (INTEROP-07).
- **`mlcroissant` as the manifest library.** The manifest is built and
  validated in pure Python (`croissant.py`); the package stays blocked in the
  API-process tripwire (INTEROP-05 divergence, recorded).
- **An ATLAS case-study export.** Documented in the appendix, not built.

## 3. Prerequisites the tree provides

Every seam the v1 plan had to negotiate exists:

| Needs | Provided by | What exactly |
|---|---|---|
| Per-sample slices of a terminal run | the modality runners (`redsim/ml/runners/{classification,text,detection}.py`, `runners/base.py::slice_bytes`) | self-describing `.npz` slices: `clean_slice.npz` after `clean_eval`, `adv_slice/<attack>_<eps>.npz` per attack row, `control_slice/<eps>.npz` per control row, each with the input tensor (or the message strings for text), `indices`, `y`, the clean and adversarial predictions and confidences where the runner has them, and the descriptor keys `family` / `attack` / `eps`, so the exporter labels a slice from its bytes whatever the blob backend did with its name (INTEROP-04, closed for every runner in wave B4). A slice over `REDSIM_ML_MAX_ADV_ARTIFACT_MB` is not retained and the row says so |
| The flip matrix to check against | the campaign frame | `ml.flip_matrix`; `croissant.check_projection` refuses an export whose rows disagree with it (`ExportMismatch`) |
| The record and its digest | `ml.run_record` artifact, `ml_campaigns` row | one export per run, keyed by the source run id |
| The `Target` protocol and registry for uploads | `redsim/ml/targets/base.py`, `registry.py` (P0) | an ONNX upload is a `Target` of kind `ml_model_artifact` (wave 1), the consume side of section 27 |
| The ATLAS mapping | `redsim/ml/atlas.py` over `atlas_data.py` | checked at import against the vendored release; `AML.T0043` for the gradient, text and patch attacks, `AML.T0040` for `hopskipjump` and `zoo`, `AML.T0020` reserved for the poisoning ids, `None` for controls |
| Blob store and audit chain | the platform | `Artifact` rows under `datasets/<source-run-id>/`, the `dataset.export` / `dataset.register` / `integration.push` actions (spec 27.4) |

## 4. Interfaces as built

### 4.1 Routes (spec 27.4; details in `docs/api/v1.md`)

| Method | Path | Gate | Answers |
|---|---|---|---|
| `POST` | `/v1/runs/{run_id}/dataset` | membership, `dataset.export` (remediator since wave B2; B0 had scanner) | `202 {dataset_id, status, type, run_id, job_id, job_ids, status_url, dataset_url}` (a follow-up `Run` with scanner `ml.dataset_export`); the existing manifest with `status: exists` on a second call; `404`; `409 export_unavailable` (non-campaign, non-terminal or slice-less run); `409 export_in_flight`; `422 fixture_not_exportable`; `503 queue_unavailable` with the rows rolled back |
| `GET` | `/v1/datasets/{id}` | membership on the run's or the slice's project | the run's Croissant manifest as `application/ld+json`, digest-checked, `404` until exported; or the consumed record for a `ds-…` id |
| `POST` | `/v1/datasets` | membership, `dataset.register` (remediator) | `201` record in `validating` with `ingest_run_id`, `ingest_job_id`; `411`; `413 dataset_too_large` (over `REDSIM_ML_DATASET_UPLOAD_MAX_MB`, 256); `415 unsupported_dataset_format`; `422 remote_reference_refused` / `license_required` / `schema_undeclared`; `501` for `text` and `detection` slices (loaders not built) |
| `GET` | `/v1/datasets` | authenticated | the bundled manifest rows plus the consumed `ds-…` rows of the caller's memberships (`consumed_count`) |
| `GET` | `/v1/runs/{run_id}/atlas-coverage` | membership | `exercised`, `declared_not_run`, `catalog_outside_declared`, `controls`, `techniques_exercised`, the release citation and the statement; no numeric field; `404` without a record, `409 llm_target_required`, `409 score_unavailable` on a digest mismatch |
| `GET` | `/v1/attacks` | authenticated | each row with `atlas_technique`, `atlas_techniques`, `atlas_reason` and the response with an `atlas` release citation; `?modality=` filters on the capability tags since wave B4 |
| `GET` | `/v1/integrations` | authenticated | `foundry` `disabled` (default) / `misconfigured` (with the rule) / `configured`, booleans only, never a host or token; `lattice` `not_implemented` with the D3 reason |
| `POST` | `/v1/runs/{run_id}/integrations/foundry` | membership, `integration.push` (admin) | `202 {run_id, job_ids, status_url, integration, campaign_run_id, target_ref, kind}`; `501 integration_disabled` (`reason` `disabled` or `misconfigured`) while `REDSIM_INTEGRATION_FOUNDRY_URL` is unset, fails the egress rules or lacks the `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1` attestation; `409 llm_target_required` / `campaign_not_terminal` / `score_unavailable` / `job_in_flight`; `422 fixture_not_exportable` / `params_out_of_range` / `auth_profile_kind_unsupported`; `404`; `503 queue_unavailable` |

Five paths follow the orchestrator brief rather than the register
(`atlas-coverage` not `atlas`, `integrations/foundry` not
`integrations/{integration}/push`, and the three report and bulk paths listed
in `docs/api/v1.md` "Phase B routes").

### 4.2 What an export contains

- **Shards.** One deterministic Parquet shard per `(attack, eps)` of the
  adversarial family, one per control eps and one clean shard, on one fixed
  nullable schema: `sample_index`, `family`, `attack`, `eps`, `norm`, `y`,
  `y_pred_clean`, `y_pred_adv`, `conf_clean`, `conf_adv`, `flipped`, `input`
  (a numeric feature vector or flattened tensor, never a string) and, since
  wave B4, a nullable `text` column that only a text-modality slice fills (a
  text model has no numeric input tensor). Tabular exports carry feature
  vectors only, never URL strings (spec 11.5, D9). The `flipped` column comes
  from the run's flip matrix, so a detection export, whose model predicts
  boxes rather than one label, still carries it.
- **Manifest.** `croissant.json` (Croissant 1.0 JSON-LD): a `FileObject` per
  shard with its sha256, the `RecordSet` fields, and a `redsim:provenance`
  block with the model sha256 and manifest, dataset id, revision and split,
  library versions, `settings_hash`, the limitations and the ATLAS techniques
  exercised. The manifest's own sha256 is the dataset version.
  `croissant_validate` refuses model file names, `reviewer_notes`, credential
  names and any bare MRI number before the manifest is written.
- **Card.** A template-only `README.md` naming the families the source run
  retained and the realizability caveat.
- **Rows on the source run.** `ml.dataset.manifest`, `ml.dataset.parquet` and
  `ml.dataset.card` artifacts under `datasets/<source-run-id>/`; the
  `dataset.export.execute` and `job.complete` rows on the follow-up run's
  chain (manifest sha256, file count, bytes, prefix). A mismatch or an
  invalid manifest is a `success=False` execute row and a failed job with
  nothing written.

The first export built with these modules is in the public data repository
at `0dababc` (`data/exports/url_trees_sample/`, INTEROP-33): three PGD shards
from an offline `url_trees` campaign, 600 rows of 16 lexical features, the
adversarial family only because the source run predated the clean and control
slices.

### 4.3 What the consume side does

Static checks in the API (`redsim/services/ml_datasets.py`, stdlib only):
length cap, Parquet magic `PAR1`, no pickle-shaped part name, the Croissant
shape when a manifest is given, bare-file-name `contentUrl`s only, a licence
statement, a declared schema (`modality`, `class_names`, the feature or image
shape and value range). Every refusal is a `success=False` `dataset.register`
row and nothing is persisted. Success writes the row, the blobs, the
`ml_datasets` row in `validating`, an `ml.dataset_ingest` `Run` with no target
and a `dataset.validate` `Job`, then enqueues `redsim.ml_dataset_validate`.
The worker materialises the blobs into the job work directory, re-hashes them
in the parent (a substituted blob is `artifact_digest_mismatch` with no child
spawned), spawns `python -m redsim.ml.interop.consume` under the ML sandbox's
credential-free environment and rlimits, and marks the row `available` or
`refused` with the child's code (`manifest_digest_mismatch`,
`dataset_too_large`, `schema_mismatch`, `class_names_mismatch`, `parse_failed`,
`sandbox_timeout`, `sandbox_killed`).

Binding (INTEROP-16): a `dataset_id` of the form `ds-…` that names an
`available` consumed slice of the project binds at upload
(`check_upload_dataset` falls back to `consumed_upload_binding`), at campaign
admission (`services/ml_campaigns.py`, modality and project checked,
`422 dataset_incompatible` otherwise) and in the target loader
(`ml/targets/artifact.py::consumed_eval_slice` reads a slice the worker parent
materialised with `materialize_consumed_slice`, re-checks its digest and reads
it with the same `load_consumed_slice` the parse child used). **Open at the
B4 push:** the worker parent (`redsim/workers/tasks/ml_model.py` and
`ml_campaign.py`) does not yet call `materialize_consumed_slice` when it builds
the target detail, so a campaign on a consumed-bound model does not run end to
end; `tests/e2e/test_ml_interop.py::test_consumed_slice_binds_a_model_and_a_campaign`
fails with that attribution.

### 4.4 The Foundry payload guard (D9)

`assert_push_payload` refuses anything that would leave without its evidence
or with something that must not leave: a bare MRI or a grade without the MRI,
a missing subscore, a URL string, a JWT-shaped or `pk_` value, a `token` key,
a model file name, raw bytes, a base64 blob, a readiness word,
`expected_gain`, `reviewer_notes`, `requested_by`, empty rows or limitations.
The exact bytes that leave are stored first (`ml.integration.payload`,
`ml.integration.rows`), the bearer token is resolved through
`resolve_auth_for_scan` only then and dropped after the push, the receipt is
stored (`ml.integration.receipt`) and `integration.push.execute` records host,
rids, digests, statuses and counts, or `step`, `http_status`, `error_class`
and `transaction_aborted` with `success=False` and no retry.

## 5. Order in which it was built

1. Wave B0 (`3cd3362`, `0b0981b`, `ff9e658`, `7b1f2fa`): the actions
   `dataset.register`, `dataset.export`, `integration.push` with their OPA and
   Cedar mirrors, the codes `export_in_flight`, `export_unavailable`,
   `dataset_too_large`, `unsupported_dataset_format`, `license_required`,
   `remote_reference_refused`, `schema_undeclared`, `integration_disabled`
   (first addendum) and `fixture_not_exportable` (second addendum, wave B2),
   the gated `501` stubs, migration `0011` (`ml_datasets`), the vendored ATLAS
   release.
2. Wave B3 (`1f1b52b`, `595a89b`, `bfde5e1`, `005e666`, then the reconcile
   commits `f718f10` and `5f02ac6`, integration `703f8f6`): the three tracks
   above, the export routes on their final signatures, the classification
   runner's self-describing slices, the campaign-side consumed binding.
3. Wave B4 (`6484f2c` and the fix pass): `tests/e2e/test_ml_interop.py`, the
   text and detection runners' slices and the nullable `text` export column,
   the upload binding and the loader for consumed slices, the JWT pattern in
   `redsim/audit/redact.py`, the ATLAS stamp on analyst drafts, the
   `interop` block on `GET /v1/ml/capabilities`, the `.env.example` and
   compose pass-through of the Foundry and capacity variables scoped to the
   default worker pool, `docs/interop.md` and this rewrite.

## 6. Files (as they exist)

- `redsim/ml/interop/__init__.py`, `parquet.py`, `croissant.py`, `card.py`,
  `consume.py`
- `redsim/services/ml_datasets_export.py`, `redsim/services/ml_datasets.py`
- `redsim/workers/tasks/dataset_export.py`, `dataset_validate.py`,
  `integration_push.py`
- `redsim/api/v1/datasets.py`, `redsim/api/v1/integrations.py`, the ATLAS
  block in `redsim/api/v1/attacks.py`
- `redsim/ml/atlas.py`, `redsim/ml/atlas_data.py`
- `redsim/integrations/__init__.py`, `redsim/integrations/foundry.py`
- `tests/ml/test_interop_export.py`, `test_interop_consume.py`,
  `test_atlas_foundry.py`, `tests/ml/fake_foundry_server.py`,
  `tests/e2e/test_ml_interop.py`

## 7. Testing and validation (as it stands)

- `tests/ml/test_interop_export.py` (`ml` tier): a valid manifest whose
  `FileObject` digests and shard columns check out, rows equal to the flip
  matrix, a mutated row refused with a failed job and no artifacts, an
  idempotent re-export, every refusal, a fixture never exported, the
  template-only card, the nullable `text` column for a text slice.
- `tests/ml/test_interop_consume.py`: 25 static refusals audited and
  persisting nothing, the size cap, the child's digest, class, range and
  row-cap refusals, a substituted blob refused in the parent, the child
  spawned credential-free, the API and worker modules importing with
  `pyarrow` blocked, the parent never opening a Parquet file.
- `tests/ml/test_atlas_foundry.py`: the stamp table against the vendored data,
  the number-free coverage view, the roster with no value leaking, the payload
  guard, admission order and the broker rollback, the happy-path push and the
  503-on-commit abort against the fake server with no token, JWT or URL in
  any row, the sandbox child dropping every `REDSIM_INTEGRATION_FOUNDRY_*`
  name.
- `tests/e2e/test_ml_interop.py` (wave B4, `e2e` tier): the Croissant export
  and its shards, a consumed slice registered and validated through the real
  child, the ATLAS tags and coverage, the Foundry push against the fake
  server, and `redsim audit verify --all` over the lot (tolerating the chain
  `test_harness_smoke.py` tampers with on purpose). At the B4 push 5 of its 6
  cases hold; `test_consumed_slice_binds_a_model_and_a_campaign` fails with
  the attribution in 4.3.

## 8. Acceptance criteria (definition of done) and where each stands

1. `POST /v1/runs/{id}/dataset` on a terminal run writes the shards, the
   manifest and the card under `datasets/<run-id>/` as `Artifact` rows and
   answers a 202 handle; a second call answers the existing manifest. **Holds**
   (`tests/ml/test_interop_export.py`, `tests/e2e/test_ml_interop.py`).
2. `GET /v1/datasets/{id}` returns the manifest as `application/ld+json`,
   digest-checked. **Holds.**
3. The manifest cites every shard by sha256, its own sha256 is the version,
   and it carries provenance, library versions, limitations and the ATLAS
   techniques exercised; a projection that disagrees with the flip matrix is
   refused. **Holds.**
4. A partner team's Parquet slice registers with static checks in the API and
   the parse in the sandbox child, is refused without a licence, and binds to
   an upload and a campaign. **Holds at admission; open in the worker parent**
   (4.3).
5. Every new finding carries its ATLAS technique, the attack catalog exposes
   it, and a campaign has a number-free coverage view. **Holds.**
6. The Foundry push is opt-in, off by default, admin-gated, holds no standing
   credential, and nothing leaves without its subscores, denominators, eps
   grid, `settings_hash` and grade sentence. **Holds against the fake server**;
   a real non-operational instance is the owner's call (INTEROP-26).
7. Lattice is text only. **Holds** (D3).
8. The default and `ml` tiers pass on the interop files and `mkdocs build
   --strict` is clean. **Holds at `703f8f6`** (`tests/ml/` counts in
   `docs/dev/testing.md`).

## 9. Divergences recorded (plan 01 section 8 protocol)

Listed with the others in `docs/architecture/ml-vertical.md` "Accepted
divergences": the Foundry switch is the URL plus the attestation variable
(spec 27.3's last sentence made checkable); `fixture_not_exportable` at 422
(register INTEROP-03 wrote 409); no `export_blocked_pending_d006` code because
imagery exports stay in the artifacts bucket (INTEROP-34); no `include_card`
flag (the card is always written); `export_unavailable` instead of
regenerate-in-child (INTEROP-07); the manifest built without `mlcroissant`
(INTEROP-05); the `batch_id` overlay on `GET /v1/runs/{id}/campaign` rather
than a schema field (BULK-02); a text or detection export carried the
adversarial family only between the B3 push and the B4 fix pass (INTEROP-04,
closed).

## Appendix: optional ATLAS case-study export (documented, not built)

A program may contribute a sanitized case study to the MITRE ATLAS community.
The export would be one JSON document per run holding the technique ids from
the coverage view, the attack ids and families from the record, the summary
measurements (accuracy drop and flip rate with denominators, no raw data), the
MRI with its five subscores and the grade sentence when a score exists, and the
standing limitations. It carries no tensors and no dataset payload, only the
technique-to-outcome narrative. Building an exporter is a follow-on, not part
of any Phase B wave.
