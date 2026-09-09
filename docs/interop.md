# Interoperability (Phase B wave B3)

Status as of 2026-09-09: wave B3 of the [Phase B plan](plans/12-phase-b-plan.md)
is on the tree (six commits, `feat(interop): Croissant/Parquet dataset export
of a campaign run` through `fix: integrate Phase B wave B3 tracks`), and every
statement on this page was read from those commits (`redsim/ml/interop/`,
`redsim/ml/atlas.py`, `redsim/integrations/`, `redsim/services/ml_datasets.py`,
`redsim/services/ml_datasets_export.py`, `redsim/workers/tasks/{dataset_export,
dataset_validate,integration_push}.py`, `redsim/api/v1/{datasets,integrations,
attacks}.py` and their tests), not from the writers' reports. The design is
section 27 of the
[product spec](superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md)
(the plan-07 file predates it and keeps a banner saying so). The route
contracts are in the [API reference](api/v1.md#dataset-export); this page is
the narrative: what leaves the platform, what enters it, and the rules both
directions obey. Everything here is opt-in and off by default (spec 27 rule
1). The end-to-end evidence for the round trip is wave B4's
`tests/e2e/test_ml_interop.py` (the export and its shards, a consumed slice
registered and validated through the real child, the ATLAS tags and coverage,
the fake Foundry push, `redsim audit verify --all` over the lot); at the B4
push five of its six cases hold and the consumed slice bound to a campaign
fails by attribution (see "Consume" below). `tests/ml/` proves each piece in
isolation.

## Contribute: a run's adversarial examples as a Croissant dataset

`POST /v1/runs/{run_id}/dataset` (membership, `dataset.export`, remediator)
turns one terminal campaign or verify run into an open, content-addressed
dataset. The admission (`redsim/services/ml_datasets_export.py::admit_export`)
writes the `dataset.export` audit row before the follow-up `Run` (scanner
`ml.dataset_export`) and `Job` (type `dataset.export`) exist and before the
enqueue on `redsim.dataset_export` (queue `scans`, set at enqueue). It refuses,
before any row, a run that is not an ML campaign or not terminal or retained no
adversarial slice (`409 export_unavailable` with the reason), a fixture-only or
partial run (`422 fixture_not_exportable`, D3), a second export while one is
queued or running (`409 export_in_flight`), and a broker outage (`503
queue_unavailable`, the two rows rolled back). One export per run: a second
call after the first completed answers the existing manifest (`status:
"exists"` with `manifest_artifact_id` and `manifest_sha256`), never a second
copy. A verify run exports with its `baseline_run_id` carried in the
provenance and is never merged with its baseline.

The worker (`redsim/workers/tasks/dataset_export.py`) loads the source run's
persisted slices (`ml.adv_slice`, and `ml.clean_slice` / `ml.control_slice`
where the run wrote them) and its `ml.flip_matrix`, and builds:

- **Parquet shards** (`redsim/ml/interop/parquet.py`), one per (attack, ε) for
  the adversarial family plus the control family and the clean slice when
  those slices exist. One fixed nullable Arrow schema for every family:
  `family`, `attack`, `eps`, `norm`, `sample_index`, `true_label`, `flipped`,
  `y_pred_clean`, `y_pred_adv`, `conf_clean`, `conf_adv`, `input`,
  `dataset_id`, `dataset_revision`, `run_id`. Rows are sorted by
  `sample_index` and written with a pinned writer configuration so the bytes
  are byte-identical for the same slice, and the shard's sha256 is its content
  id. `input` is always a numeric feature vector or a flattened tensor; a URL
  string never leaves (the tabular demo's rows are the 16 lexical features).
- **The projection-equality guard** (`croissant.py::check_projection`): every
  adversarial row's `flipped` must equal the run's `ml.flip_matrix` entry,
  computed from the retained per-sample predictions when a slice carries them
  (so the guard is a real cross-check) and taken from the flip matrix
  otherwise. A disagreement is `ExportMismatch`: the job fails, a
  `success=False` `dataset.export.execute` row records it, and nothing is
  written. The export refuses to ship labels that are not the record's.
- **The Croissant manifest** (`croissant.py`): an MLCommons Croissant 1.0
  document (`@context`, `conformsTo`, `name`, `description`, `license`,
  `version`, `distribution` of `FileObject`s with `sha256` and `contentSize`,
  one `RecordSet` per family with typed fields) plus a `redsim:provenance`
  block (model and settings digests, the source dataset id, revision and
  licence with the coverage caveat, the frozen campaign configuration, the
  run's limitations verbatim, the ATLAS technique per attack through
  `redsim.ml.atlas.technique_for_attack` with `atlas_data` as the fallback,
  the ATLAS release, and `baseline_run_id` for a verify run). The manifest's
  own sha256 is the dataset version. `croissant_validate` is the structural
  gate and also refuses banned tokens: no model or tensor file name, no
  `reviewer_notes`, no credential environment name, and no bare MRI (a
  number or grade without its subscores, denominators, grid and
  `settings_hash`, D9).
- **The dataset card** (`card.py::render_card`): a Hugging Face style Markdown
  card rendered by a template over the manifest and the limitations, with the
  "evidence, not a readiness statement" footer. Never written by the LLM
  narrator (spec 27 rule 2).

The files land under `datasets/<source-run-id>/` as `Artifact` rows on the
source run with kinds `ml.dataset.manifest`, `ml.dataset.parquet` and
`ml.dataset.card`; `GET /v1/datasets/{run_id}` serves the digest-checked
manifest as `application/ld+json` (`404` until an export exists). The
`dataset.export.execute` row carries the manifest sha256, the file count, the
byte total and the prefix, ids, digests and counts only, then `job.complete`
closes the follow-up run's chain.

What a live export contains today (INTEROP-04, closed by the B3 reconcile
pass): the classification runner (image and tabular) writes, under the
`REDSIM_ML_MAX_ADV_ARTIFACT_MB` cap, `clean_slice.npz` after the clean
evaluation (`x`, `indices`, `y`, `y_pred_clean`, `conf_clean`),
`adv_slice/<attack>_<eps>.npz` per attack row and `control_slice/<eps>.npz` per
control row, each carrying `y_pred_clean`, `y_pred_adv`, `conf_clean` and
`conf_adv` (confidence is the probability of the predicted class). Every slice
is self-describing: zero-dimensional `family`, `attack` and `eps` keys are
embedded in the archive, so the exporter labels a slice from its bytes and no
longer depends on the blob store keeping a file name (the default
`FilesystemBlobStore` stores by digest, so the location carries none). A slice
over the cap is noted on its measurement row, never faked. A live export of a
classification run therefore yields clean, adversarial and control shards with
populated prediction columns; the text and detection runners still persist
only their own `adv_slice` formats, so the export skips a non-npz slice with a
caveat and labels a legacy npz from its location only where the backend keeps
the name. Regenerating a slice in the sandbox child when none was retained
(INTEROP-07) is carried forward: the honest answer today is
`export_unavailable`, never a fabricated slice.

### The published sample

One export built with these modules from a real offline `url_trees` PGD
campaign (`run-dce555487e2b`, 200 samples) is published for other teams in
the public data repository
[IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data)
at commit `0dababc` (head on 2026-09-09) as
`data/exports/url_trees_sample/`: `croissant.json`, `README.md` (the card) and
`data/adversarial/pgd_eps0.01.parquet`, `pgd_eps0.03.parquet`,
`pgd_eps0.1.parquet`, three shards and 600 rows of 16-feature CC0-derived
vectors, no URL strings, only vocabulary URIs in the manifest. The dataset
version (the manifest sha256) is
`8a4a5dfa85faf1d2b46981afde161b734a3c001226bc7c6b462d1f43eac19406`;
`INDEX.csv` and `MANIFEST.json` record the files, digests and licence. Only
the adversarial family was retained by the source run, and the card says so,
together with the feature-space realizability caveat that every tabular row
carries. `tests/ml/fixtures/public_index.csv` still snapshots the repository's
`INDEX.csv` at `4048a209`; the live check (`REDSIM_PUBLIC_DATA_CHECK=1`)
asserts the live index covers that snapshot, so the export rows are additive
to it.

## Consume: another team's evaluation slice

`POST /v1/datasets` (multipart only; membership, `dataset.register`,
remediator) admits a Parquet evaluation slice with an optional Croissant
manifest and never parses a Parquet file in the API process. The static
checks (`redsim/services/ml_datasets.py`, stdlib only) run in this order:
`Content-Length` required (`411`) and at most `REDSIM_ML_DATASET_UPLOAD_MAX_MB`
(default 256, `413 dataset_too_large`), `project_id` from the form, JSON or
`?project=` (`422 params_out_of_range` when absent), membership and the gate,
then the body: a JSON body is `415 unsupported_dataset_format`; every part
named `file` must be Parquet (`PAR1` at both ends, never a pickle-shaped name,
non-empty); the part named `manifest` must be Croissant JSON-LD (at most 4 MiB,
an object with `@context`, a `@type` containing `sc:Dataset`, a `distribution`
list of `FileObject`s); every `contentUrl` must be a bare file name present in
the upload, so a scheme, host, slash, backslash or parent segment is `422
remote_reference_refused` naming the distribution index only (nothing is ever
fetched); a `license_statement` or the manifest's licence is required (`422
license_required`); and the schema must be declared (`422 schema_undeclared`
naming the field): `modality` `image` or `tabular`, distinct `class_names`
(a JSON or comma list, or the manifest's), `label_column` (default `label`),
for tabular the `features` (names or `{name, min, max}` objects, else the
manifest's `recordSet`), for image `input_shape` `[C, H, W]`, a `dtype` from
the allowlist (`uint8`, `float16`, `float32`, `float64`, `int32`, `int64`),
`value_range` `[min, max]` and `image_column` (default `image`). `text` and
`detection` slices are `501 not_implemented` with `phase: "B"` and the reason
(their consumed-slice loaders are not built). Every refusal writes a
`success=False` `dataset.register` row first (reason, field, counts, digests,
never a URL string or bytes) and persists nothing.

On success the service writes the `dataset.register` row, then the blobs under
`{project}/datasets/{dataset_id}/{safe name}`, then the `ml_datasets` row
(`status: validating`, `manifest_sha256` = the revision = the manifest sha256,
or the Parquet digest when no manifest was sent, the declared schema and file
digests in `detail`), an `ml.dataset_ingest` `Run` (no target) and a
`dataset.validate` `Job`, and enqueues `redsim.ml_dataset_validate` on `scans`
after the commit (a broker outage leaves the durable queued row with
`enqueued: false`). `201` answers the record projection with `ingest_run_id`,
`ingest_job_id` and `enqueued`. `GET /v1/datasets` lists the consumed rows of
the caller's memberships (or of `?project=`) after the bundled catalog, with
`consumed_count`; `GET /v1/datasets/{ds-…}` is one consumed record.

The parse happens only in the sandbox child. `redsim/workers/tasks/dataset_validate.py`
materialises the recorded blobs into the job work directory and re-hashes them
in the parent (a substituted blob is `artifact_digest_mismatch` with no child
spawned), then spawns `python -m redsim.ml.interop.consume` under the ML
sandbox's allowlisted, credential-free environment and rlimits, in its own
process group, polled for cancellation and the wall clock. The child
(`redsim/ml/interop/consume.py`, pyarrow imported inside functions only)
checks every `FileObject` sha256 against the bytes (`manifest_digest_mismatch`),
reads the Parquet in row-group batches, refuses more rows than
`REDSIM_ML_DATASET_MAX_ROWS` (default 200000, `dataset_too_large`), a missing
or non-numeric column (`schema_mismatch`), labels outside the declared class
names or index range (`class_names_mismatch`), image rows of the wrong size or
values outside the declared range and non-finite features (`schema_mismatch`),
and returns a report (`schema_version: consumed-slice-1`, rows, per-class
counts, empty classes, columns, `x_shape`, the observed range, the Parquet
metadata, digests, revision, library versions) in the sandbox envelope
shape. The worker marks the row `available` or `refused` with the child's
code (a timed-out or killed child is `sandbox_timeout` / `sandbox_killed`),
writes one `dataset.validate` audit row and the report as the
`ml.dataset_validation_report` artifact of the ingest run, then `job.complete`.
`tests/ml/test_interop_consume.py` runs the real child with
`pyarrow.parquet.ParquetFile` monkeypatched to raise in the test process,
which proves the parent never opened a Parquet file.

Parquet contract for a consumed slice: one Parquet file (a second part is
refused in this wave). Tabular: the declared numeric feature columns plus the
label column (class names or 0-based indices). Image: a binary column of raw
C-order arrays of the declared dtype at `input_shape` (or a list of numbers
per row) plus the label column. The loader returns `float32` inputs in the
declared shape and `int64` labels in the declared class order, which is what
the evaluation binding consumes.

Binding a consumed slice to a model or a campaign (INTEROP-16) is built on the
service side (`resolve_consumed_slice`, `consumed_dataset_binding` returning a
`DatasetBinding` with `split: eval`, the Parquet location and the manifest
digest as the revision; `load_consumed_slice` on the worker). The campaign
admission calls it since the B3 reconcile pass: a `dataset_id` matching
`ds-<hex>` must resolve to an `available` slice of the project (else
`422 dataset_incompatible` naming why, field `dataset_id`, `dataset_role`
`consumed`) and match the campaign modality; `dataset_revision` defaults to
the slice's manifest digest; the admitted `attack.run` row and every refusal
carry `dataset_id` and `dataset_role`. Since wave B4 the upload admission
(`services/ml_models.py::check_upload_dataset`, falling back to
`consumed_upload_binding` for a `ds-…` id: an `available` slice of the
project, split `eval` only) binds a consumed slice too, and the worker's
target loader (`ml/targets/artifact.py::consumed_eval_slice`) reads a slice
the worker parent materialised into the job work directory
(`services/ml_models.py::materialize_consumed_slice` writes the
`target_detail["consumed_slice"]` block: file, sha256, the declared schema,
class names, revision, row cap), re-checks its digest and reads it with the
same `load_consumed_slice` the parse child used, scaling image rows onto
[0, 1] from the declared range. What stays open is the one call in the worker
parent (`redsim/workers/tasks/ml_model.py` and `ml_campaign.py`) that writes
that block when the manifest's `dataset_id` is a `ds-…` id, so a campaign on
a consumed-bound model does not run end to end yet;
`tests/e2e/test_ml_interop.py::test_consumed_slice_binds_a_model_and_a_campaign`
fails with that attribution.

### Contribute a model (walkthrough, no code)

Another team's classifier enters the same way an uploaded model always has:
`POST /v1/models` multipart with `source: upload`, `declared_format: onnx` (or
a PyTorch `state_dict` with an allowlisted `architecture`), a
`license_statement`, the `modality`, `class_names` and the `dataset_id` the
model is evaluated on (a bundled id today; a consumed `ds-…` id once the
INTEROP-16 hook lands). Pickles are refused at the door (`415 pickle_refused`)
and the bytes are opened only in the sandbox child by
`redsim.ml_model_validate`, which records the ONNX to torch conversion and its
argmax agreement in the validation report. Then `POST /v1/models/{id}/attacks`
runs a campaign like any bundled target, and `POST /v1/runs/{id}/dataset`
exports its adversarial examples back out. Operator rule (register risk): a
consumed slice used in any demo is published to the public data repository
by the operator before use; the `public` flag on the upload is declared, not
verified.

## ATLAS: technique stamping and the coverage view

`redsim/ml/atlas.py` (imports `atlas_data` and the schema only) carries the
per-attack stamp `STAMP_TECHNIQUE_IDS`, checked at import against the vendored
`atlas_data.ATTACK_TECHNIQUE_IDS` (ATLAS `v2026.08`): `fgsm`, `pgd`, `cw_l2`,
`deepfool` and the tabular surrogate-transfer PGD stamp `AML.T0043 Craft
Adversarial Data`; `hopskipjump` and `zoo` stamp `AML.T0040` (the 2026.08 name
"AI Model Inference API Access", the earlier "ML Model Inference API Access"
recognised through `ATLAS_PRIOR_NAMES` so stored findings are never
rewritten); `word_substitution` and `dpatch` stamp `AML.T0043` because the
release has no text- or patch-specific technique among the vendored ids (the
reason is on the row, adding one is an `atlas_data` change, never a guess);
`label_flip_poisoning` and `backdoor_poisoning` map to `AML.T0020` and are
reserved for the data-poisoning package F; controls and unknown ids stamp
`None`. Since B3 `services.ml_findings.build_finding_detail` writes the
technique into `Finding.schema_blob.ml.atlas_technique` on every new ML
finding (findings written before stay `None`), and `GET /v1/attacks` adds
`atlas_technique`, `atlas_techniques` (every attributed technique with its
parent) and `atlas_reason` to each catalog row plus an `atlas` release
citation on the response; the frozen `AttackInfo` gains no field.

`GET /v1/runs/{run_id}/atlas-coverage` (membership) is the per-campaign view
of spec 27.2: `exercised` (declared attacks with an evasion measurement row),
`declared_not_run` (with the `not_run` reason from the record), the catalog
attacks outside the declared set, the controls (technique `None` with the
control reason), `techniques_exercised`, the release citation, the coverage
statement and the stored-name note. The view carries no `int` or `float`
anywhere and refuses to build if one appears: coverage is membership, never
a score. `404` without a campaign record, `409 llm_target_required` for a
probe run, `409 score_unavailable` with `artifact_digest_mismatch` when the
record bytes disagree with the artifact row.

## Foundry: the scorecard push

`redsim/integrations/foundry.py` and `redsim/integrations/__init__.py` (the
admission boundary; the track has no services file) implement the one
outbound integration, off by default:

- **Settings** are read from the process environment only, never `.env`.
  `REDSIM_INTEGRATION_FOUNDRY_URL` unset means disabled (the default). A set
  URL must pass the wave B0 egress rules (`https` except loopback, no
  userinfo, query or fragment, host in the target allowlist) and the
  deployment must carry the spec 27.3 operator attestation
  `REDSIM_INTEGRATION_FOUNDRY_NON_OPERATIONAL=1` (D3); optional
  `REDSIM_INTEGRATION_FOUNDRY_DATASET_RID` (a validated rid shape, never a
  URL) and `REDSIM_INTEGRATION_FOUNDRY_TIMEOUT_S` (30). A failed rule is
  `FoundryMisconfigured` naming the variable and the rule, never the value.
  No token variable exists: the bearer token comes from an `AuthProfile`
  named at push time and is decrypted in the worker only for the push.
- **The roster**, `GET /v1/integrations` (authenticated): `foundry` as
  `disabled`, `misconfigured` (with the rule) or `configured`, booleans
  `host_configured`, `target_ref_configured`, `attested`, the route, the gate
  and the setting names, never a host, URL, rid or token; `lattice` as the
  text-only entry below.
- **The payload**, `build_scorecard_payload(record)`: one row per (attack, ε)
  `MRIInputRow` carrying `n`, `n_correct_clean`, the measured metrics, the
  five subscores, `mri`, `grade`, the grade sentence, `settings_hash` and the
  ATLAS technique, plus the scorecard block, the per-family table with
  denominators, the ε curve, the limitations verbatim, a provenance subset
  (versions, dataset identity, digests) and the target and dataset identity.
  Recommendations, interpretation text, artifact locations and every Pythia
  setting are left out by construction.
- **The payload guard**, `validate_push_payload` / `assert_push_payload`: any
  mapping naming `mri` or `grade` must carry the five-key subscores, the
  grade sentence, `settings_hash`, an ε grid or point and denominators (D9);
  grade without MRI and MRI without grade are refused; forbidden keys
  (`expected_gain`, `reviewer_notes`, actor and email keys, `model_bytes`,
  `state_dict`, URL and host keys), credential-shaped keys, URL strings,
  JWT-shaped or `Bearer` values, `pk_` and other token shapes, model or
  tensor file names, raw bytes, oversized or base64 blobs and the banned
  readiness words are refused wherever they appear. `scrub_detail` redacts
  JWT-shaped tokens, `Bearer` values, `token=` / `authorization=` markers and
  URL strings from every audit row the track writes.
- **The client**, `FoundryClient`, speaks the public Foundry Datasets v2 flow
  over httpx with the Pythia truststore TLS helper (plaintext only for a
  loopback host): create an `APPEND` transaction, upload
  `redsim/scorecards/<run_id>/scorecard.json` and `rows.jsonl`, commit, abort
  best-effort on failure. Any 4xx, 5xx or transport error is
  `FoundryPushFailed(step, http_status, error_class, aborted)` with no URL or
  body in the message. A real instance whose REST shape differs is a change
  inside that one class (spec 25 risk).
- **Admission**, `POST /v1/runs/{run_id}/integrations/foundry`
  (`integration.push`, admin; body `{auth_profile_id, target_ref?, payload:
  "scorecard"}`): `501 integration_disabled` with `reason` `disabled` or
  `misconfigured` (and the rule) while Foundry is unset or refused; `409
  llm_target_required` for a probe run, `409 campaign_not_terminal`, `409
  score_unavailable` (`reasons: [no_run_record]`), `409 job_in_flight` per
  (campaign run, foundry); `422 fixture_not_exportable` when the target or the
  frozen snapshot flags a fixture (D3), `422 params_out_of_range` for a
  malformed `target_ref` or none anywhere, `422 auth_profile_kind_unsupported`
  for a non-bearer profile; `404` for an unknown run, a run without a
  campaign row, or a profile outside the project; `503 queue_unavailable`
  with the two rows rolled back. Every refusal after the lookup is a
  `success=False` `integration.push` row on the campaign run's chain. On
  admission the `integration.push` row (with the Foundry host as `target` and
  the allowlist verdict) opens the follow-up run's chain, then the `Run`
  (scanner `ml.integration_push`, `parent_run_id` the campaign) and `Job`
  (type `integration.push`, detail without a credential) are written and
  `redsim.integration_push` is enqueued on `default`. `202` with `run_id`,
  `job_ids`, `status_url`, `integration`, `campaign_run_id`, `target_ref`,
  `kind`.
- **The worker task**, `redsim.integration_push` (queue `default`, the one
  pool with egress, `max_retries=0`): re-reads the settings on the worker
  (nothing is assumed from admission), loads the run record with its digest
  checked against the artifact row and the admission-time digest, refuses a
  fixture-flagged record, builds and guards the payload, stores the exact
  bytes that leave as `ml.integration.payload` and `ml.integration.rows`
  artifacts first, decrypts the bearer token only then, pushes, stores the
  receipt as `ml.integration.receipt`, and writes `integration.push.execute`
  (host, dataset rid, transaction rid, payload, rows and record sha256,
  HTTP statuses, file count, bytes, outcome; on failure `step`,
  `http_status`, `error_class`, `transaction_aborted`, `success=False`, and
  the job fails without a retry) and `job.complete`. The chain of a push
  reads `[integration.push, integration.push.execute, job.complete]`.

The push is proven against `tests/ml/fake_foundry_server.py` (a stdlib server
speaking the v2 create, upload, commit and abort paths with a bearer check and
a low-entropy JWT-shaped fake token assembled from three segments so no JWT
literal sits in the source): the happy path, a 503 on commit with the abort,
the fail-closed cases, and no token, JWT or URL in any audit row. No push to a
real Foundry instance has been made (INTEROP-26: it needs an operator-configured
non-operational instance), and the adversarial-dataset push "when exported"
(the second half of INTEROP-23) is not built: `PUSH_PAYLOADS` is `("scorecard",)`
and the roster says so.

## Lattice: text only

Anduril Lattice is an operating-picture platform. The D3 bound and the
constitution's Principle II state "no mission-system connections", so under
the decisions of 2026-09-08 this integration cannot be enabled. It stays text
only (spec 27.3, owner decision INTEROP-27 / TESTS_DOCS-41): the roster's
`lattice` entry is `not_implemented` with `phase: "B"`, that reason, the
decision reference and the payload a push would carry if it ever existed
(beside the number and grade: the five subscores with denominators, the ε grid
points, `settings_hash`, `computed_at`, the grade sentence and a link to the
full scorecard, D9). No setting, route, task or client exists, and none is
written until an explicit product-owner decision and a constitution amendment
proposal say otherwise.

## Rules both directions obey

- Audit-first. Every admission writes its row before any `Run`, `Job` or
  blob exists and before Celery is touched; every refusal is a `success=False`
  row with ids, codes, digests and counts, never a URL string, a key or bytes.
- Nothing is faked. A slice that was not retained is `export_unavailable`;
  a Parquet file the child cannot parse is a refused dataset with the child's
  code; a Foundry instance that is not configured is `integration_disabled`;
  Lattice is text.
- No bare MRI leaves. The manifest validator, the card template and the push
  guard all refuse a number or grade without the five subscores, the
  denominators, the ε grid and `settings_hash` (D9).
- The API process imports no ML library: the Parquet writer runs in the
  export task, the Parquet reader in the sandbox child, and
  `tests/test_api_process_has_no_ml.py` blocks `pyarrow` and `mlcroissant`
  while building the app.
- Off by default. An export exists only when a member asks for it, a consumed
  slice only when a remediator uploads one, a push only when an admin names a
  profile against a configured, attested, allowlisted Foundry host.

## Closed in wave B4, and what stays open

Closed by the wave B4 fix pass, read from the tree: the text and detection
runners write the same self-describing slices as the classification runner
(`redsim/ml/runners/base.py::slice_bytes`; INTEROP-04 for every runner), and
the export schema gained a nullable `text` column that only a text slice fills
(a text model has no numeric input tensor, so `input` is null on its rows) and
labels a detection export's `flipped` column from the flip matrix; the
INTEROP-16 binding at upload and in the target loader; the JWT pattern in
`redsim/audit/redact.py` and the Foundry header names (INTEROP-28); the ATLAS
stamp on analyst drafts (INTEROP-18); the `interop` block on
`GET /v1/ml/capabilities` and the `.env.example` and compose pass-through of
the Foundry and capacity variables, the Foundry settings scoped to
`redsim-worker-default` (INTEROP-29, BULK-23); the e2e round trip
`tests/e2e/test_ml_interop.py` with the `make check-phase-b` gate and the
docs-consistency test.

Still open, recorded in the README: the worker-parent
`materialize_consumed_slice` call (INTEROP-16 remainder, above); the
`atlas_technique_id` key on finding list rows (the tag is in every finding's
`schema_blob.ml.atlas_technique`); regenerate-in-child for a run whose slices
were not retained (INTEROP-07, `export_unavailable` instead); the dataset push
to Foundry (INTEROP-23, `PUSH_PAYLOADS` is `("scorecard",)`); a push against a
real non-operational instance (INTEROP-26, the owner's call); and the
public-index fixture `tests/ml/fixtures/public_index.csv`, which snapshots the
repository's `INDEX.csv` at `4048a209`, before the export rows.
