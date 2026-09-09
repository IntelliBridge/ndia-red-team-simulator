# Testing

For the contributor workflow (how to install extras and what must stay green
on every PR), see
[`CONTRIBUTING.md`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/CONTRIBUTING.md)
under "Run the test suite". This page documents the shared test plumbing, the
test tiers and the CI split. The test plan for the ML vertical is section 22
of the [product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md);
the Phase B additions to it are plan 12
([`docs/plans/12-phase-b-plan.md`](../plans/12-phase-b-plan.md)) sections 5
and 6.

## Running

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider                          # default tier: 2257 passed, 35 skipped, 1 deselected at 1439f92 (2:03 with the ml extra)
.venv/bin/python -m pytest -q -p no:cacheprovider -m ml                    # only the ml-marked tests: 418 passed, 1 skipped at 1439f92
REDSIM_E2E=1 .venv/bin/python -m pytest -q -p no:cacheprovider -m e2e tests/e2e   # e2e tier: 22 passed at 1439f92 (2:30, Postgres lane on)
.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests          # garak tier: the 12 garak-marked tests of wave B2 (needs the garak extra)
.venv/bin/python -m pytest -q -p no:cacheprovider tests/ml/test_interop_export.py tests/ml/test_interop_consume.py \
  tests/ml/test_atlas_foundry.py tests/ml/test_batches.py tests/ml/test_bulk_upload_capacity.py tests/ml/test_cli_matrix.py   # wave B3 writers' files: 140 passed, 1 skipped in the B3 worktree at a780d88
.venv/bin/python -m pytest -q -p no:cacheprovider tests/ml/test_phase_b_stubs.py   # the Phase B surface pin: 61 passed at the B3 integration
.venv/bin/python -m pytest -q --cov=redsim --cov-report=term | tail -5
```

The counts are the wave B1 integration run at `main` `1439f92` (2026-09-09),
not CI results, and they move with every wave: re-run before quoting them.
Wave B2's own checks before its rebase (a worktree on `b404eb8`): ruff and
`mypy redsim` (236 files) clean, 251 passed and 1 xfailed in its writers' ten
test files, the full default tier 2431 passed, 36 skipped, 12 deselected,
1 xfailed with 17 failures that were all present at that base and fixed on
`main` by the B1 integration; the 11 `garak`-marked tests passed with garak
0.16.0. The B2 integration pass (`fix: integrate Phase B wave B2`, pushed with the B2 commits) re-ran every tier on the rebased tree from the venv: ruff (CI selection) and `mypy redsim` (236 files) clean, the default tier 2480 passed, 35 skipped, 13 deselected, the `ml` tier 420 passed, 1 skipped, the 12 `garak`-marked tests green against the fake gateway, the e2e tier 22 passed against Postgres with the sandbox child, `mkdocs build --strict` exit 0.
Wave B3's checks are the B3 assembler's, in its worktree on the B2
integration (`wt/waveb3`, head `a780d88` before its last two commits and the
rebase): ruff and `mypy redsim` (253 files) clean, the six writers' test
files 140 passed and 1 skipped (`test_manifest_route_serves_ld_json_after_an_export`,
skipped by design: it needs a run with persisted slices, the e2e tier), the
rewritten `tests/ml/test_phase_b_stubs.py` 61 passed, the e2e smoke file 8
passed through the real child (run by the `bulk-service-routes` writer with
the `batch_id` mirror). Final counts at the B3 integration on the rebased tree (the reconcile pass, run from the repository root): `ruff check --select E4,E7,E9,F,I redsim tests` clean, `mypy redsim` clean (253 source files), the default tier `pytest -q -p no:cacheprovider --ignore=tests/e2e` 2634 passed, 35 skipped, 13 deselected (the `test_campaign_golden` artifact pin now excludes the Phase B export slices, `test_cli_ml` pins the `l2` default `pgd`; the `test_campaign` harden-hook and `test_datasets` synonyms failures of the B2 tree are not present), the `ml` tier 433 passed and 1 skipped, the `garak` tier 12 passed, the `e2e` tier against the compose Postgres 22 passed, `mkdocs build --strict` exit 0. The venv was
created with uv and has no `pip`, so always run through
`.venv/bin/python -m …`. The default `-m` from `addopts` in `pyproject.toml`
excludes `docker`, `e2e`, `slow`, `auth_required` and `garak`. The wave B2
tests need `reportlab` (worker extra) and `pypdf` (test extra); the wave B3
export and consume tests need `pyarrow` (ml extra) and are `ml`-marked, and
`tests/ml/test_cli_matrix.py` carries one `ml`-marked real-child matrix run.

## Test tiers

| Tier | Selected by | What it proves | Where it runs |
|---|---|---|---|
| default (unit and integration) | no `-m` flag (`addopts`) | pure-Python units plus the sqlite-harness integration tests, including every `ml`-marked test when the extra is installed | both unit lanes (3.13 without `ml`), Coverage gate, API integration (without `ml`) |
| `ml` | `-m ml`, needs the `ml` extra | the vertical's library layer: targets, attacks, runners, explainers, defenses, sandbox child, endpoint broker, hardening, since wave B2 the endpoint registration and validate path, the Phase B admission rules, the worker's broker lifecycle and derived-target registration, the review workflow, the PDF and snapshot path (`tests/ml/test_endpoint_routes.py`, `test_admission_phase_b.py`, `test_tasks_phase_b.py`, `test_review_workflow.py`, `test_reports_phase_b.py`, `test_llm_routes.py`, `test_llm_core.py` default-tier cases), and since wave B3 the Croissant export against a TinyTarget-shaped run with eager Celery (`test_interop_export.py`: a valid manifest whose FileObject digests and shard columns check out, rows equal to the flip matrix, a mutated row refused with a failed job and no artifacts, idempotent re-export, the refusals, a fixture never exported, the template-only card), the consumed-slice admission and the real parse child (`test_interop_consume.py`: 25 static refusals audited and persisting nothing, the size cap, the child's digest, class, range and row-cap refusals, a substituted blob refused in the parent, the child spawned credential-free, the API and worker modules importing with pyarrow blocked), ATLAS and Foundry (`test_atlas_foundry.py`: the stamp table against the vendored data, the number-free coverage view, the roster with no value leaking, the payload guard refusing a bare MRI and every forbidden content, admission order and the broker rollback, the happy-path push and the 503-on-commit abort against the fake server with no token, JWT or URL in any row), batches (`test_batches.py`: the roll-up vocabulary, a two-model batch through the single boundary, collected refusals, deferral through the capacity service, cancel, RBAC negatives, grouped compare, bulk verify), bulk upload and capacity (`test_bulk_upload_capacity.py`) and the CLI matrix (`test_cli_matrix.py`, one real-child matrix run) | Unit tests (py3.12), Coverage gate, E2E tier |
| `e2e` | `tests/e2e/`, stamped `e2e` by its `conftest.py`, run only with `REDSIM_E2E=1` | the completion criteria end to end: real API, admission, eager Celery, the real sandbox child and the real CLI over sqlite on a synthetic asset tree; the Postgres RLS lane with `REDSIM_E2E_POSTGRES_URL`. Phase A only: the B2 and B3 scopes get their files in wave B4 (`test_ml_interop.py`, `test_ml_bulk.py` among them); the harness's `ml_campaigns` mirror carries `batch_id` since B3 | `E2E tier (python, eager Celery)` on every PR and push (wave B0), and locally. After wave B3 only the 8-case smoke file was re-run (8 passed) |
| `garak` | `-m garak`, needs the `garak` extra (`garak>=0.16,<0.17`) | the Phase B LLM domain: since wave B2, 11 tests (ten in `tests/ml/test_llm_core.py`, one in `tests/ml/test_llm_routes.py`) that run real garak 0.16.0 through `PythiaGenerator` against the in-process fake gateway `tests/ml/fake_openai_server.py`: headers, body keys and ledger against an `httpx.MockTransport`, the key-file mode check, one real child run (exit 0, counts equal garak's eval records, the hard cap, the persona on every request, no `/v1/models` call, token sums), the credential boundary (no `PYTHIA_`/`AWS_`/`KAGGLE` name in the child env, the key in no file, a DAN prompt fragment only in garak's own `report.jsonl`), the scorecard, rules and report from that run, a version mismatch (exit 3, zero requests), offline mode with HF-detector probes (all `not_run`, zero requests), the wall-clock kill, the committed catalog equal to a fresh regeneration, and the route-to-worker end-to-end case | `garak offline` on every PR and push (wave B0); the workflow still maps exit 5 to success, and whether the 11 pass on the runner is proven by the first run after the B2 push |
| browser e2e | Playwright, `workflow_dispatch` with `run_e2e=true` | the web app against the compose stack | on demand only, not part of the Phase B waves |

## Shared fixtures (`tests/conftest.py`)

- **`sqlite_session_factory`**: a session factory bound to a fresh in-memory
  SQLite engine with the schema created.
- **`db_session`**: a ready-to-use `Session` from that factory, rolled back
  and disposed at the end of the test.
- The `garak` skip: when `importlib.util.find_spec("garak")` is `None`, every
  `garak`-marked item is skipped at collection, so `pytest -m garak` on an
  interpreter without the extra reports skips, never errors (wave B0,
  TESTS_DOCS-01).

Use `db_session` for a single test that needs a working session, reach for
`sqlite_session_factory` when a test needs to mint several sessions itself.
`tests/conftest.py` stamps DB-touching tests with the `integration` marker so
CI can route them to the Postgres-equipped jobs. `tests/ml/conftest.py` has an
autouse fixture that keeps every ML test away from a developer's `.env`.

## Markers

| Marker | What it gates |
|---|---|
| `unit` | Pure-Python. Runs everywhere. |
| `integration` | May hit Postgres / Redis. Runs on the sqlite harness locally, against real services in the `Coverage gate` and `API integration` jobs. RLS, `FORCE ROW LEVEL SECURITY` and the tenant-drift guards are no-ops on SQLite, so those guarantees are only exercised in CI (`tests/test_tenant_rls.py`, `tests/test_migration_0011.py` skip their Postgres cases without `REDSIM_DB_URL`). |
| `ml` | Needs the `ml` extra (torch, ART, SHAP, onnxruntime, scikit-learn). Deselected on the Python 3.13 lane and in the API integration job. |
| `garak` | Needs the `garak` extra; skipped when absent (wave B0). Deselected by `addopts` and by every other lane's marker expression, so `garak` tests run only in the `garak offline` job. Stamp it (and `importorskip("garak")`) on every test that imports garak. |
| `e2e` | `tests/e2e/`, opt-in with `REDSIM_E2E=1`. |
| `docker`, `slow`, `auth_required` | Opt-in. `slow` covers the live public-data check `tests/ml/test_datasets.py::test_live_public_index_covers_the_snapshot` (`REDSIM_PUBLIC_DATA_CHECK=1`). |

Deselection happens after collection, so an `ml` test module must still
import cleanly without the extra. Put `pytest.importorskip("torch")` at module
top, or place the module under a directory whose `conftest.py` skips when the
extra is absent. A bare `import torch` in a test module fails collection on
3.13 regardless of the marker. The same holds for the `garak` marker and
`import garak`.

## ML test doubles and fixtures (`tests/ml/`)

- `fakes.py::TinyTarget` and `TinyTabularTarget`: a random-weight 1-conv net
  on 8×8×3 inputs with three synthetic classes, and a tiny tree ensemble.
  They exercise the `Target` and `AttackAdapter` protocols with no download.
- `fakes_text.py::TinyTextTarget` (wave B1): a seeded TF-IDF plus logistic
  regression on a synthetic three-topic corpus with a synonym lexicon from the
  committed fixture, and `tiny_tsv()`, an inline ham / spam corpus.
- `fakes_detection.py::TinyDetector` (wave B1): a hand-built differentiable
  colour-evidence anchor detector honouring the torchvision output and loss
  contract on 16×16 images with two classes, wrapped in ART's
  `PyTorchFasterRCNN`; a whole detection campaign runs in about 2 s.
- `tiny_endpoint_server.py::TinyEndpointServer` (wave B1): a stdlib
  `http.server` over `TinyTarget` behind `POST /predict` speaking the
  `endpoint-v1` contract with bearer or header auth and misbehaviour switches
  (see [Endpoint predict contract](../api/endpoint-contract.md)). Since wave
  B2 `tests/ml/test_endpoint_routes.py` registers it through `POST /v1/models`
  and validates it through the worker task.
- `fake_openai_server.py` (wave B2): a stdlib `ThreadingHTTPServer` on
  `127.0.0.1` with `GET /v1/models` and `POST /v1/chat/completions`, a bearer
  check (401 otherwise), persona-header and body-key recording, fixed, echo,
  empty or callable replies, usage blocks, `fail_status`, `fail_first` and
  `latency_s` switches, and a low-entropy fake token. The garak tier and the
  LLM route tests run against it; no test reaches the live gateway.
- `fake_foundry_server.py` (wave B3): a stdlib `ThreadingHTTPServer` on
  `127.0.0.1` speaking the Foundry Datasets v2 create, upload, commit and
  abort paths with a bearer check (401 otherwise), per-request records (step,
  dataset rid, file path, transaction rid, auth, content type, the raw upload
  body), `fail_at` / `fail_status` switches and the committed and aborted
  lists. `DEFAULT_TOKEN` is a low-entropy JWT-shaped fake assembled from
  three segments at import, so the redaction is exercised and no JWT literal
  sits in the source for the Aikido hook to find. `tests/ml/test_atlas_foundry.py`
  runs the push task eagerly against it; no test reaches a real Foundry
  instance (INTEROP-26).
- `fixtures/run_record.json`: the frozen `GET /v1/runs/{id}/campaign` shape
  with a full `score` block, sha256
  `e5266f1873dc3fcd0d784acf3bf9e97463595d3bbff351edf7560ca1716d9c1a`.
  `test_fixture.py` validates it and `test_schema_compat.py` pins its digest.
  Any P0 contract change goes through the change protocol in
  `docs/plans/01`, section 8.
- `fixtures/run_record_phase_b.json` (wave B0): the frozen fixture plus the
  plan 12 section 3 fields, so a partial landing of the Phase B schema shows
  up as a failure, not a skip.
- `fixtures/cifar10_test_500.npz` (pinned CIFAR-10 slice) and
  `fixtures/malicious_urls_sample.csv` (seeded stratified URL sample): the
  Phase A CI fixtures.
- `fixtures/sms_spam_sample.tsv` (wave B0): 300 rows, 150 per class, seed 0,
  drawn from the UCI SMS Spam Collection with the eligibility rule and source
  digests recorded in `fixtures/MANIFEST.json`. `fixtures/synonyms_tiny.json`:
  47 WordNet 3.0 entries cross-checked against nltk's reader.
  `fixtures/public_index.csv`: the byte-identical snapshot of the public data
  repository's `INDEX.csv` at commit `4048a209`.
- `_campaign_pre_refactor.py` and `test_campaign_golden.py` (wave B1): the
  pre-refactor `run_campaign` frozen byte for byte (sha256 asserted) and the
  four-scenario golden test that proves the frame-plus-runner split is
  behaviour-preserving. Delete both together once Phase B has landed and the
  golden is no longer wanted.

Fixture data never appears in the demo catalog or as a result.

## Guard tests worth knowing

- `test_api_process_has_no_ml.py`: builds the app in a subprocess with
  `torch`, `torchvision`, `art`, `onnx`, `onnxruntime`, `shap`, `sklearn`,
  `xgboost` and, since wave B0, `garak`, `openai`, `litellm`, `reportlab`,
  `pyarrow` and `mlcroissant` blocked in `sys.modules`, serves `/health`, and
  asserts `POST /v1/scans` answers 404. It also builds the sandbox child
  environment with low-entropy fake credentials in the parent environment
  and asserts none survives.
- `tests/ml/test_schema_compat.py` (wave B0): the P0 schema tripwire. The
  frozen fixture's sha256, its byte-identical round trip under
  `exclude_unset`, every P0 property present and untyped, every property
  added since P0 default-valued, sixteen P0 vocabularies never narrowed, the
  P0 stage order kept.
- `tests/ml/test_import_order.py`: imports the `datasets` and `targets`
  packages in a fresh interpreter with the ML libraries blocked in three
  orders and fails on the first cycle.
- `test_admission_audit_before_enqueue.py`: the chain row exists before the
  `Run` and `Job` rows and before Celery.
- `test_migration_0010.py` and `test_migration_0011.py`: `0010_ml_vertical`
  sits above `0009` on a single head chain, `0011_phase_b_platform` is the
  single head above `0010`, the offline SQL creates the four Phase B tables
  with RLS parity copied token for token from `0010`, and the sqlite round
  trip upgrades and downgrades cleanly.
- `test_policy_ml_actions.py`: the seven ML `Action` members, the seven
  Phase B members, their minimum roles, the `viewer` rank, and the OPA and
  Cedar mirrors parsed and asserted equal to the Python table.
- `tests/ml/test_error_codes.py`: the spec 17.3 table and both dated Phase B
  addenda (wave B0's 23 codes, wave B2's 13) parsed from the spec and matched
  against `redsim/api/errors.py` both ways, the Phase A count invariant over
  both addendum sets, the `capacity_deferred` marker semantics, and a refusal
  of the register spelling `idempotency_in_flight`.
- `tests/ml/test_phase_b_stubs.py` (rewritten by the B3 integration, 61
  cases): the Phase B surface pin now that every wave B0 stub has a real
  handler. Every B0 path and method is in the OpenAPI document; a `viewer`
  gets `403` on every gated route and the same answer as an admin on the
  reads its membership admits; a non-member is refused before the handler
  wherever a project resolves; an unknown run, model, finding, dataset or
  batch is `404`; a batch, bulk or dataset body without `project_id` is `422
  params_out_of_range`; on a seeded harness whose finished run retained no
  slices, record or `ml_campaigns` row every write route answers its typed
  refusal (`409 export_unavailable`, `415 unsupported_dataset_format`, `422
  params_out_of_range` / `batch_member_refused`, `404` for the manifest, the
  coverage view and an unknown batch, `200` for the roster, the batch list
  and capacity), never `501 not_implemented`; refusals create no `Run`,
  `Job`, `Target` or `Finding` and every audit row they write is
  `success=False` or the `batch.create` admission row that precedes its
  members' refusals. Its fixture carries the sqlite `ml_campaigns` mirror
  with `batch_id`. The one `not_implemented` left on the Phase B surface by
  design is the Lattice entry of the integrations roster; `report.pdf` stays
  pinned as `404 report not yet rendered`.
- `tests/ml/test_interop_consume.py::test_api_service_and_worker_modules_import_with_pyarrow_blocked`
  and the happy-path cases that monkeypatch `pyarrow.parquet.ParquetFile` to
  raise in the test process (wave B3): the API and worker modules import
  without pyarrow and the parent never opens a Parquet file, only the sandbox
  child does. `test_child_is_spawned_credential_free_under_the_ml_sandbox`
  asserts no `PYTHIA_`, `AWS_`, `KAGGLE`, `REDSIM_AUTH` or `REDSIM_DB` name
  and no proxy reaches the parse child;
  `tests/ml/test_atlas_foundry.py::test_sandbox_child_env_drops_every_foundry_setting`
  does the same for `REDSIM_INTEGRATION_FOUNDRY_*`.
- `tests/ml/test_atlas_foundry.py::test_payload_guard_refuses_bare_mri_and_every_forbidden_content`
  (wave B3): the D9 guard on anything that leaves for Foundry (a bare MRI, a
  grade without MRI, a URL string, a JWT-shaped or `pk_` value, a `token`
  key, a model file name, raw bytes, a base64 blob, a readiness word,
  `expected_gain`, `reviewer_notes`, `requested_by`, empty rows or
  limitations, a missing subscore); `test_stamp_table_agrees_with_the_vendored_atlas_data`
  keeps `redsim/ml/atlas.py` and `atlas_data.py` in step;
  `test_coverage_lists_membership_without_a_single_number` pins the
  number-free coverage view.
- `tests/test_worker_hardening.py::TestQueueRouting`: the routed-set pin is
  the nine `task_routes` entries; the four B3 tasks register through the
  Celery `include` list with their queue on the decorator or at enqueue, so
  the pin held without an edit.
- `tests/test_idempotency.py` (wave B2): the `Idempotency-Key` middleware
  replays a stored 2xx with `Idempotency-Replayed: true` and no second row or
  enqueue, refuses a reused key with a different body
  (`idempotency_key_reused`) and an open reservation
  (`idempotency_conflict`), and passes through without the header.
- `tests/test_policy_ml_actions.py` and `tests/test_policy_engine.py`: since
  wave B2 the `dataset.export` bar is `remediator` in the Python table and
  both mirrors.
- **e2e pins moved by the B2 integration.** `tests/e2e/test_ml_governance.py`
  and `tests/e2e/test_ml_verify_upload_reports.py::test_reports_sections_and_pdf_404`
  now assert `report.pdf` is `404 report not yet rendered` before a render, a
  `source: endpoint` body without `auth_profile_id` is `422
  auth_profile_required` with the host-only refusal row, and the campaign
  projection's `weights` / `non_default_weights` keys are allowed beside the
  record. The e2e tier is 22 passed on the integrated tree.
- `test_llm_pythia.py` and `test_pythia_check.py`: the Pythia client and the
  connectivity check against an `httpx.MockTransport`, including `.env`
  discovery isolated from a developer's real `.env`.
- The engine-unavailable paths (`test_cli_commands_coverage.py`,
  `test_m6_dispatch.py`, `test_api_routes_coverage.py`, `test_doctor.py`) pin
  the explicit failure of the removed pentest seams, so a faked empty result
  fails the suite.

## CI split

The full description is [CI pipeline](ci.md).

- `Unit tests (py3.12)` and `(py3.13)`: install `.[api,worker,test,dev]`
  (plus `ml` with CPU torch on 3.12), run ruff and mypy, then pytest with
  `not integration and not docker and not e2e and not slow and not
  auth_required and not garak` (3.13 adds `and not ml`). No Postgres or
  Redis.
- `Coverage gate`: the full default suite against Postgres 16 and Redis 7,
  `alembic upgrade head` first, `--cov-fail-under=81`.
- `API integration (Postgres + Redis)`: `.[api,worker,test]`, migrations,
  then `pytest -m "not e2e and not docker and not slow and not auth_required
  and not ml and not garak" tests/`.
- `E2E tier (python, eager Celery)` (wave B0): `REDSIM_E2E=1 pytest -m e2e
  tests/e2e` with the migrated service Postgres as
  `REDSIM_E2E_POSTGRES_URL`, so the RLS lane runs.
- `garak offline` (wave B0): `.[garak]` on CPU torch, `import garak`, then
  `pytest -m garak tests`; the workflow still maps exit 5 to success, and
  since wave B2 the lane collects 12 tests (11 from the B2 tracks, one probe-route case added by the integration).
- `Stack E2E (Playwright)`: only via `workflow_dispatch` with `run_e2e=true`,
  brings the compose stack up and runs `web/tests`.

The default `pytest -q` stays green with no services and no live LLM.
