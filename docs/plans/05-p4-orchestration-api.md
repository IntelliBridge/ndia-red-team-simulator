# Phase P4 · Milestones M1-M6 · Feature F004 (v2, redsim substrate)

Status: v2, 2026-09-08. Owner: backend lead (WS4). Waves: Slice 1 scaffold,
Slice 2 complete. This phase is the integration spine of the ML vertical.

Read these first, in order:

1. `docs/plans/00-master-plan.md` sections 2, 5, 7.
2. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`
   sections 6, 10, 17.
3. `specs/004-run-management/spec.md`.

P4 wires the redsim platform so a user starts an attack campaign and watches it
finish. It owns the new HTTP routers, the campaign admission service, and the
Celery tasks that run the pipeline. It consumes the target, attack, explain, and
scoring modules from P1, P2, and P3. It writes no state to disk. All state lives
in Postgres (`runs`, `jobs`, `findings`, `artifacts`, `ml_campaigns`), in the
blob store (S3/MinIO), and on the hash-chained audit log.

The v1 standalone `redsim/` package is gone: no `redsim/runs.py`, no
`redsim/jobs.py`, no thread pool, no `run.json`, and no new `create_app`. The paths below are the
real redsim paths on `main`.

## Landed status (2026-09-08, `main` at `bb43bd7`)

The body below is the pre-merge plan and is kept as written. This block
records what is on `main`, what lands with wave 3, and what is still open.
Where the body and the tree disagree, the tree wins.

On `main` (PR #22 `a864da6`, completion waves 1 and 2):

- Routers mounted on `redsim/api/app.py` under `/v1`: `ml_capabilities`
  (`GET /v1/ml/capabilities`), `attacks` (`GET /v1/attacks`, `POST
  /v1/models/{id}/attacks`), `datasets` and `defenses` (`GET`), `models`,
  `artifacts` (`GET /v1/artifacts/{id}`, `GET /v1/runs/{id}/artifacts`),
  `compare` (`GET /v1/runs/{id}/campaign`, `GET /v1/runs/{id}/compare?with=`,
  `PATCH /v1/runs/{id}/reviewer-notes`), `ml_findings` (`POST
  /v1/findings/{id}/explain`, `POST /v1/findings/{id}/harden`, `PATCH
  /v1/findings/{id}/status`), `verify` (`POST /v1/findings/{id}/verify`),
  `runs_cancel` (`409 run_terminal` on a terminal run), `reports` (`GET
  /v1/runs/{id}/report.{md,json,html}`, `report.pdf` answers `501`) and
  `audit` (`GET /v1/audit/verify`, `?run=` resolved through
  `ensure_run_access`, `?all=1` answering `{"chains": [...]}`).
- `redsim/api/errors.py` is the single copy of the spec 17.3 code table and
  defines `ApiError`. Every ML route answers `{"detail": {"code", "message",
  ...}}` with a listed snake_case code and no message parsing. `GET
  /v1/ml/capabilities` reports `pickle_accepted: false`, `sandbox_enabled:
  true`, the architecture allowlist and whether Pythia is configured, never
  its URL or key.
- `redsim/services/ml_campaigns.py`: audit-first admission for `attack.run`
  and `verify.replay` (the audit row before any `Run` or `Job` row and before
  `task.delay`), the default ε grid and reference budget, `parent_run_id`
  reruns of a terminal failed or cancelled campaign with the original rows
  untouched, `503 queue_unavailable` when the enqueue fails (rows removed and
  a second `success=False` row written), `celery_task_id` stamped on the job.
- Tasks: `redsim.ml_campaign_run` and `redsim.ml_model_validate` on the
  `scans` queue (`redsim/workers/celery_app.py`), the ML branch of
  `redsim.report_render` (re-render from `ml.run_record` with the reviewer
  notes overlay after a `report.render` audit row), and the reaper calling
  `rollup_run_status`. The six task names and the per-attack chain in section
  4 of this file were not built. `explain.run`, `harden.recommend` and
  `verify.replay` are job types on `redsim.ml_campaign_run`. The divergence
  is recorded in master plan section 0 (v2.3).
- The worker emits the spec 10.5 vocabulary (`model.load`,
  `attack.execute.<id>`, `explain.execute`, `campaign.score`,
  `harden.execute`, `verify.execute`, `report.render` with `formats`,
  `job.complete`) as `worker:<job.type>` with `requested_by` in the detail,
  keeps `Run.stage_table` in the spec 6.5 shape with per-stage `failed`,
  `timed_out` and `cancelled`, publishes stage frames on the run channel, and
  maps artifact names to the spec 5.8 kinds (`ml.input.*`,
  `ml.perturbation`, `ml.shap.*`, `ml.validation_report`, `ml.curve`,
  `report.md` / `report.json` / `report.html`).
- Observability: worker OTel and structlog init with `run_id`, `job_id` and
  `project_id` bound on the log context and a `job.run` span
  (`redsim/workers/bootstrap.py`), the `stage_span` helper
  (`ml.stage.<name>`) in `redsim/observability.py`, and
  `redsim_ml_campaigns_total` incremented per outcome.
- Web contract: `web/src/lib/api.ts` and the run and finding pages were
  aligned to these routes in PR #22.

Wave 3, landing 2026-09-09: `GET /v1/attacks` loads the opt-in attack plugins.
`CampaignScannerAdapter` (`ml-campaign`, capabilities `adversarial_ml` and
`explainability`) registers on the scanner registry and appears in `GET
/v1/scanners` and `redsim doctor`. `redsim audit verify --run` gains a
`--run-dir` fallback for the offline chain, and the audit chain persists `ts`
canonically so a sqlite-backed chain verifies. Admission no longer freezes
`eps` into `attack_params`.

Still open: the web UI beyond the PR #22 contract alignment and a Playwright
browser e2e (P5), the Fargate services (P7). Phase B routes stay `501
not_implemented`.

---

## 1. Objective

Deliver the orchestration and API surface for one attack campaign against one
model, end to end, on Celery.

Concretely, deliver four things:

1. New routers under `redsim/api/v1/` (`models.py`, `attacks.py`, `datasets.py`,
   `defenses.py`, `ml_capabilities.py`, `artifacts.py`, `compare.py`,
   `ml_findings.py`), each mounted on the existing `redsim/api/app.py`
   `create_app` under `prefix="/v1"`.
2. `redsim/services/ml_campaigns.py`, an audit-first admission service that
   mirrors `redsim/services/scans.py::create_scan_job` and ends in `task.delay`.
3. The Celery tasks in `redsim/workers/tasks/` (`model_validate.py`, `attack.py`,
   `explain.py`, `harden.py`, `verify.py`, `report.py`), each wrapped by
   `redsim/workers/bootstrap.py::task_context` and writing status through
   `redsim/workers/job_state.py::set_job_status`.
4. Campaign progress through `Run.stage_table` plus the Redis run-event channel,
   and artifact streaming through `GET /v1/artifacts/{id}`.

The acceptance gate is the vertical smoke test: one image target plus FGSM plus
SHAP, from `POST /v1/models/{id}/attacks` to a `succeeded` `Run` with a scored
campaign record served at `GET /v1/runs/{id}/campaign`.

## 2. Scope

### In scope

- The new routers listed in section 1, mounted on the existing app factory.
- `redsim/services/ml_campaigns.py`: admission for `attack.run`, plus the
  follow-on admission helpers for `explain.run`, `harden.recommend`, and
  `verify.replay`. Each emits its audit event before any `Run` or `Job` row and
  before `task.delay`.
- The six Celery tasks, each built on `task_context` and the `job_state`
  machine.
- Campaign progress through `Run.stage_table` (shape fixed in spec section 6.5)
  and the `run:{run_id}:events` Redis channel via
  `redsim/workers/events.py::publish_job_event`.
- Artifact streaming through the new `GET /v1/artifacts/{id}` route, path- and
  RLS-confined.
- The `run.status` roll-up rule (spec section 6.2) evaluated by the worker at
  each job's terminal transition.
- The cancel amendment: `redsim/services/runs.py::cancel_run` rejects an
  already-terminal run with `409 run_terminal` instead of rewriting
  `Run.status`.
- Queue routing for the ML tasks and their reaper coverage.
- The pytest suite named in section 7.

### Out of scope

- Any target, attack, scoring, explain, or recommend logic. P4 consumes those
  modules from P1, P2, and P3. It does not implement them.
- The schema and migration. `RunConfig` widening, the `ml_campaigns` table, and
  `targets.detail` are WS0 (`0010_ml_vertical`, master plan section 4). P4
  assumes they exist and fills them.
- The plugin sandbox and the sandbox child (`redsim/scanners/sandbox.py`,
  `redsim/scanners/sandbox_worker.py`, and `python -m redsim.ml.sandbox_worker`).
  P4 spawns the child from inside the tasks. P1 and WS0 own the child body.
- The app factory, CORS, auth, tenant middleware, CSRF, and rate limiting. Those
  exist on `redsim/api/app.py`. P4 mounts routers into that app and touches
  nothing else.
- `/v1/scans`. It is unmounted at M0 (spec section 17.1).
- The web UI (WS5) and the report renderer body (WS6). P4 calls
  `redsim/services/reports.py::render_reports` from the `report` stage.
- Keycloak, RLS, and the audit chain themselves (F001, F008). P4 reuses them.

## 3. Prerequisites and dependencies

### Consumed from other phases

| From | Import | Used for |
|---|---|---|
| P1 | `redsim.ml.targets` registry + `targets/base.py` | resolve the `Target`, load in the sandbox child |
| P1/WS0 | `redsim.ml.sandbox_worker` (child entry) | run each stage inside the plugin sandbox |
| P2 | `redsim.ml.attacks` registry + `attacks/base.py` (`resolve_params`) | resolve the attack set, validate params |
| P2 | `redsim.ml.eval`, `redsim.ml.scoring` | measurements, MRI, severity |
| P3 | `redsim.ml.explain` (`shap_image`, `shap_tabular`) | observations, `expl_shift`, `S_expl` |
| P3 | `redsim.ml.recommend.rules`, `redsim.ml.recommend.narrative` | interpretation, candidate recommendations |
| WS0 | `redsim.ml.schema` (`RunConfig`, `RunRecord`, `Provenance`, `STAGES`, `STANDING_LIMITATIONS`) | campaign record construction |
| WS0 | migration `0010_ml_vertical` (`ml_campaigns`, `targets.detail`) | campaign persistence |
| redsim | `redsim/api/app.py::create_app` | mount point for the new routers |
| redsim | `redsim/api/auth.py::get_current_user`, `redsim/api/policy.py` (`Action`, `check`, `ensure_project_access`, `accessible_project_ids`) | auth and RBAC |
| redsim | `redsim/audit/chain.py::resolve_writer`, `redsim/safety.py::authorize` | audit-first admission |
| redsim | `redsim/workers/bootstrap.py::task_context`, `redsim/workers/job_state.py::set_job_status` | execution wrapper, status machine |
| redsim | `redsim/workers/events.py::publish_job_event` | live stage and job events |
| redsim | `redsim/storage` blob store, `redsim/db/models.py` (`Run`, `Job`, `Finding`, `Artifact`) | bytes and rows |
| redsim | `redsim/services/reports.py::render_reports` | the `report` stage output |

### Audit chain (from redsim, F008)

Admission and execution both write to the hash-chained audit log. Admission uses
`resolve_writer(config)` (Postgres online, JSONL offline). The worker uses the
`PostgresAuditWriter` that `task_context` supplies as `ctx.audit_writer`. Every
human-triggered status change appends a chained event *before* the row changes
(spec invariant 6.7.4). The emission order per task is fixed in spec section
10.5. `detail` carries digests, counts, ids, and blob references only. It never
carries model bytes, images, dataset rows, prompt text, or secrets.

### New `Action` members (WS0, spec section 17.2)

`MODEL_REGISTER` (remediator), `ATTACK_RUN` (scanner), `EXPLAIN_RUN` (scanner),
`HARDEN_RECOMMEND` (remediator), `FINDING_REVIEW` (approver), `FINDING_ANNOTATE`
(remediator), `REPORT_EXPORT` (scanner). P4 calls `check(user, Action.X,
project_id)` at each write route. WS0 adds the rows to `redsim/api/policy.py`.

### Environment

`REDSIM_DB_URL`, `REDSIM_BROKER_URL`, `REDSIM_RESULT_BACKEND`, blob store env, and
the sandbox budget `REDSIM_ML_SANDBOX_TIMEOUT_S`. The Pythia narrative stays off
unless `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, and `REDSIM_ML_LLM_MODEL` are set and
`llm_narrative` is true (master plan section 5, spec section 10.8).

## 4. Interfaces

### HTTP surface exposed (spec section 17)

Base `/v1`, mounted on the existing app. Auth, RLS, CSRF, and rate limits apply.
New ML routes use the structured error envelope
`{"detail": {"code", "message", "phase"?, "field"?}}`. Retained routes keep
`{"detail": "<string>"}`.

| Method | Path | Router | Gate | Returns |
|---|---|---|---|---|
| GET | `/v1/models?project=` | `models.py` | membership | list of ML `Target` rows with manifest and status |
| POST | `/v1/models` (bundled / upload / endpoint) | `models.py` | `MODEL_REGISTER` | 201 Target; 413/415/422 on refusal; 501 for endpoint (Phase B) |
| GET | `/v1/models/{id}` | `models.py` | membership | detail plus validation summary and campaign history |
| DELETE | `/v1/models/{id}` | `models.py` | `TARGET_MANAGE` | 200; 409 `campaign_in_flight` |
| POST | `/v1/models/{id}/attacks` | `attacks.py` | `ATTACK_RUN` | 202 JobHandle `{run_id, job_ids, status_url}`; starts a campaign |
| GET | `/v1/attacks?modality=` | `attacks.py` | authenticated | attack registry (`AttackInfo` + phase/access/status) |
| GET | `/v1/datasets` | `datasets.py` | authenticated | bundled dataset manifest |
| GET | `/v1/defenses` | `defenses.py` | authenticated | ART preprocessing defenses for verify |
| GET | `/v1/ml/capabilities` | `ml_capabilities.py` | authenticated | honest modality and feature roster |
| GET | `/v1/runs/{id}/campaign` | `compare.py` or `ml_findings.py` | membership | full campaign record (spec section 5) |
| GET | `/v1/runs/{id}/artifacts` | `artifacts.py` | membership | `Artifact` row list |
| GET | `/v1/artifacts/{id}` | `artifacts.py` | membership via run | streams the blob; CSP + nosniff + ETag |
| GET | `/v1/runs/{id}/compare?with=` | `compare.py` | membership on both | verify delta or side-by-side |
| PATCH | `/v1/runs/{id}/reviewer-notes` | `compare.py` or `ml_findings.py` | `FINDING_ANNOTATE` | stores notes; audit `finding.annotate` |
| POST | `/v1/findings/{id}/explain` | `ml_findings.py` | `EXPLAIN_RUN` | 202 JobHandle; 409 if not terminal |
| POST | `/v1/findings/{id}/harden` | `ml_findings.py` | `HARDEN_RECOMMEND` | 202 JobHandle; 409 if not terminal |

Retained routes that P4 amends, not replaces: `GET /v1/runs`, `GET
/v1/runs/{id}`, `POST /v1/runs/{id}/cancel` (the 409 amendment),
`GET/PATCH /v1/findings…`, `POST /v1/findings/{id}/verify` (body extended with
`{defense, params}`), `GET /v1/runs/{id}/report.{md,json,html}` (one `check()`
added). These live in `redsim/api/v1/runs.py`, `runs_cancel.py`, `findings.py`,
`verify.py`, and `reports.py`.

A campaign starts at `POST /v1/models/{id}/attacks`. There is no generic
`POST /v1/runs`. The campaign record is read at `GET /v1/runs/{id}/campaign`.
The plain `GET /v1/runs/{id}` wire shape is untouched so the existing web tests
keep passing.

### Celery task names and queues (spec section 10.2)

| Task name | `Job.type` | Module | Queue |
|---|---|---|---|
| `redsim.model_validate` | `model.validate` | `workers/tasks/model_validate.py` | `scans` |
| `redsim.attack_run` | `attack.run` (one Job per attack) | `workers/tasks/attack.py` | `scans` |
| `redsim.explain_run` | `explain.run` | `workers/tasks/explain.py` | `scans` |
| `redsim.harden_recommend` | `harden.recommend` | `workers/tasks/harden.py` | `default` |
| `redsim.verify_replay` | `verify.replay` | `workers/tasks/verify.py` (ML branch) | `scans` |
| `redsim.report_render` | `report.render` | `workers/tasks/report.py` | `default` |

Each ML task is declared `bind=True, max_retries=2`, exactly like `scan_start`
and `verify_replay`. Add the new modules to the `include` list and the queue
routes in `redsim/workers/celery_app.py`.

### Job state machine (consumed, `redsim/workers/job_state.py`)

```
queued    -> running | cancelled
running   -> succeeded | failed | cancelled | queued
succeeded | failed | cancelled -> (terminal)
```

Every status write goes through `set_job_status`. `running -> queued` is the
transient-retry requeue that `task_context` performs. `task_context` runs a task
only when its job is `queued`; any other status yields `skip=True` and the body
returns without work. This is the cancellation and redelivery guard. It is why a
cancelled attack never re-fires.

## 5. Ordered implementation steps

### Step 1 — mount the routers (Slice 1)

Create the eight router modules under `redsim/api/v1/` as `APIRouter` instances,
each with its own `prefix` and `tags`, following `redsim/api/v1/targets.py`. Add
each to the import block and the `include_router(..., prefix="/v1")` block in
`redsim/api/app.py::create_app`. Start with read-only handlers that return `501`
where the pipeline is not wired yet, so the app boots and the route table is
complete.

### Step 2 — `ml_capabilities.py`, `datasets.py`, `attacks.py`, `defenses.py`

Wire the four catalog reads first. They are pure reads over the P1/P2/P3
registries and the dataset and defense manifests. `GET /v1/ml/capabilities`
returns the honest roster in spec section 17.2 and never leaks the Pythia key or
base URL. `GET /v1/attacks` lists the registry plus `phase`, `access`,
`requires_gradients`, `status`, and `reason`, including the benign
`noise_control` adapter as `family: "control"`.

### Step 3 — `models.py`

Implement the model catalog and upload. `GET /v1/models` lists `Target` rows of
kind `ml_model_artifact` / `ml_model_endpoint`. `POST /v1/models` accepts
`bundled`, `upload`, and `endpoint` sources. The upload handler performs static
checks only (size cap while streaming, magic bytes, pickle refusal), computes
`sha256`, writes the bytes to the blob store, and creates the `Target` with
`status="registered"`. The same service then creates the `ml.ingest` Run and the
`model.validate` Job and moves the status to `validating`. Deep validation runs
on the worker (step 6). `endpoint` returns `501` with `phase: "B"`. Nothing
deserialises the file in the API process.

### Step 4 — `redsim/services/ml_campaigns.py` (admission)

Mirror `redsim/services/scans.py::create_scan_job`. Write
`create_attack_campaign(...)` with this load-bearing order:

1. `authorize("attack.run", target=None, allowlist=config.target_allowlist,
   actor=f"user:{user.sub}", writer=audit_writer, project_id=..., run_id=...,
   detail=<config snapshot, model sha256, dataset id + revision, settings_hash>)`.
   The chained audit row lands before any domain row.
2. Insert one `Run` (`scanner="ml.campaign"`, `mode="api"`, `status="queued"`,
   `stage_table={}`), flush for FK precedence.
3. Insert one `attack.run` `Job` per attack id, chained in the declared order
   (the first carries `chain_position == 0`); insert the campaign-wide
   `explain.run` Job when `explain_k > 0`; insert `harden.recommend` when
   `auto_recommend`. Each Job's `detail` carries the campaign config snapshot.
4. `attack_run.delay(job_id_of_chain_position_0)`. A broker failure is logged;
   the rows stay `queued` for a later pickup. The audit row already exists.
5. Return `JobHandle.to_response()` → 202 `{run_id, job_ids, status_url}`.

Add sibling admission helpers `create_explain_job`, `create_harden_job`, and the
ML branch of `create_verify_job` (or extend `redsim/services/verify.py`), each
audit-first and each ending in `task.delay`. Reject the guarded cases with the
spec section 17.3 codes (`model_load_refused`, `unknown_attack`,
`attack_requires_gradients`, `eps_grid_invalid`, `params_out_of_range`, and so
on).

### Step 5 — `attacks.py` route `POST /v1/models/{id}/attacks`

Read the `Target`, run `check(user, Action.ATTACK_RUN, project_id)`, validate
the `CampaignConfig` body (Pydantic + manifest compatibility + attack
`resolve_params`), reject a target whose status is not `available` with
`409 model_load_refused`, then call `create_attack_campaign`. Return 202. The
route runs no pipeline work.

### Step 6 — the Celery tasks (`redsim/workers/tasks/`)

Build each task on `task_context(job_id, task=self)`. On `ctx.skip`, return
early. Read config from `Job.detail`. Re-check the world before spawning the
child (spec section 10.4): assert the `Target` belongs to `Job.project_id` and
is `available`, recompute the model `sha256`, re-validate the config, and assert
the dataset revision matches the audit row. Spawn the sandbox child
(`python -m redsim.ml.sandbox_worker --stage <stage>`), read the returned
envelope, verify artifact digests, and persist rows.

- `model_validate.py`: verify sha256, run the validate stage, write
  `ml.validation_report`, set `targets.detail.status` to `available` or
  `refused`.
- `attack.py`: the chain body. `chain_position == 0` also runs `sample`,
  `clean_eval`, and `control`, and writes `slice.npz`, `m.clean`, and the
  `m.control.*` rows; later jobs re-fetch `slice.npz` (digest-checked) and reuse
  those rows. Run the attack at each ε in the grid, build measurements, create
  the `Finding` by threshold, record the `ml.adv_slice`, `ml.flip_matrix`, and
  `ml.curve` artifacts, then `attack_run.delay` the next attack job or
  `explain_run.delay` the pre-created explain job.
- `explain.py`: SHAP clean vs adversarial, then the `score` stage. The MRI and
  `S_expl` are written only here, with all five subscores present, then
  `harden_recommend.delay`.
- `harden.py`: `interpret`, then `recommend` (rules always; optional Pythia
  narrative), then `report` through `render_reports`. Mark `Run.status`
  `succeeded` when it is the last job of the chain.
- `verify.py`: the ML branch of `verify_replay`. Apply the ART preprocessor
  defense around a copy of the estimator inside the child, re-run the whole
  in-scope attack set at the campaign's ε grid on the same slice, compute ΔMRI,
  and map the outcome through the existing `_STATE_MAP` to
  `Finding.validation_state` and `Finding.status`.
- `report.py`: re-render reports from findings on demand (the existing
  `report.render` shape).

Write `Run.stage_table` per the spec section 6.5 shape after each stage. Publish
each transition on `run:{run_id}:events` with
`publish_job_event(run_id, job_id, status, type="stage", stage=...)`. Remember
the failure rule: anything written to `Job.detail` or `Run.stage_table` inside a
failing body is rolled back, so commit partial evidence as `Artifact` rows
before the risky step.

### Step 7 — `run.status` roll-up

At each job's terminal transition, inside the same transaction, evaluate the
roll-up rule (spec section 6.2): `succeeded` when all campaign jobs are terminal
and at least one succeeded and none failed; `failed` when all terminal and at
least one failed; otherwise `running`. A task that fails marks the remaining
`queued` chain jobs `cancelled` with `error="upstream job failed: <job_id>"` and
sets `Run.status="failed"`. Follow-on jobs never reopen a terminal run.

### Step 8 — `artifacts.py`

`GET /v1/runs/{id}/artifacts` lists `Artifact` rows. `GET /v1/artifacts/{id}`
resolves the artifact, checks project access through its `run_id`, and streams
the blob. Serve `image/png` inline; serve JSON, `.npz`, and text as
`Content-Disposition: attachment`. Every response carries
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`,
and `ETag = sha256`. Return `404` for unknown ids and for a row whose blob is
missing (`artifact_blob_missing`). Confine the lookup to the blob store key; a
path escape is a `404`.

### Step 9 — `compare.py` and `GET /v1/runs/{id}/campaign`

`GET /v1/runs/{id}/campaign` assembles the full campaign record from
`ml_campaigns`, the measurements, artifacts, observations, interpretation,
recommendations, and the `MRIRecord` (spec section 5). `GET
/v1/runs/{id}/compare?with=` returns the verify delta when the two runs are a
baseline/verify pairing, or two scorecards side by side when settings match but
the model differs. Reject a settings mismatch with `409 incompatible_campaigns`
and a missing score with `409 score_unavailable`.

### Step 10 — `ml_findings.py`

Add `POST /v1/findings/{id}/explain` and `POST /v1/findings/{id}/harden`. Each
runs RBAC, rejects a non-terminal campaign with `409 campaign_not_terminal` and
a duplicate in-flight job with `409 job_in_flight`, then delegates to the
matching admission helper. `POST /v1/findings/{id}/verify` stays in
`redsim/api/v1/verify.py`; extend its body with `{defense, params}`.

### Step 11 — cancel amendment

Amend `redsim/services/runs.py::cancel_run` to reject an already-terminal run.
When `Run.status` is `succeeded`, `failed`, or `cancelled`, raise a typed error
that `redsim/api/v1/runs_cancel.py` maps to `409 run_terminal`, and leave the run
untouched (provenance preserved, spec section 6.3). For a live run, keep the
existing behaviour: audit `run.cancel` first, then set `Run.status="cancelled"`,
flip every `queued`/`running` job to `cancelled` through `set_job_status`, and
best-effort revoke the Celery tasks. Add the cooperative-kill loop (spec section
10.7): the ML tasks poll `Job.status` in a fresh session while waiting on the
child and SIGKILL the child's process group on `cancelled`.

### Step 12 — celery wiring and reaper

Add the six task modules to the `include` list and `task_routes` in
`redsim/workers/celery_app.py` (`scans` for `model_validate`, `attack_run`,
`explain_run`, `verify_replay`; `default` for `harden_recommend` and
`report_render`). The existing beat reaper (`redsim.reap_stale_jobs`, every 300 s)
already covers every `running` job past `job_max_runtime_seconds`, so the ML
tasks need no new reaper.

## 6. Files to create or modify

| File | Action | Contents |
|---|---|---|
| `redsim/api/v1/models.py` | create | model catalog + upload routes |
| `redsim/api/v1/attacks.py` | create | attack registry read + `POST /v1/models/{id}/attacks` |
| `redsim/api/v1/datasets.py` | create | bundled dataset manifest read |
| `redsim/api/v1/defenses.py` | create | ART defense list read |
| `redsim/api/v1/ml_capabilities.py` | create | `GET /v1/ml/capabilities` |
| `redsim/api/v1/artifacts.py` | create | artifact list + `GET /v1/artifacts/{id}` stream |
| `redsim/api/v1/compare.py` | create | `/campaign`, `/compare`, reviewer-notes |
| `redsim/api/v1/ml_findings.py` | create | `POST /v1/findings/{id}/{explain,harden}` |
| `redsim/api/app.py` | modify | import and `include_router` the eight new routers |
| `redsim/services/ml_campaigns.py` | create | `create_attack_campaign` + follow-on admission helpers |
| `redsim/services/runs.py` | modify | `cancel_run` rejects a terminal run with 409 |
| `redsim/services/verify.py` | modify | ML branch of `create_verify_job`, body `{defense, params}` |
| `redsim/api/v1/verify.py` | modify | extend the verify body |
| `redsim/api/v1/reports.py` | modify | add the `REPORT_EXPORT` `check()` |
| `redsim/workers/tasks/model_validate.py` | create | `redsim.model_validate` task |
| `redsim/workers/tasks/attack.py` | create | `redsim.attack_run` chain task |
| `redsim/workers/tasks/explain.py` | create | `redsim.explain_run` + score stage |
| `redsim/workers/tasks/harden.py` | create | `redsim.harden_recommend` + interpret/recommend/report |
| `redsim/workers/tasks/verify.py` | modify | ML branch of `redsim.verify_replay` |
| `redsim/workers/tasks/report.py` | modify | ML campaign report render |
| `redsim/workers/celery_app.py` | modify | `include` + `task_routes` for the ML tasks |
| `tests/ml/fakes.py` | create/modify | `TinyTarget` + a small test attack adapter |
| `tests/ml/test_ml_admission.py` | create | audit-before-Job-row |
| `tests/ml/test_ml_campaign_api.py` | create | POST → 202 → poll → campaign |
| `tests/ml/test_artifacts_api.py` | create | artifact path guard + CSP |
| `tests/ml/test_cancel_terminal.py` | create | 409 on terminal cancel |

## 7. Testing and validation

Backend pytest under `tests/ml/` with the `ml` marker, the sqlite conftest
harness (`tests/conftest.py`), and the `TinyTarget` fake. Offline, no ART or
CIFAR-10 assets in the unit path. Use the FastAPI `TestClient` in dev-token auth
mode.

1. **Admission is audit-first** (`test_ml_admission.py`). Call
   `create_attack_campaign` with a failing `audit_writer` and assert no `Run` or
   `Job` row exists. On success, assert the audit event's `ts` precedes the
   `Job` row (mirrors `tests/test_admission_audit_before_enqueue.py`).
2. **`POST /v1/models/{id}/attacks` returns 202** (`test_ml_campaign_api.py`).
   POST a valid `CampaignConfig` against a `TinyTarget` model with the test
   attack. Assert 202 and a `{run_id, job_ids, status_url}` body.
3. **Campaign completes**. Run the chain to a terminal state (eager Celery or a
   direct task call). Poll `GET /v1/runs/{id}` to `succeeded`. Assert
   `GET /v1/runs/{id}/campaign` carries the clean, evasion, and control
   measurements, an `MRIRecord` with all five subscores, and a non-empty
   `limitations`.
4. **Artifact path guard** (`test_artifacts_api.py`). Assert
   `GET /v1/artifacts/{id}` streams a known blob, returns `404` for an unknown
   id and for a traversal attempt, and that no blob-store key outside the run's
   artifacts is reachable.
5. **Report CSP**. Assert `GET /v1/runs/{id}/report.html` carries
   `Content-Security-Policy: default-src 'none'`, and `X-Content-Type-Options:
   nosniff`, and that the `REPORT_EXPORT` gate rejects a caller below `scanner`.
6. **Cancel a terminal run** (`test_cancel_terminal.py`). Cancel a `succeeded`
   run and assert `409 run_terminal` with the run untouched. Cancel a `running`
   run and assert every `queued`/`running` job flips to `cancelled` and the run
   is `cancelled`.
7. **Job state** reuse. `tests/test_job_state.py` already covers the machine.
   Add an ML case that a cancelled attack job is skipped on redelivery
   (`task_context` `skip=True`).

Run `make test` and `make typecheck`. Both must stay green. `vitest` (the web
tests) is WS5 and out of scope here.

## 8. Acceptance criteria / definition of done

1. **Vertical smoke test.** `POST /v1/models/{id}/attacks` for one bundled image
   target with `fgsm` and `explain_k > 0` returns 202 on the live stack (API +
   Celery worker on Redis). The `attack.run` → `explain.run` → `harden.recommend`
   chain runs. Polling `GET /v1/runs/{id}` reaches `succeeded`.
   `GET /v1/runs/{id}/campaign` holds the clean, evasion, and control
   measurements, the SHAP observations, the `MRIRecord` with all five subscores
   and a grade, the interpretation, the candidate recommendations, and a
   non-empty `limitations`.
2. Admission appends the `attack.run` audit event before any `Run` or `Job` row
   and before `task.delay`. `redsim audit verify --run <run_id>` passes for the
   campaign chain.
3. `Run.stage_table` advances monotonically through `STAGES`, and each transition
   publishes a frame on `run:{run_id}:events`.
4. `GET /v1/artifacts/{id}` streams the blob under the CSP, nosniff, and ETag
   headers, RLS-confined, and returns `404` for a path escape or a missing blob.
5. `cancel_run` rejects a terminal run with `409 run_terminal` and cancels every
   live job of a running campaign.
6. A `succeeded` campaign always states its `limitations`; the schema validator
   passes. A `failed` or `cancelled` campaign has no `score`.
7. The pytest suite in section 7 passes. `make test` and `make typecheck` stay
   green.

## 9. Effort estimate and special considerations

Estimate: 4 to 6 developer-days across Slice 1 (routers + catalog reads +
admission scaffold) and Slice 2 (the task chain, campaign record, and verify),
gated on P1, P2, and P3 landing their modules.

### Celery queues

The ML attack, explain, model-validate, and verify tasks run on the `scans`
queue with the long-running scanner work; `harden.recommend` and `report.render`
run on `default`. Deploy a dedicated worker pool per queue (spec section 20).
Keeping the harden/report bookkeeping off `scans` stops a 30-minute campaign
from starving a report behind it. Add the new task names to
`redsim/workers/celery_app.py::task_routes` or they inherit `default` and land on
the wrong pool.

### Reaper

A task that crashes so hard it never reaches `task_context`'s failure path is
left `running`. The existing beat reaper (`redsim.reap_stale_jobs`, every 300 s)
flips any `running` job past `job_max_runtime_seconds` (default 3600) to `failed`
with `error="reaped: exceeded max runtime TTL"`. The ML tasks need no new
reaper; they only need to respect the redelivery guard so a reaped-then-
redelivered job is skipped.

### Sandbox child

Every stage that touches model bytes runs inside the plugin sandbox as a child
process (`python -m redsim.ml.sandbox_worker --stage <stage>`), never in the API
process and never in the worker parent. The parent waits on the child in a 5 s
loop that re-reads `Job.status` in a fresh session, so a cancel can SIGKILL the
child's process group (spec section 10.7). `harden.recommend` is the one task
that never loads a model; it runs on the `default` pool and may call Pythia. The
sandbox wall clock (`REDSIM_ML_SANDBOX_TIMEOUT_S`) raises `SandboxTimeout` per
stage; the Celery soft/hard limits (1800/2100 s) are the outer fence.

### Failure isolation

Anything written to `Job.detail` or `Run.stage_table` inside a failing task body
is rolled back by `task_context`. Commit partial evidence as `Artifact` rows
before the risky step. A failed chain job marks the remaining `queued` jobs
`cancelled` and sets `Run.status="failed"`; nothing downstream runs on partial
inputs. Failure classes (`ModelLoadRefused`, `SandboxTimeout`,
`ExplainerUnavailable`, and the rest) are run/infrastructure states, never model
outcomes, and never render as "robust" or "not robust".

### The LLM narrative

The Pythia narrative runs only inside `harden.recommend`, only when configured,
and never fails the job. On any failure the deterministic rule text stands with
`narrative_source="rules"` and the skip reason recorded. The writer adds no
claim absent from the rule outputs and never receives images, model data, or
dataset rows (spec section 10.8).
