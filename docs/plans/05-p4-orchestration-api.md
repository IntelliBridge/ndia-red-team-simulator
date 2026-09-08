# Phase P4 — Orchestration & API wiring

Status: v1, 2026-09-08. Owner: backend lead. Wave: scaffold in Wave 1, complete
in Wave 2. This phase is the integration spine. Read `00-master-plan.md` first,
then the design spec `docs/superpowers/specs/2026-09-08-redsim-design.md`, then
this file.

P4 turns three independent phases into one running product. P1 builds targets,
P2 builds attacks and MRI scoring, P3 builds explanation and rules. P4 executes
them in order, persists the record after each stage, serves the HTTP surface,
and renders the reports.

---

## 1. Objective

Wire the pipeline and the API so a user can launch a run and watch it finish.

Concretely, deliver four modules:

1. `redsim/runs.py` — `run_pipeline(config, store) -> RunRecord`. It runs the
   nine `STAGES` in order, calls the `TARGETS` and `ATTACKS` registries, the
   scoring module, the explain module, and the rules module. It writes
   `run.json` through `store.save_record` after every stage so the UI polls
   progress.
2. `redsim/jobs.py` — a thread pool and an in-memory handle table. `submit`
   returns a `run_id` and runs the pipeline off the request thread. `status`
   returns a `RunSummary` or `None`.
3. `redsim/api/routes.py` — the full route surface from design spec section 4
   and master plan section 6.7, completed from the P0 skeleton.
4. `redsim/report.py` builders — render a `RunRecord` to Markdown, JSON, and
   HTML, reusing the existing `html_escape` and `_md_to_html_min` helpers.

The acceptance gate is the vertical smoke test: one image target plus FGSM plus
SHAP, from `POST /v1/runs` to a `succeeded` `RunRecord` with a `scoring` block.

## 2. Scope

### In scope

- `run_pipeline` orchestration across all nine stages.
- Per-stage persistence of `run.json` via `store.save_record`.
- Population of `RunRecord.measurements`, `observations`, `interpretation`,
  `recommendations`, `scoring`, `atlas_coverage`, `provenance`, and
  `limitations`.
- The stub-target path: `status="not_implemented"`, a stated reason, no
  fabricated panels.
- The thread pool, the handle table, and failure capture in `jobs.py`.
- All P4-owned routes in `routes.py`.
- The three report builders in `report.py`.
- The pytest suite named in section 7.

### Out of scope

- Any target, attack, scoring, explain, or rules logic. P4 consumes those
  modules, it does not implement them.
- The schema additions themselves. `Scoring`, `RunRecord.scoring`,
  `RunRecord.atlas_coverage`, `AttackInfo.atlas_technique_id`,
  `AttackInfo.atlas_technique_name`, and `Measurement.severity` are P0
  additions per master plan section 6.1. P4 assumes they exist and fills them.
- The `create_app()` factory wiring, CORS, and `/health`. Those are the P0
  skeleton in `redsim/api/app.py`. P4 adds routes into that app.
- `/v1/targets` and `/v1/attacks`. P0/P1/P2 own those.
- Dataset routes `/v1/runs/{id}/dataset` and `/v1/datasets/{id}`. P6 owns those.
- The optional LLM narrative. P3 owns `narrative.py`. P4 leaves narrative off
  unless the environment enables it, and never blocks a run on it.

## 3. Prerequisites & dependencies

### Consumed from other phases

| From | Import | Used for |
|---|---|---|
| P1 | `from redsim.targets.registry import TARGETS` | resolve `config.target_id` |
| P1 | `redsim.targets.base.Target`, `Sample` | protocol shape, slice type |
| P2 | `from redsim.attacks.registry import ATTACKS` | resolve `config.attack_id` |
| P2 | `redsim.attacks.base.AttackAdapter`, `AttackOutput` | protocol shape, attack result |
| P2 | `redsim.scoring.score_run`, `severity_for` | MRI block, measurement severity |
| P3 | `redsim.explain.shap_image.explain` (and `shap_tabular`) | observations, `expl_shift_mean` |
| P3 | `redsim.explain.base.ExplainOutput` | explain return shape |
| P3 | `redsim.recommend.rules.interpret`, `recommend` | interpretation, candidates |
| P0 | `redsim.schema` all models, `STAGES`, `STANDING_LIMITATIONS` | record construction |
| P0 | `redsim.state.RunStore` | persistence, artifact resolution |
| P0 | `redsim.api.app.create_app` | app factory to mount routes on |

### Wave discipline

P4 starts in Wave 1. Scaffold `runs.py` and `jobs.py` against the Protocols and
the registries, not against concrete classes. Import `Target`, `AttackAdapter`,
`score_run`, `explain`, `interpret`, and `recommend` by their master-plan
signatures. Where a dependency is not merged yet, guard the call site so the
scaffold imports and the tests collect. Complete the wiring in Wave 2 as P1, P2,
and P3 land.

The one cross-phase value P4 forwards is `expl_shift_mean`. The explain stage
produces it. The scoring stage consumes it. When `explain_k == 0` or the explain
stage is skipped, pass `expl_shift_mean=None` so `score_run` renormalizes the
weights, exactly as master plan section 6.1 specifies.

### Environment

Reads `REDSIM_OUTPUT_DIR` through `RunStore` defaults. Narrative stays off
unless `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, and `REDSIM_LLM_MODEL` are all set
and `config.llm_narrative` is true. See master plan section 6.8.

## 4. Interfaces

### Exposed to other phases

```python
# redsim/runs.py
def run_pipeline(config: RunConfig, store: RunStore) -> RunRecord: ...
#   Executes STAGES in order. Writes run.json via store.save_record after each
#   stage. Returns the final RunRecord (status succeeded, failed, or
#   not_implemented).

# redsim/jobs.py
def submit(config: RunConfig) -> str: ...          # returns run_id, runs on the pool
def status(run_id: str) -> RunSummary | None: ...  # None when the run_id is unknown
```

`submit` creates a `RunStore` with a fresh `run_id`, writes an initial queued
`run.json`, then hands `run_pipeline` to the pool. It returns before the
pipeline finishes.

### HTTP surface (P4 completes the P0 skeleton)

Base `/`, JSON errors `{detail}`, CORS allows `http://localhost:3000`, no auth.

| Method | Path | Owner | Returns |
|---|---|---|---|
| GET | `/health` | P0 | `{status:"ok", version}` |
| GET | `/v1/targets` | P0/P1 | list `TargetInfo` |
| GET | `/v1/attacks` | P0/P2 | list `AttackInfo` (incl. atlas fields) |
| POST | `/v1/runs` | P4 | 202 `{run_id}`; 501 stub target; 422 bad params |
| GET | `/v1/runs` | P4 | list `RunSummary` |
| GET | `/v1/runs/{id}` | P4 | full `RunRecord` (incl. `scoring`, `atlas_coverage`) |
| PATCH | `/v1/runs/{id}/reviewer-notes` | P4 | updated `RunRecord` |
| GET | `/v1/runs/{id}/artifacts/{path}` | P4 | PNG/JSON, path-confined |
| GET | `/v1/runs/{id}/report.{md,json,html}` | P4 | report; HTML with strict CSP |

Response bodies are the Pydantic models from `redsim/schema.py`. Do not invent
fields.

## 5. Ordered implementation steps

### Step 1 — pipeline skeleton (`runs.py`, Wave 1)

Write `run_pipeline(config, store)` as a stage loop over `STAGES`. Keep a live
`RunRecord`. After each stage, set `record.stage`, append the stage to
`record.stages_done`, and call `store.save_record(record.model_dump(mode="json"))`.

`RunStore.save_record` takes a plain dict, so always dump the record first. Use
`mode="json"` so datetimes and enums serialize cleanly, matching the
`json.dumps(..., default=str)` the store already does.

Wrap the whole body in one try block. On any exception set
`record.status="failed"`, `record.error=str(exc)`, keep `record.stage` at the
failing stage, write the record one last time, and return it. Never leave a
half-written record on disk without a terminal status.

### Step 2 — `load_target` stage

Resolve the target with `TARGETS.get(config.target_id)`. A missing id raises
`KeyError`. Catch it at the `POST /v1/runs` boundary and return 422, so the
pipeline never starts on an unknown target.

Call `target.info()`. When `info().status == "not_implemented"`, stop early. Set
`record.status="not_implemented"`, copy `info().reason` into `record.error`,
attach the `TargetInfo` to `record.target`, write `run.json`, and return. Do not
sample, attack, explain, or score. The UI must show the reason and no fabricated
panels (design spec section 5).

For a live target, call `target.load()` (idempotent) and set `record.target`.

### Step 3 — `sample` stage

Call `target.sample(config.n_samples, config.seed)` to get a `Sample`. Keep the
`Sample.x`, `Sample.y`, `Sample.indices`, and `Sample.class_names` in local
state for later stages. Persist the record.

### Step 4 — `clean_eval` stage

Run `target.predict_proba(sample.x)`, take the argmax, and count correct
predictions against `sample.y`. Build the clean `Measurement`:

- `id="m.clean"`, `family="clean"`, `attack_id=None`.
- `n`, `n_correct`, `accuracy`.
- `per_class` keyed by class name, each `{"n": ..., "n_correct": ...}`.
- `wall_time_s` for the stage.

Append it to `record.measurements`. Persist.

### Step 5 — `attack` stage

Resolve the adapter with `ATTACKS.get(config.attack_id)`. Call
`adapter.resolve_params(config.params)` to fill defaults and reject
out-of-range values. `resolve_params` raises `ValueError` on bad params. Catch
it at the `POST` boundary for a 422. Run
`adapter.run(target, sample.x, sample.y, resolved_params, config.seed)` to get
an `AttackOutput`.

`AttackOutput` carries `x_adv`, `linf_norm_mean`, `l2_norm_mean`, `wall_time_s`,
`params`, `library_versions`, and `notes`. It does **not** carry predictions, so
compute the adversarial predictions here with `target.predict_proba(out.x_adv)`.

Build the evasion `Measurement`:

- `id=f"m.evasion.{config.attack_id}"`, `family="evasion"`,
  `attack_id=config.attack_id`, `params=resolved_params`.
- `n`, `n_correct`, `accuracy` on `x_adv`.
- `n_flipped_from_clean` = count where the clean argmax and the adversarial
  argmax differ.
- `linf_norm_mean`, `l2_norm_mean` from `AttackOutput`.
- `per_class`, `wall_time_s`.

Set `Measurement.severity` with `severity_for(measurement, eps_small, eps_mid)`
(P2, master 6.3). Append and persist. Keep `x_adv` for the explain stage.

### Step 6 — `control` stage

Skip when `config.include_control` is false. Otherwise resolve the
`noise_control` adapter, run it at the same eps as the attack, and build a
`Measurement` with `id="m.control.noise"`, `family="control"`. Persist.

The control exists to show whether random noise at the same budget degrades the
model. Do not blend it into the evasion row.

### Step 7 — `explain` stage

Skip when `config.explain_k == 0`. Otherwise call the P3 entry point,
`explain(target, sample, x_adv, config.explain_k, config.seed, store)`
(master plan section 6.4). It writes the artifact PNGs through the same
`store` and returns an `ExplainOutput`.

Copy `ExplainOutput.observations` into `record.observations`. Keep
`ExplainOutput.expl_shift_mean` for the scoring stage. Fold
`ExplainOutput.shap_version` into provenance. Persist.

Pick the explain module by domain: `shap_image.explain` for images,
`shap_tabular.explain` for tabular. The first milestone runs the image path
only.

### Step 8 — `interpret` stage

Score first, because interpretation rests on the scoring block. Call
`score_run(record.measurements, expl_shift_mean, reference_eps, eps_grid)` (P2,
master 6.3) and set `record.scoring`. Derive `reference_eps` and `eps_grid` from
the resolved attack params. Pass `expl_shift_mean=None` when the explain stage
was skipped, so `score_run` renormalizes the weights.

Then call `interpret(record.measurements, record.observations, record.scoring)`
(P3, master 6.5) and set `record.interpretation`. Persist.

### Step 9 — `recommend` stage

Call `recommend(record.measurements, record.observations, record.scoring)` (P3)
and set `record.recommendations`. Each candidate stays `status="candidate"` and
`validation="not evaluated"` from the schema defaults.

When narrative is enabled (all three env vars plus `config.llm_narrative`), pass
the candidates through `redsim.recommend.narrative`. The narrative is optional
prose over rule outputs. It must not add claims. A narrative failure never fails
the run. Catch it, log it, and keep the rule text. Persist.

### Step 10 — `report` stage and finalize

Fill `record.atlas_coverage` from the ATLAS technique ids on the attacks used
(the `atlas_technique_id` fields P3 populates on `AttackInfo`). De-duplicate.

Build `record.provenance` (a `Provenance` model): `redsim_version`, `python`,
`torch`, `art`, `shap`, `numpy`, `model_sha256` and `model_manifest` from
`target.manifest()`, `dataset`, `dataset_split`, `started_at`, `finished_at`,
`hostname`, `device`, and `nondeterminism` sources.

Set `record.limitations` from `STANDING_LIMITATIONS`, then extend it with
run-specific notes (slice size, single seed, single eps unless swept). The
schema validator `_limitations_required_when_done` rejects a `succeeded` record
with an empty `limitations`, so this list must be non-empty before the terminal
write.

Set `record.status="succeeded"`, `record.stage=None`. Write `run.json` a final
time. Return the record.

Rendering the report files is on demand at the route, not written to disk here,
unless a later phase needs cached copies. The stage marks the run complete.

### Step 11 — `jobs.py`

Build a module-level `ThreadPoolExecutor` and a dict mapping `run_id` to a
`Future` (the handle table). Guard both with a lock.

`submit(config)`:

1. Create a `RunStore` with a fresh `run_id`.
2. Write an initial `run.json` with `status="queued"`, `stage=None`,
   `created_at=now`.
3. Submit `run_pipeline(config, store)` to the pool. Store the `Future`.
4. Return `store.run_id`.

`status(run_id)`:

1. Open the store with `RunStore.open(run_id)`. Return `None` when it is `None`.
2. Load `run.json` with `store.load_record()`.
3. Build a `RunSummary` from the loaded dict: `run_id`, `status`, `stage`,
   `config.target_id`, `config.attack_id`, `created_at`.

Read status from disk, not from the `Future`, so a process restart still reports
progress. The `Future` handle only reports in-process failures that never
reached disk.

### Step 12 — `routes.py`

Complete the router the P0 skeleton mounts on `create_app()`.

- `POST /v1/runs`: validate the body as `RunConfig` (FastAPI returns 422 on a
  bad body). Resolve the target. When `TARGETS.maybe_get(target_id)` is `None`,
  return 422. When `target.info().status == "not_implemented"`, return 501 with
  the reason in `detail`. Validate the attack params with
  `adapter.resolve_params`, returning 422 on `ValueError`. Otherwise call
  `jobs.submit(config)` and return 202 `{"run_id": run_id}`.
- `GET /v1/runs`: list ids with `RunStore.list_run_ids()`, load each record, and
  return a list of `RunSummary`.
- `GET /v1/runs/{id}`: open the store, load `run.json`, validate it as
  `RunRecord`, and return it. 404 when the run is unknown.
- `PATCH /v1/runs/{id}/reviewer-notes`: load the record, set `reviewer_notes`
  from the body, rewrite `run.json` via `store.save_record`, return the updated
  `RunRecord`.
- `GET /v1/runs/{id}/artifacts/{path:path}`: call `store.resolve(rel)` for the
  path-escape guard. `resolve` raises `ValueError` on a traversal attempt.
  Convert that to 404. Return the bytes with the content type inferred from the
  suffix (`.png` -> `image/png`, `.json` -> `application/json`).
- `GET /v1/runs/{id}/report.md`: return the Markdown builder output,
  `text/markdown`.
- `GET /v1/runs/{id}/report.json`: return `record.model_dump(mode="json")`,
  `application/json`.
- `GET /v1/runs/{id}/report.html`: return the HTML builder output with the exact
  header from the design spec:
  `Content-Security-Policy: default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'`.

### Step 13 — `report.py` builders

Add three functions that take a `RunRecord`:

- `render_markdown(record) -> str`: the six report sections in order (config and
  provenance, measurements, observations, interpretation, candidate
  recommendations, limitations). Keep the honesty labels: candidates read
  "candidate / not evaluated", the center-mass metric reads "heuristic".
- `render_json(record) -> str`: `json.dumps(record.model_dump(mode="json"))`.
  It must equal the record dump so a run reruns from it.
- `render_html(record) -> str`: run `render_markdown` through `_md_to_html_min`.
  Every interpolation already routes through `html_escape` inside the helper, so
  a `<script>` in a class name renders inert.

Reuse the existing helpers. Do not add a template engine.

## 6. Files to create or modify

| File | Action | Contents |
|---|---|---|
| `redsim/runs.py` | create | `run_pipeline` stage loop, per-stage persistence |
| `redsim/jobs.py` | create | pool, handle table, `submit`, `status` |
| `redsim/api/routes.py` | create | all P4 routes from section 4 |
| `redsim/api/app.py` | modify | mount the P4 router (if P0 left a seam) |
| `redsim/report.py` | modify | `render_markdown`, `render_json`, `render_html` |
| `tests/fakes.py` | modify | add a fake attack double next to `TinyTarget` |
| `tests/test_runs.py` | create | pipeline persists after each stage |
| `tests/test_jobs.py` | create | `submit` then poll `status` |
| `tests/test_api.py` | create | POST -> poll -> GET, 501 stub, traversal, CSP |
| `tests/test_report.py` | create | six sections, escaped script, json equality |

Note on test doubles: the existing double in `tests/fakes.py` is `TinyTarget`
(`id="tiny"`), a random-weight image target. There is no attack double yet. Add
one small `AttackAdapter` fake (call it what the suite already expects) so the
run and API tests never need ART or the CIFAR-10 assets.

## 7. Testing & validation

Backend pytest, offline, under 60 s total (design spec section 7).

1. **Pipeline persists after each stage** (`test_runs.py`). Run `run_pipeline`
   with `TinyTarget` and the fake attack against a temp `RunStore`. Assert
   `run.json` exists and its `stages_done` grows across a sequence of loads, or
   assert the final record lists all expected stages in `stages_done`. Assert
   the final `status == "succeeded"`, `scoring` is set, and `measurements`
   holds a clean and an evasion row.
2. **Stub target -> not_implemented**. Register a stub target whose
   `info().status == "not_implemented"`. Run the pipeline. Assert
   `status == "not_implemented"`, `error` holds the reason, and there are no
   measurements, observations, or scoring.
3. **POST -> poll -> GET** (`test_api.py`, FastAPI `TestClient`). POST a valid
   `RunConfig`, assert 202 and a `run_id`. Poll `GET /v1/runs/{id}` until
   `status` is `succeeded` or `failed`. Assert the final record carries
   `scoring`, at least the clean and evasion `measurements`, and
   `atlas_coverage`.
4. **Stub target -> 501**. POST a run whose `target_id` is a stub. Assert 501
   and a reason in `detail`.
5. **Bad params -> 422**. POST a run with an out-of-range param. Assert 422.
6. **Artifact traversal blocked**. GET
   `/v1/runs/{id}/artifacts/..%2f..%2frun.json` (and a plain `../` variant).
   Assert 404, driven by the `RunStore.resolve` guard.
7. **Report HTML has the CSP header**. GET `/v1/runs/{id}/report.html`. Assert
   the response header equals
   `default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'`.
8. **Report shape** (`test_report.py`). Assert Markdown holds the six sections
   in order. Assert a `<script>` inside a class name renders escaped in HTML.
   Assert `render_json` equals `record.model_dump()`.
9. **Jobs** (`test_jobs.py`). `submit` a config, poll `status` to a terminal
   state, assert a `RunSummary` comes back and an unknown id returns `None`.

Run `make test` and `make typecheck`. Both must stay green.

## 8. Acceptance criteria / definition of done

1. **Vertical smoke test.** `POST /v1/runs` for the CIFAR-10 image target with
   `fgsm` and `explain_k > 0` returns 202. Polling `GET /v1/runs/{id}` reaches
   `succeeded`. The record holds `measurements` (clean, evasion, control), a
   `scoring` block with a grade, `observations` with SHAP artifacts,
   `interpretation`, `recommendations`, `atlas_coverage`, `provenance`, and a
   non-empty `limitations`.
2. `run_pipeline` writes `run.json` after every stage. A poll mid-run shows a
   growing `stages_done` and the current `stage`.
3. A stub target returns 501 from `POST /v1/runs` and never starts a pipeline.
   A stub run record, if built, is `not_implemented` with a reason and no
   fabricated panels.
4. Artifact path traversal returns 404 through `RunStore.resolve`.
5. `report.html` carries the exact design-spec CSP header. `report.json` equals
   the record dump. `report.md` holds the six sections in order.
6. A `succeeded` record always states its limitations. The schema validator
   passes.
7. The full pytest suite in section 7 passes. `make test` and `make typecheck`
   stay green.

## 9. Effort estimate & special considerations

Estimate: 2 to 3 developer-days. Scaffolding in Wave 1 is about half a day. The
Wave 2 completion, once P1 through P3 land, is the rest, most of it in the
stage-by-stage integration and the API tests.

### Thread pool sizing

Runs are CPU-bound (torch, ART, SHAP) and the demo is single-user. Size the
pool small, `max_workers=2` by default, overridable with an env var. A large
pool oversubscribes the CPU and slows every run. Keep the pool module-level and
create it once, not per request.

### Error propagation

Wrap the whole pipeline body in one try block. On failure set
`status="failed"`, put `str(exc)` in `error`, keep `stage` at the failing stage,
and write `run.json` one last time. A run must never sit `running` on disk after
its worker died. `jobs.status` reads that terminal state from disk, so a caller
polling `GET /v1/runs/{id}` sees the failure even after a process restart.
Distinguish user errors (unknown target, bad params) from pipeline faults:
catch the former at the `POST` boundary and return 422 or 501, never a 500.

### Atomic run.json writes

`RunStore.save_record` already writes to `run.json.tmp` and calls
`Path.replace`, which is atomic on the same filesystem. Rely on it. Never write
`run.json` directly. On EFS the tmp file and the target sit in the same run
directory, so the atomic rename holds. A concurrent poller therefore reads
either the old record or the new one, never a torn file.

### Narrative isolation

The optional LLM narrative runs inside the `recommend` stage. It must never fail
a run. Catch every exception from `narrative`, keep the rule text, and continue.
It stays off unless all three env vars and `config.llm_narrative` are set.

### Determinism note

The pipeline forwards `config.seed` to `sample`, `attack`, and `explain`. SHAP
sampling and CPU float reductions stay non-deterministic. Record those in
`provenance.nondeterminism` rather than promising bit-for-bit repeats.
