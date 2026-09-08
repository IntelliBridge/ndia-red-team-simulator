> **SUPERSEDED / RECONCILED (2026-09-08 spec update).** This file was written for v1 against the deleted `redsim/` package. It now maps to: **Milestone M0** (scaffold + migration `0010_ml_vertical`); cross-cutting contracts for **F002/F003/F004**.
>
> Substrate corrections (see `00-master-plan.md` §2 and the canonical spec): package `redsim/` → `aegis/ml/`; schema lives in `aegis/ml/schema.py`; no new `create_app` — ML routers mount on the existing `aegis/api/app.py`; add `targets.detail` JSONB + `ml_campaigns` table via one Alembic migration; widen `RunConfig` to attack-set + ε-grid + MRI weights.
>
> Use this file for the parallel-execution shape only, not the literal paths, signatures, or mechanisms below.

# P0 — Contracts, schema additions & API skeleton

Status: v1, 2026-09-08. Owner: Backend lead. Wave: 0 (blocking, ~0.5 day).
Read `docs/plans/00-master-plan.md` first, section 6 above all. Section 6 is
canonical. Do not invent alternatives.

---

## 1. Objective

Land the day-0 blocker. Freeze the wire contract so every other phase builds
against a fixed surface.

P0 does three things:

1. Add the missing fields to `redsim/schema.py` from master section 6.1. These
   are the `Scoring` model, the ATLAS fields on `AttackInfo`, `severity` on
   `Measurement`, and `scoring` plus `atlas_coverage` on `RunRecord`.
2. Boot a real FastAPI app. Serve the read-only endpoints that need no ML, so
   P5 (web) and P7 (infra) build against a live server from day 0.
3. Ship the shared plumbing the other phases import: the two registry
   singletons, the `redsim` CLI, and a validated `run_record.json` fixture.

After P0 merges, the schema is frozen. Later changes follow the protocol in
section 8.

## 2. Scope — in / out

### In scope

- Schema additions in section 6.1, exactly as written. No other schema edits.
- `redsim/api/app.py` with a `create_app()` factory.
- `redsim/api/routes.py` with `GET /health`, `GET /v1/targets`,
  `GET /v1/attacks`, `POST /v1/runs` (stub behaviour only), `GET /v1/runs`,
  and `GET /v1/runs/{id}`.
- `redsim/targets/registry.py` and `redsim/attacks/registry.py`: the empty
  `TARGETS` and `ATTACKS` singletons that section 6.2 names. P0 creates the
  containers. P1 and P2 register concrete items into them.
- `redsim/cli.py` with `main()`, wired to the dangling `redsim` console script.
- `tests/fixtures/run_record.json`, a full `RunRecord` with a populated
  `scoring` block and `atlas_coverage`.
- `tests/test_api.py` and schema round-trip tests for the new fields.

### Out of scope

- Any target, attack, explain, scoring, or recommend logic. P0 registers no
  concrete target or attack.
- `POST /v1/runs` real execution. P0 returns a stub. P4 completes it.
- `PATCH /v1/runs/{id}/reviewer-notes`, `GET /v1/runs/{id}/artifacts/{path}`,
  and the report routes. P4 owns these.
- Dataset routes. P6 owns these.
- `runs.py`, `jobs.py`, `scoring.py`. Other phases own these.
- Editing any existing field in `schema.py`. Add only.

## 3. Prerequisites & dependencies

- Python 3.12 venv from `make install`. `make test` and `make typecheck`
  already pass.
- These files exist and are read-only inputs to P0:
  - `redsim/schema.py` (188 lines, the models to extend).
  - `redsim/state.py` (`RunStore`, `new_run_id()`, `list_run_ids`).
  - `redsim/registry.py` (`Registry[T]`, `DuplicateRegistration`).
  - `redsim/targets/base.py` (`Target` protocol, `Sample`).
  - `redsim/attacks/base.py` (`AttackAdapter` protocol, `AttackOutput`).
  - `deploy/Dockerfile.api` (declares the `create_app` factory entrypoint).
  - `web/src/lib/api.ts` (client base `http://localhost:8000`, route shapes).
- No other phase blocks P0. P0 blocks all others. Merge it first.

## 4. Interfaces consumed / exposed

### 4.1 Consumed

From `redsim/registry.py`:

```python
class Registry(Generic[T]):
    def register(self, item: T) -> T: ...
    def get(self, item_id: str) -> T: ...        # raises KeyError
    def maybe_get(self, item_id: str) -> T | None: ...
    def ids(self) -> list[str]: ...
    def items(self) -> list[T]: ...
    def __iter__(self) -> Iterator[T]: ...
```

Use `.items()`, `.maybe_get(id)`, and iteration. Do not call `.list()`. It
does not exist (master 6.2).

From `redsim/targets/base.py` and `redsim/attacks/base.py`:

```python
class Target(Protocol):
    id: str
    def info(self) -> TargetInfo: ...            # UI reads status, reason, metadata

class AttackAdapter(Protocol):
    id: str
    def info(self) -> AttackInfo: ...            # UI reads params_schema, atlas fields
```

Routes call `.info()` on each registered item. They never touch the model.

From `redsim/state.py`:

```python
RunStore.list_run_ids(output_dir=...) -> list[str]
RunStore.open(run_id, output_dir=...) -> RunStore | None
RunStore.load_record() -> dict | None
new_run_id() -> str
```

### 4.2 Exposed

New registry singletons (master 6.2). Other phases import these exact objects:

```python
# redsim/targets/registry.py
from redsim.registry import Registry
from redsim.targets.base import Target
TARGETS: Registry[Target] = Registry("target", Target)

# redsim/attacks/registry.py
from redsim.registry import Registry
from redsim.attacks.base import AttackAdapter
ATTACKS: Registry[AttackAdapter] = Registry("attack", AttackAdapter)
```

The app factory (matches `deploy/Dockerfile.api` `CMD`):

```python
# redsim/api/app.py
def create_app() -> FastAPI: ...
```

The HTTP surface P0 serves (master 6.7, design spec section 4):

| Method | Path | P0 behaviour |
|---|---|---|
| GET | `/health` | 200 `{"status":"ok","version": <str>}` |
| GET | `/v1/targets` | 200 list of `TargetInfo`; `[]` while `TARGETS` is empty |
| GET | `/v1/attacks` | 200 list of `AttackInfo`; `[]` while `ATTACKS` is empty |
| POST | `/v1/runs` | 422 unknown/invalid config; 501 registered stub target; 202 `{"run_id": <str>}` stub otherwise |
| GET | `/v1/runs` | 200 list of `RunSummary` from `RunStore` |
| GET | `/v1/runs/{id}` | 200 full `RunRecord`; 404 if absent |

The CLI:

```python
# redsim/cli.py
def main(argv: list[str] | None = None) -> int: ...
# redsim serve [--host H] [--port P] [--reload]   -> runs uvicorn on create_app
# redsim version                                   -> prints the version
# redsim --version                                 -> prints the version
```

### 4.3 Schema additions (master 6.1, exact)

```python
class Scoring(BaseModel):
    mri: int                       # 0-100, rounded
    grade: Literal["A", "B", "C", "D", "F"]
    subscores: dict[str, float]    # keys: S_acc, S_asr, S_eps, S_conf, S_expl
    weights: dict[str, float]      # weight actually applied (renormalized if S_expl absent)
    reference_eps: float
    eps_grid: list[float]
    delta_mri: int | None = None   # set on verify re-run
```

Field additions to existing models:

- `AttackInfo`: `atlas_technique_id: str | None = None` and
  `atlas_technique_name: str | None = None`.
- `Measurement`: `severity: Literal["critical", "high", "medium", "low"] | None = None`.
- `RunRecord`: `scoring: Scoring | None = None` and
  `atlas_coverage: list[str] = Field(default_factory=list)`.

## 5. Ordered implementation steps

1. Branch `p0-contracts-api` off the `redsim-mvp` integration branch.

2. Edit `redsim/schema.py`. Add the `Scoring` class. Place it directly above
   `class RunRecord`, so `RunRecord` can name `Scoring` without a forward
   reference. Copy the field set from section 4.3 exactly. Keep Pydantic v2
   style and match the surrounding models.

3. In `redsim/schema.py`, add `atlas_technique_id` and `atlas_technique_name`
   to `AttackInfo`, after `references`.

4. In `redsim/schema.py`, add `severity` to `Measurement`, after `notes`.

5. In `redsim/schema.py`, add `scoring` and `atlas_coverage` to `RunRecord`,
   after `reviewer_notes`. Use `Field(default_factory=list)` for
   `atlas_coverage`, to match the mutable-default style already used in this
   file. This is the intended reading of the master's `= []`.

6. Create `redsim/targets/registry.py`. Define the `TARGETS` singleton from
   section 4.2. Register nothing. Add a one-line docstring pointing at the
   design spec. P1 populates it.

7. Create `redsim/attacks/registry.py`. Define the `ATTACKS` singleton from
   section 4.2. Register nothing. P2 populates it.

8. Create `redsim/api/routes.py`. Build one `APIRouter`. Add the six handlers:
   - `GET /health` returns `{"status": "ok", "version": REDSIM_VERSION}`.
     Resolve the version once with `importlib.metadata.version("redsim")`,
     falling back to `"0.1.0"` on `PackageNotFoundError`.
   - `GET /v1/targets` returns `[t.info() for t in TARGETS]`. Empty is valid.
   - `GET /v1/attacks` returns `[a.info() for a in ATTACKS]`. Empty is valid.
   - `POST /v1/runs` accepts a `RunConfig` body. Pydantic returns 422 on a bad
     body automatically. Then look up the target with `TARGETS.maybe_get`.
     Return 422 for an unknown `target_id`. Return 501 when the target's
     `info().status == "not_implemented"`. Otherwise return 202 with
     `{"run_id": new_run_id()}` as a stub. Add a comment that P4 replaces the
     stub with a real `jobs.submit(config)` call.
   - `GET /v1/runs` lists `RunSummary` items. Read `RunStore.list_run_ids()`,
     open each, load the record, and project the summary fields. Skip any run
     whose record fails to load. Sort newest first.
   - `GET /v1/runs/{id}` opens the run with `RunStore.open`. Return 404 when it
     is `None`. Otherwise validate the stored dict with
     `RunRecord.model_validate` and return it.
   - Raise `fastapi.HTTPException` with a `detail` string for every error, so
     the body stays `{"detail": ...}` (design spec section 4).

9. Create `redsim/api/app.py`. Write `create_app() -> FastAPI`. Add
   `CORSMiddleware` allowing origin `http://localhost:3000`, all methods, all
   headers. Include the router from `routes.py`. Return the app. Do not create
   a module-level `app`. The Dockerfile calls the factory with `--factory`.

10. Decide the registration seam. P0 does not import concrete target or attack
    modules, so the endpoints return `[]` at P0. Record in `app.py` a single
    commented import block where P1/P2/P4 will import their concrete modules to
    trigger registration. Note this in section 9 as a coordination point.

11. Create `redsim/cli.py`. Use `argparse`. Implement `main(argv=None)`.
    - `serve` runs `uvicorn.run("redsim.api.app:create_app", factory=True,
      host=..., port=..., reload=...)` with defaults host `0.0.0.0`, port
      `8000`.
    - `version` and `--version` print the resolved version.
    - Return `0` on success. Return `2` on an unknown command.
    - Guard the entrypoint with `if __name__ == "__main__": raise SystemExit(main())`.

12. Create `tests/fixtures/run_record.json`. Shape it like `GET /v1/runs/{id}`,
    a full `RunRecord` with `status: "succeeded"`. Populate every field P5
    renders. See section 7 for the required contents.

13. Add tests. See section 7.

14. Run `make typecheck` and `make test`. Fix findings. Do not touch the
    pre-existing `lint-py` and `lint-web` breakage noted in `CLAUDE.md`.

15. Open a PR into `redsim-mvp`. In the description, state that the schema is
    now frozen and link section 8.

## 6. Files to create / modify

Create:

- `redsim/api/app.py`
- `redsim/api/routes.py`
- `redsim/targets/registry.py`
- `redsim/attacks/registry.py`
- `redsim/cli.py`
- `tests/fixtures/run_record.json`
- `tests/test_api.py`
- `tests/test_schema_additions.py`

Modify:

- `redsim/schema.py` (add only; edit no existing field)

Do not modify: `deploy/Dockerfile.api`, `web/src/lib/api.ts`, `pyproject.toml`
(the `redsim` console script and all deps already exist).

## 7. Testing & validation

All tests run offline in under a second. None loads torch, ART, or SHAP.

`tests/test_api.py`, using `fastapi.testclient.TestClient(create_app())`:

- `test_create_app_boots`: `create_app()` returns a `FastAPI` instance without
  raising.
- `test_health_ok`: `GET /health` returns 200. Body has `status == "ok"` and a
  non-empty `version` string.
- `test_targets_empty`: `GET /v1/targets` returns 200 and `[]` at P0, because
  P0 registers no target.
- `test_attacks_empty`: `GET /v1/attacks` returns 200 and `[]` at P0.
- `test_run_unknown_target_422`: `POST /v1/runs` with a valid body naming an
  unregistered `target_id` returns 422.
- `test_run_bad_body_422`: `POST /v1/runs` with `n_samples` below the schema
  minimum returns 422.
- `test_runs_list_empty`: `GET /v1/runs` returns 200 and `[]` against an empty
  output dir. Set `REDSIM_OUTPUT_DIR` to a `tmp_path` for this test.
- `test_run_not_found_404`: `GET /v1/runs/does-not-exist` returns 404 with a
  `detail` key.

Guard the two registry-population tests. If a later phase registers a stub
target on import, add a variant that asserts a registered
`not_implemented` target makes `POST /v1/runs` return 501. Keep the empty-case
tests valid for the P0 merge.

`tests/test_schema_additions.py`:

- `test_scoring_round_trip`: build a `Scoring`, dump it, reload it, assert
  equality. Assert the subscore keys are `S_acc, S_asr, S_eps, S_conf, S_expl`.
- `test_attack_info_atlas_fields`: `AttackInfo` accepts `atlas_technique_id`
  and `atlas_technique_name`, and both default to `None`.
- `test_measurement_severity`: `Measurement` accepts `severity="high"` and
  rejects `severity="bogus"`.
- `test_run_record_scoring_and_coverage`: `RunRecord` accepts a `Scoring` and a
  populated `atlas_coverage`, and both have sane defaults (`None` and `[]`).
- `test_fixture_validates`: load `tests/fixtures/run_record.json` and pass it
  through `RunRecord.model_validate`. It must validate with no error. This is
  the contract check that keeps the P5 fixture honest.

`tests/fixtures/run_record.json` must contain, at minimum:

- `run_id`, `status: "succeeded"`, `stage: "report"`, `stages_done` (the full
  `STAGES` list), `created_at`, and a valid `config` (`RunConfig`).
- `target`: a `TargetInfo` with `status: "available"`.
- `attack`: an `AttackInfo` with `atlas_technique_id: "AML.T0043"` and
  `atlas_technique_name: "Craft Adversarial Data"`.
- `provenance`: a full `Provenance` with `started_at` and `finished_at`.
- `measurements`: three rows (`clean`, `evasion`, `control`). Give the evasion
  row a `severity` such as `"high"`.
- `observations`: at least two, one flipped and one not, each with `artifacts`
  paths and both `center_mass_ratio_*` values.
- `interpretation` and `recommendations`: at least one each, with `basis` and
  `triggered_by` that cite real measurement ids.
- `scoring`: a full `Scoring`. Include all five subscore keys, the matching
  `weights`, `reference_eps`, and an `eps_grid`. Example `mri: 62`,
  `grade: "C"`.
- `atlas_coverage`: `["AML.T0043"]`.
- `limitations`: the seven `STANDING_LIMITATIONS` strings. The `RunRecord`
  validator rejects a succeeded run with an empty `limitations` list.

Validate the fixture two ways before commit:

1. `python -c "import json; from redsim.schema import RunRecord;
   RunRecord.model_validate(json.load(open('tests/fixtures/run_record.json')))"`
   prints nothing and exits 0.
2. Boot the server, and manually confirm `GET /health` returns
   `{"status":"ok","version":...}` and `GET /v1/targets` returns `[]`.

## 8. Acceptance criteria / Definition of Done

- [ ] `redsim/schema.py` adds `Scoring`, the two `AttackInfo` ATLAS fields,
      `Measurement.severity`, and `RunRecord.scoring` plus
      `RunRecord.atlas_coverage`. Field names and types match master section
      6.1 exactly. No existing field changed.
- [ ] `uvicorn redsim.api.app:create_app --factory --port 8000` boots and
      serves. This matches the `deploy/Dockerfile.api` `CMD`.
- [ ] `GET /health` returns `{"status":"ok","version":<str>}`.
- [ ] `GET /v1/targets` and `GET /v1/attacks` return `[]` at P0 and read from
      `TARGETS` and `ATTACKS`.
- [ ] `POST /v1/runs` returns 422 for a bad body or unknown target, 501 for a
      registered stub target, and a 202 `{"run_id"}` stub otherwise.
- [ ] `GET /v1/runs` and `GET /v1/runs/{id}` read `RunStore` and return 404 for
      a missing run.
- [ ] `TARGETS` and `ATTACKS` singletons exist at the section-6.2 import paths.
- [ ] `redsim serve` and `redsim version` work. The `pyproject.toml` console
      script `redsim` is no longer dangling.
- [ ] `tests/fixtures/run_record.json` validates against `RunRecord` and holds
      a populated `scoring` block and `atlas_coverage`.
- [ ] `make test` and `make typecheck` pass. No new `lint-py` or `lint-web`
      regressions beyond the pre-existing ones.
- [ ] The PR states the schema is frozen and records the change protocol below.

### What P0 must freeze

This phase is the day-0 blocker. After merge, treat these as locked:

- Every field name and type in `redsim/schema.py`, old and new. P5 renders
  against these. P2 writes `Scoring`. P3 sets `severity`. Any rename breaks a
  parallel phase silently.
- The six endpoint shapes in section 4.2 and their status codes.
- The `TARGETS` and `ATTACKS` import paths and their `Registry` API (`.items`,
  `.maybe_get`, iteration, no `.list`).
- The `create_app()` factory name and module path.
- The `run_record.json` fixture shape, which P5 renders before P4 is done.

### Change protocol after freeze

1. Do not change a schema field or an endpoint shape silently.
2. Announce any change as a one-line note in master section 6.1, plus a
   heads-up to the team.
3. Prefer adding an optional field over changing an existing one. Additive,
   default-valued fields do not break a parallel phase. Renames and type
   changes do.

## 9. Effort estimate & special considerations

Estimate: about half a day for one backend developer. The schema edits are
small. The app, routes, CLI, and fixture are the bulk. The work is low-risk
because it wires no ML.

Special considerations:

- The registries are a coordination seam. Master 6.2 attributes `TARGETS` to
  P1 and `ATTACKS` to P2, but P0's endpoints must import them on day 0. P0
  therefore creates the empty singleton containers, and P1/P2 only add
  `.register(...)` calls. Confirm this split with the P1 and P2 owners so no
  one redefines the singleton and shadows the shared instance.
- Registration triggers on import. The endpoints return `[]` until something
  imports the concrete target and attack modules. P0 leaves a commented import
  block in `app.py` for P1/P2/P4 to fill. Flag this so a populated
  `/v1/targets` does not silently wait on nobody importing the modules.
- `atlas_coverage` default. Master 6.1 writes `= []`. Use
  `Field(default_factory=list)` to avoid a shared mutable default, matching the
  rest of `schema.py`. The wire shape is identical.
- Version source. Read the version from installed package metadata, not a
  hard-coded string, so `/health` stays true after a version bump.
- Do not touch the pre-existing `lint-py` and `lint-web` breakage. `CLAUDE.md`
  records both as inherited, not caused here. `make test` and `make typecheck`
  are the gate.
- Follow repo prose conventions in code comments and this doc: no em dashes, no
  semicolons.
