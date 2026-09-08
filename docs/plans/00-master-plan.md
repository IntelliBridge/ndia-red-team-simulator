# redsim — Master Implementation Plan

Status: v1, 2026-09-08. Scope: hackathon Phase A + interoperability, deployed
live on AWS ECS. Team: 3-4 developers working in parallel.

This is the coordination document. Each phase has its own detailed plan in this
directory (`01-*.md` through `08-*.md`). Read this file first, then your phase
file. Build against the **shared contracts** in section 6 so parallel work
integrates cleanly.

---

## 1. Goal

Ship a working adversarial-ML red-team simulator that a judge can drive in a
browser against the deployed AWS stack. A user picks a model target, launches an
attack, and sees the adversarial examples, the SHAP explanation, a Model
Robustness Index (MRI) scorecard, and candidate hardening recommendations, side
by side. The run's adversarial examples publish as a Croissant dataset another
team can consume, and every finding carries its MITRE ATLAS technique.

The four locked decisions that shape this plan:

- **Team:** 3-4 developers. Work is sliced into 8 discrete phases with explicit
  interface contracts.
- **Architecture:** the `redsim` package and its design spec
  (`docs/superpowers/specs/2026-09-08-redsim-design.md`) are authoritative for
  the core. The hackathon spec (`docs/adversarial-ml-redteam-spec.md`) layers on
  three additions: MRI scoring, interoperability (Croissant + MITRE ATLAS), and
  the AWS ECS deployment.
- **Done bar:** the demo runs live on AWS ECS Fargate. Infrastructure is on the
  critical path, not a stretch.
- **Feature scope:** Phase A (image + tabular; FGSM/PGD/noise; SHAP; MRI;
  recommendations; the two-column UI) plus interoperability (Croissant dataset
  export, ONNX ingest, MITRE ATLAS tagging). Text, object detection, black-box
  attacks, and Palantir/Lattice are out of scope for this plan.

## 2. Reconciling the two specs

The hackathon spec predates the `redsim` restructure, so where they differ, the
`redsim` design spec wins. Concretely:

- **Persistence** is the filesystem `RunStore` (design spec), not Postgres/RLS.
  On AWS the run directory lives on an EFS mount; S3 holds published datasets
  and reports.
- **Jobs** run on an in-process thread pool (`redsim/jobs.py`), not Celery.
- **The evidence model** is `measurements` / `observations` / `interpretation` /
  `recommendations` on `RunRecord`, not an aegis-style `Finding` table. MRI and
  ATLAS attach to these models, defined in Phase 0.
- **Deployment** is ECS Fargate (hackathon spec), replacing the design spec's
  local docker-compose as the done bar, while compose stays the local dev target.

## 3. Current state (verified inventory)

- **Backend contracts exist and are frozen-ish:** `schema.py` (all record
  models), `state.py` (`RunStore`), `registry.py` (`Registry`),
  `targets/base.py` (`Target` Protocol, `Sample`), `attacks/base.py`
  (`AttackAdapter` Protocol, `AttackOutput`), `recommend/guardrails.py`,
  `recommend/pythia_client.py`, `redact.py`, `report.py` (helpers only).
- **Backend implementations are missing:** every target/attack/explain
  implementation, `recommend/rules.py`, `recommend/narrative.py`, `runs.py`,
  `jobs.py`, `api/app.py`, `api/routes.py`, `setup_assets.py`, `cli.py`.
- **Frontend shell exists:** layout, nav, theming, command palette, and the
  `api<T>` client (`web/src/lib/api.ts`, base `NEXT_PUBLIC_REDSIM_API_URL` →
  `http://localhost:8000`). All four feature routes are placeholders. The
  design system (`@redsim/design-system`) ships `Table`, `Card`, `Alert`,
  `Input`, `Textarea`, `Tooltip`, `AlertDialog`, `Command`, plus `RunStatusBadge`,
  `SeverityChip`, `StageTimeline`, `ToastList`.
- **CI/CD exists:** GitHub OIDC role, three ECR repos, and
  `.github/workflows/deploy-aws.yml` build both images and hold a deploy job
  that activates once the ECS repo variables are set.
- **The API entrypoint is a stub:** `redsim.api.app:create_app` does not exist,
  so the built `api` image serves nothing yet.

## 4. Phase catalog

| Phase | Name | Owner role | Critical path |
|---|---|---|---|
| **P0** | Contracts, schema additions & API skeleton | Backend lead | Yes — blocks all |
| **P1** | Targets & assets (CIFAR-10 image + tabular) | Dev A | Yes |
| **P2** | Attacks & MRI scoring | Dev B | Yes |
| **P3** | Explanation, recommendations & ATLAS | Dev C | Yes |
| **P4** | Orchestration & API wiring | Backend lead | Yes — integration spine |
| **P5** | Web UI | Dev D | Yes |
| **P6** | Interoperability (Croissant + ONNX ingest) | rotates in | No — after P4 |
| **P7** | Infrastructure & CD to AWS ECS | Dev D or lead | Yes — parallel from day 0 |

## 5. Dependency graph and wave schedule

```
Wave 0  (blocking, ~0.5 day)
  P0  Contracts + schema additions + booting API skeleton
        │  freezes schema.py additions, registries, endpoint shapes
        ▼
Wave 1  (parallel, the bulk of the build)
  P1 Targets ──┐
  P2 Attacks+MRI ─┼─► feed interfaces to P4
  P3 Explain+Rec ─┘
  P5 Web UI ........ builds against P0 endpoints + fixtures (no backend block)
  P7 Infra ......... builds against the P0 booting image (no backend block)
        │
        ▼
Wave 2  (integration)
  P4  runs.py pipeline wires P1+P2+P3; jobs.py; report builders; POST /runs live
  P6  Croissant export + ONNX ingest built on real run outputs
        │
        ▼
Wave 3  (end-to-end on AWS)
  P7+P4+P5 deploy, smoke-test the demo path live, tune
```

Coordination seams inside Wave 1:

- **P2 needs one value from P3.** The MRI explanation-stability subscore
  (`S_expl`) consumes `expl_shift` from P3's SHAP output. P2 builds everything
  else first and integrates `S_expl` last against the agreed function shape in
  section 6. Until P3 lands, P2 scores with `S_expl` omitted and the weight
  renormalized.
- **P4 starts in Wave 1** by scaffolding `runs.py`/`jobs.py` against the
  Protocols and registries, then completes wiring in Wave 2 as P1-P3 land.
- **P5 and P7 never block on backend logic.** P5 renders fixtures shaped like
  the section-6 API responses; P7 needs only `/health` from the P0 skeleton.

## 6. Shared contracts (the integration boundaries)

Everyone codes to these. P0 lands them first. Do not change a signature without
announcing it in this section.

### 6.1 Schema additions (P0, in `redsim/schema.py`)

```python
class Scoring(BaseModel):
    mri: int                       # 0-100, rounded
    grade: Literal["A","B","C","D","F"]
    subscores: dict[str, float]    # keys: S_acc, S_asr, S_eps, S_conf, S_expl
    weights: dict[str, float]      # the weight actually applied (renormalized if S_expl absent)
    reference_eps: float
    eps_grid: list[float]
    delta_mri: int | None = None   # set on verify re-run

# additions to existing models
# AttackInfo:   atlas_technique_id: str | None = None   # e.g. "AML.T0043"
#               atlas_technique_name: str | None = None  # "Craft Adversarial Data"
# Measurement:  severity: Literal["critical","high","medium","low"] | None = None
# RunRecord:    scoring: Scoring | None = None
#               atlas_coverage: list[str] = []           # technique ids exercised
```

`ExplainOutput` is a dataclass owned by P3 in `redsim/explain/base.py`:

```python
@dataclass
class ExplainOutput:
    observations: list[Observation]     # schema.Observation, artifacts already written
    expl_shift_mean: float              # mean 1 - cosine(SHAP_clean, SHAP_adv) over flipped
    shap_version: str
    background_size: int
    nsamples: int
    wall_time_s: float
```

### 6.2 Registries

```python
from redsim.targets.registry import TARGETS   # Registry[Target]   (P1)
from redsim.attacks.registry import ATTACKS    # Registry[AttackAdapter]  (P2)
# use .get(id), .maybe_get(id), .ids(), .items(), iteration — NOT .list()
```

### 6.3 Scoring (P2, `redsim/scoring.py`)

```python
def score_run(measurements: list[Measurement],
              expl_shift_mean: float | None,
              reference_eps: float,
              eps_grid: list[float]) -> Scoring: ...

def severity_for(measurement: Measurement,
                 eps_small: float, eps_mid: float) -> str: ...  # critical|high|medium|low
```

### 6.4 Explanation (P3, `redsim/explain/shap_image.py` and `shap_tabular.py`)

```python
def explain(target: Target, sample: Sample, x_adv: np.ndarray,
            k: int, seed: int, store: RunStore) -> ExplainOutput: ...
```

### 6.5 Interpretation & recommendations (P3, `redsim/recommend/rules.py`)

```python
def interpret(measurements, observations, scoring) -> list[Interpretation]: ...
def recommend(measurements, observations, scoring) -> list[CandidateRecommendation]: ...
# narrative.py rewrites recommendations via pythia_client, guardrailed, off by default
```

### 6.6 Orchestration (P4)

```python
# redsim/runs.py
def run_pipeline(config: RunConfig, store: RunStore) -> RunRecord: ...  # writes run.json after each STAGE
# redsim/jobs.py
def submit(config: RunConfig) -> str: ...        # returns run_id, runs pipeline on the pool
def status(run_id: str) -> RunSummary | None: ...
```

### 6.7 HTTP API (P0 skeleton, P4 completes; P6 adds dataset routes)

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
| POST | `/v1/runs/{id}/dataset` | P6 | 202/200 `{dataset_id}` builds Croissant+Parquet |
| GET | `/v1/datasets/{id}` | P6 | Croissant JSON-LD manifest |

### 6.8 Environment contract (P7 provides, all consume)

`REDSIM_OUTPUT_DIR` (EFS mount on ECS), `REDSIM_S3_BUCKET` (datasets/reports),
`PYTHIA_BASE_URL` / `PYTHIA_API_KEY` / `REDSIM_LLM_MODEL` (Secrets Manager,
narrative off unless all set), `NEXT_PUBLIC_REDSIM_API_URL` (web → API ALB URL).

## 7. Integration strategy

- **One integration branch** (`redsim-mvp`) off `main`. Each phase works on a
  short-lived branch and opens a PR into it. `main` stays releasable.
- **P0 merges first** and tags the schema as frozen. Later schema changes go
  through a one-line note in section 6.1 plus a heads-up to the team.
- **Fixtures unblock the UI.** P0 commits `tests/fixtures/run_record.json`
  shaped like `GET /v1/runs/{id}`, including `scoring` and `atlas_coverage`, so
  P5 renders the real screen before P4 is done.
- **Vertical smoke test** lands as soon as P4 wires one target + FGSM + SHAP:
  `POST /v1/runs` → poll → `GET /v1/runs/{id}` shows measurements, a scorecard,
  and observations. That path is the demo and the acceptance gate.

## 8. Suggested ownership for 3-4 developers

- **Backend lead:** P0 then P4 (the API + pipeline spine); pairs on P7.
- **Dev A:** P1 (targets + assets), then P6 (interop) since ONNX ingest is a
  target.
- **Dev B:** P2 (attacks + MRI scoring).
- **Dev C:** P3 (explain + recommend + ATLAS); pairs into P5 for the scorecard
  and gallery rendering.
- **Dev D (if present):** P5 (web UI) and P7 (infra); otherwise the lead and Dev
  A split P7, and P5 is shared by C and D.

## 9. Risks and mitigations

- **Image size / build time (torch + ART + SHAP).** Mitigate: CPU torch wheel
  in the worker image (already in `Dockerfile.api`), pin versions, GHA layer
  cache. Bake trained CNN weights as an asset; never train at container start.
- **EFS + ECS wiring is fiddly and on the critical path.** Mitigate: P7 starts
  day 0, proves `/health` behind the ALB with the P0 skeleton before any ML
  lands. Fallback: single Fargate task with a local volume for the demo.
- **SHAP on images is slow.** Mitigate: small CNN, small eval slice (default
  200, allow 50), `explain_k` default 8, cache explanations per run.
- **P2↔P3 coupling on `S_expl`.** Mitigate: the agreed function shape in 6.1/6.3;
  P2 renormalizes weights when `expl_shift_mean is None`.
- **Pythia LLM optional and private.** Mitigate: narrative is off by default;
  rules-only recommendations are the baseline demo.
- **Scope creep to text/detection/black-box.** Mitigate: frozen scope in
  section 1; those stay out until the image+tabular path runs end to end on AWS.

## 10. Global definition of done

1. `POST /v1/runs` against the **deployed AWS ECS** stack runs the full pipeline
   for the CIFAR-10 image target and a tabular target with FGSM and PGD.
2. `GET /v1/runs/{id}` returns measurements, an MRI `scoring` block with grade,
   observations with SHAP artifacts, interpretation, and candidate
   recommendations; each attack carries its ATLAS technique.
3. The web UI, served from ECS, renders `/targets`, `/runs`, `/runs/new`, and
   the two-column `/runs/[id]` with the scorecard, the clean-vs-adversarial
   gallery, SHAP images, and recommendations.
4. `POST /v1/runs/{id}/dataset` publishes a Croissant + Parquet adversarial
   dataset to S3, and `GET /v1/datasets/{id}` returns its manifest.
5. A push to `main` builds both images and the deploy job rolls the ECS
   services green (the guard passes because the service variables are set).
6. `pytest` and `vitest` pass for the new modules and pages.
7. Every user-facing panel keeps the design spec's honesty labels: candidates
   are "candidate / not evaluated", heuristics are marked, stubs show a reason.
