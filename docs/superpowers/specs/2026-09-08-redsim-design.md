# redsim — Adversarial ML Evaluation Simulator (design spec)

Date: 2026-09-08
Status: approved design, pre-implementation
Repo: https://github.com/IntelliBridge/ndia-red-team-simulator (forked copy of IntelliBridge/aegis)
Foundation document: the Replit "AI Assurance — Project Brief" (reproduced in
`docs/brief.md`). Where this spec and the brief differ, the brief wins.

## 1. Purpose and scope

redsim is a non-operational proof of concept that evaluates the robustness of a
machine-learning classifier under adversarial evasion attacks, shows evidence
of *what* changed in the model's behaviour, and lists **candidate**
recommendations for hardening. It runs on public or synthetic data only.

The tool exists to demonstrate one documented, benign, reproducible evaluation
workflow with human review, not to certify models or to support operational
military systems.

### In scope for the first milestone

- One live evaluation domain: **image classification** on a bundled model.
- ART evasion attacks (FGSM, PGD) plus a benign random-noise control at the
  same perturbation budget.
- SHAP attribution on clean and adversarial inputs, presented as supporting
  evidence, not causal proof.
- A run record that keeps **measurements, observations, interpretation, and
  candidate recommendations** in separate fields.
- Markdown / JSON / HTML reports that preserve enough configuration to rerun.
- A web UI: pick a target, pick an attack, launch, then view evidence and
  recommendations side by side.
- Tabular and LLM domains **registered but not evaluated**. They appear in the
  UI as unavailable with a stated reason. The LLM target accepts a LiteLLM model
  string so the connection shape is real; launching returns HTTP 501.

### Explicitly out of scope (from the brief)

- Uploading and executing arbitrary model artifacts.
- Live connections to operational or sensitive systems; sensitive datasets.
- A training-data poisoning pipeline.
- Autonomous application of mitigations.
- A universal "robustness score" that mixes test families or domains.
- Any claim of certification, causal certainty, or deployment readiness.
- Authentication, multi-tenancy, audit chain, observability stack (all present
  in aegis, all removed here).

## 2. Architecture

```
browser ──▶ Next.js 14 (web/)  ──HTTP──▶ FastAPI (redsim/)  ──▶ ./redsim_output/runs/<run_id>/
                                                │
                                                ├─ targets/   bundled models + dataset slices
                                                ├─ attacks/   ART adapters (registry)
                                                ├─ explain/   SHAP gradient explainer
                                                ├─ recommend/ rule-based candidates (+ optional LLM narrative)
                                                └─ report.py  md / json / html
```

No database, no queue, no auth. Runs execute in a `ThreadPoolExecutor` inside
the API process; status is persisted to `run.json` in the run directory so a
restart loses nothing but in-flight work. The frontend polls with SWR.

### 2.1 Python package `redsim/`

Python 3.12. Dependencies: `fastapi`, `uvicorn`, `pydantic>=2`, `numpy`,
`torch` (CPU), `torchvision`, `adversarial-robustness-toolbox`, `shap`,
`matplotlib`, `pyyaml`. Optional extras: `llm` (`litellm`), `garak` (`garak`),
`dev` (`pytest`, `ruff`, `mypy`).

Modules copied from aegis nearly verbatim (rename import paths only):

| aegis source | redsim destination | Why |
|---|---|---|
| `aegis/registry.py` | `redsim/registry.py` | Generic `Registry[T]` with duplicate detection; standard-library only |
| `aegis/audit/redact.py` | `redsim/redact.py` | Secret-token regexes used by guardrails |
| `aegis/llm/guardrails.py` | `redsim/recommend/guardrails.py` | Secret scrubbing + prompt-injection detection for the optional LLM narrative |
| `aegis/state/facade.py` + `aegis/state/filesystem.py` | `redsim/state.py` | `RunState` protocol + filesystem impl: run dir, artifact refs with sha256 |
| `aegis/report.py` lines 286–375 (`html_escape`, `render_inline_markdown`, `_md_to_html_min`) | `redsim/report.py` | XSS-safe markdown→HTML with no template engine |

New modules:

- `redsim/schema.py` — Pydantic v2 models (section 3).
- `redsim/targets/` — `base.py` (`Target` protocol: `domain`, `id`, `name`,
  `status`, `load()`, `sample(n, seed)`, `predict(x)`, `metadata()`),
  `image_cifar10.py` (live), `tabular_stub.py`, `llm_stub.py`, `registry.py`.
- `redsim/attacks/` — `base.py` (`AttackAdapter` protocol: `id`, `name`,
  `domain`, `family`, `params_schema`, `run(target, x, y, params) -> AttackOutput`),
  `fgsm.py`, `pgd.py`, `noise_control.py`, `registry.py`.
- `redsim/explain/shap_image.py` — `explain(target, x_clean, x_adv, seed) -> ExplainOutput`.
- `redsim/recommend/rules.py` — deterministic rules; `narrative.py` optional LLM.
- `redsim/runs.py` — orchestration: create run dir, execute pipeline, write
  `run.json` after each stage.
- `redsim/jobs.py` — thread pool + in-memory handle table.
- `redsim/api/app.py` — `create_app()` factory, CORS for `localhost:3000`.
- `redsim/api/routes.py` — routes (section 4).
- `redsim/setup_assets.py` — CLI: downloads CIFAR-10 test split via
  torchvision, trains the small CNN for a fixed number of epochs with a fixed
  seed, writes `assets/cifar10_smallcnn.pt` and `assets/MANIFEST.json`
  (dataset name/version, split, model arch, epochs, seed, clean test accuracy,
  torch version, sha256 of weights).

### 2.2 Bundled image target

- Dataset: **CIFAR-10** test split (public, benign, 10 everyday classes,
  32×32). Chosen over aircraft / vehicle / satellite datasets to keep the
  demo unambiguously non-operational.
- Model: a small CNN (2 conv blocks + 2 FC) trained by `setup_assets.py` on
  the train split, seed fixed, target clean accuracy 65–75 %. The exact
  achieved value is recorded in `MANIFEST.json`, never hard-coded in docs.
- Evaluation slice: default 200 test images, stratified by class, seed
  recorded. The UI allows 50–500.

### 2.3 Attacks

All attacks wrap the target in ART's `PyTorchClassifier`.

| id | family | params (defaults) | ART class |
|---|---|---|---|
| `fgsm` | evasion, white-box | `eps` (0.03, L∞) | `FastGradientMethod` |
| `pgd` | evasion, white-box | `eps` (0.03), `eps_step` (0.007), `max_iter` (10) | `ProjectedGradientDescent` |
| `noise_control` | control | `eps` (matches attack) | uniform noise in the same L∞ ball, no gradient |

`AttackOutput`: `x_adv`, `y_pred_clean`, `y_pred_adv`, `linf_norm_mean`,
`l2_norm_mean`, `wall_time_s`, `art_version`.

### 2.4 Explanation

`shap.GradientExplainer` on the CNN, 50-image background from the evaluation
slice. For each of the first `k` (default 8) samples whose prediction flipped
under attack, and for `k` samples that did not flip, produce:

- `clean.png`, `adv.png` (the images, upscaled),
- `shap_clean.png`, `shap_adv.png` (attribution for the clean-predicted class),
- `center_mass_ratio_clean`, `center_mass_ratio_adv`: fraction of absolute
  attribution inside the central 50 % of the image. **Labelled heuristic** in
  the schema and UI; it is a proxy for "attention on the subject", not a
  segmentation.

Also `shap_version`, `background_size`, `nsamples`, wall time.

### 2.5 Recommendations

`recommend/rules.py` emits `CandidateRecommendation` objects. Each rule cites
the measurement(s) that triggered it. Initial rules:

| Trigger | Candidate |
|---|---|
| `adv_accuracy < clean_accuracy - 0.20` and `noise_control_accuracy ≈ clean_accuracy` | Adversarial training (PGD-based); cite that random noise did not degrade the model, so the failure is gradient-aligned |
| `pgd` degrades more than `fgsm` at the same eps | Iterative attacks matter; evaluate at multiple eps and iterations before deployment |
| mean `center_mass_ratio_adv` drops ≥ 0.15 vs clean on flipped samples | Investigate reliance on peripheral/background pixels; consider input cropping or augmentation. Marked heuristic |
| any degradation | Input preprocessing defenses (JPEG compression, spatial smoothing via ART preprocessors) as a **cheap first experiment**, with the caveat that gradient-masking defenses are often bypassed |
| always | Rerun with a larger slice and a different seed before drawing conclusions |

Every recommendation carries `status: "candidate"` and
`validation: "not evaluated"`. The optional LLM narrative
(`REDSIM_LLM_MODEL` set) rewrites rule outputs into prose through the
guardrails; it may not introduce new claims and is labelled "LLM-generated
narrative of rule outputs" in the UI. Default off.

## 3. Evidence model (`redsim/schema.py`)

```python
class RunConfig(BaseModel):
    target_id: str; attack_id: str; params: dict[str, float | int]
    n_samples: int; seed: int; include_control: bool = True
    explain_k: int = 8

class Provenance(BaseModel):
    redsim_version: str; python: str; torch: str; art: str; shap: str
    model_sha256: str; dataset: str; dataset_split: str; model_manifest: dict
    started_at: datetime; finished_at: datetime | None; hostname: str
    nondeterminism: list[str]   # e.g. "GradientExplainer sampling", "CPU float32 reductions"

class Measurement(BaseModel):         # one per test family
    family: Literal["clean", "evasion", "control"]
    attack_id: str | None
    n: int; n_correct: int; accuracy: float
    n_flipped_from_clean: int | None
    linf_norm_mean: float | None; l2_norm_mean: float | None
    per_class: dict[str, dict[str, int]]   # class -> {n, n_correct}
    wall_time_s: float

class Observation(BaseModel):         # one per explained sample
    sample_index: int; true_label: str; pred_clean: str; pred_adv: str
    flipped: bool
    artifacts: dict[str, str]          # name -> relative path
    center_mass_ratio_clean: float; center_mass_ratio_adv: float
    metric_kind: Literal["heuristic"] = "heuristic"

class Interpretation(BaseModel):
    statement: str
    basis: list[str]                   # measurement/observation ids it rests on
    kind: Literal["inferred"] = "inferred"

class CandidateRecommendation(BaseModel):
    id: str; title: str; rationale: str
    triggered_by: list[str]            # measurement ids
    status: Literal["candidate"] = "candidate"
    validation: Literal["not evaluated"] = "not evaluated"
    references: list[str] = []

class RunRecord(BaseModel):
    run_id: str; status: Literal["queued","running","succeeded","failed","not_implemented"]
    stage: str | None; error: str | None
    config: RunConfig; provenance: Provenance
    measurements: list[Measurement]; observations: list[Observation]
    interpretation: list[Interpretation]
    recommendations: list[CandidateRecommendation]
    limitations: list[str]
    reviewer_notes: str | None = None  # free text a human can add in the UI
```

`limitations` is always non-empty and always includes: slice size, single
seed, single eps unless swept, CIFAR-10 is not a proxy for any operational
domain, SHAP attributions are not causal, and passing does not establish
safety or readiness.

## 4. API

| Method | Path | Behaviour |
|---|---|---|
| GET | `/health` | `{status:"ok", version}` |
| GET | `/v1/targets` | list `TargetInfo{id,name,domain,status,reason,metadata}`; stubs carry `status:"not_implemented"` and a reason |
| GET | `/v1/attacks` | list `AttackInfo{id,name,domain,family,params_schema}` |
| POST | `/v1/runs` | body `RunConfig`; 202 with `{run_id}`; 501 if the target is a stub; 422 on bad params |
| GET | `/v1/runs` | list summaries (id, status, target, attack, created) |
| GET | `/v1/runs/{id}` | full `RunRecord` |
| PATCH | `/v1/runs/{id}/reviewer-notes` | set `reviewer_notes` |
| GET | `/v1/runs/{id}/artifacts/{path}` | PNG/JSON artifact, path confined to the run dir |
| GET | `/v1/runs/{id}/report.{md,json,html}` | rendered report; HTML served with `Content-Security-Policy: default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'` |

Errors are JSON `{detail}`. No auth. CORS allows `http://localhost:3000`.

## 5. Frontend (`web/`)

Keep: Next.js 14 app router, Tailwind, `@aegis/design-system` (renamed
`@redsim/design-system`), `src/lib/api.ts` core (`api<T>`, `ApiError`,
`apiBase`), `src/components/{theme-provider,theme-toggle,command-palette}`,
`app/layout.tsx`, `app/globals.css`, vitest config.

Delete: `app/{login,projects,auth-profiles,agents,tools,audit,cost,logs,findings}`,
`src/server/*`, `src/lib/auth.ts`, `src/hooks/{useRequireAuth,useRoles,useRunEvents}`,
`app/api/auth/**`, `next-auth` and `jose` deps, all their tests. Design-system
components `finding-card`, `evidence-diff`, `audit-chain-badge`, `role-gated`
are deleted; `run-status-badge`, `stage-timeline`, `severity-chip`,
`toast-list` and all primitives stay.

Pages:

- `/` → redirect to `/runs`.
- `/targets` — table of targets: name, domain, status badge, reason when
  unavailable, metadata (dataset, clean accuracy from manifest). "Evaluate"
  button on available targets.
- `/runs/new?target=…` — form: attack (from `/v1/attacks`), params rendered
  from `params_schema`, `n_samples`, `seed`, include control, `explain_k`.
  Submits `POST /v1/runs`.
- `/runs` — table of runs with `RunStatusBadge`, polling every 5 s.
- `/runs/[id]` — the side-by-side page. Header: target, attack, params,
  status, `StageTimeline`. Two columns:
  - **Left, Evidence:** measurements table by family (clean / evasion /
    control) with n and denominators; per-class table (collapsible);
    observation gallery: for each explained sample, clean image, adversarial
    image, SHAP clean, SHAP adv, labels, center-mass ratios marked
    "heuristic".
  - **Right, Interpretation & candidates:** interpretation statements each
    labelled "inferred" with their basis; candidate recommendations each
    labelled "candidate, not evaluated" with the triggering measurement
    linked; limitations list; reviewer notes textarea (PATCH); report
    download links (md / json / html).
  - Stubs: if a run is `not_implemented`, the page shows the reason and no
    fabricated panels.

Nav: Targets · Runs. Title: "redsim". Footer line on every page: "Proof of
concept on public data. Results are evidence for human review, not a safety
or readiness determination."

## 6. Repository layout after the strip

```
redsim/                     new backend package
assets/                     generated by setup_assets.py (gitignored except MANIFEST.json schema)
web/                        Next.js app (pruned)
packages/design-system/     moved from project_repos/design-system
docs/brief.md               the Replit brief, verbatim
docs/superpowers/specs/     this spec
docs/references.md          ART, SHAP, garak, ACL TIP paper, OpenSandbox: role + limits
tests/                      new pytest suite
deploy/docker-compose.yml   two services: api, web
deploy/Dockerfile.api, deploy/Dockerfile.web
pyproject.toml, pnpm-workspace.yaml, Makefile, README.md, .gitignore, .env.example
```

Deleted: `aegis/`, old `tests/`, `project_repos/` (all submodules), `.gitmodules`,
`deploy/{helm,keycloak,opa,cedar,otel,loki,certs,kind.yaml,Dockerfile.{postgres,kali,worker,log_ingest}}`,
`docs/` pentest content, `examples/`, `hooks/`, `scripts/`, `alembic.ini`,
`aegis.yaml`, `mkdocs.yml`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`,
`CODEOWNERS`, `.bandit`, `.semgrep.yml`, `.semgrepignore`, `.trivyignore`,
`uv.lock`, `.github/`, `.claude/`, `scorecard.png`.

## 7. Testing

Backend (`pytest`, all offline, < 60 s total):
- `test_registry.py` — copied aegis tests for duplicate/lookup semantics.
- `test_schema.py` — `RunRecord` round-trip; literals enforce `candidate` /
  `inferred` / `heuristic`; `limitations` non-empty validator.
- `test_attacks.py` — FGSM and PGD on a 1-layer random-weight model over 16
  random images: output shape, L∞ bound respected, deterministic under seed.
- `test_noise_control.py` — control stays inside the eps ball.
- `test_recommend.py` — each rule fires on a synthetic measurement set and
  cites the right ids; nothing fires on a flat set except the "rerun" rule.
- `test_report.py` — md contains the six sections in order; html escapes a
  `<script>` in a class name; json equals `RunRecord.model_dump()`.
- `test_api.py` — TestClient: targets list shows one available and two
  `not_implemented`; POST run on stub → 501; artifact path traversal → 404.

Frontend (`vitest`): `runs/[id]/page.test.tsx` renders a fixture `RunRecord`
and asserts the four evidence sections and the "candidate" / "inferred" /
"heuristic" labels are present; `targets/page.test.tsx` shows the
unavailable reason for stubs.

## 8. Completion criteria (mirrors the brief)

1. A teammate can follow `README.md` from clone to a finished CIFAR-10 FGSM
   run in the browser in under 15 minutes on a laptop CPU.
2. Every measurement, observation and recommendation in the UI links to a
   file in the run directory.
3. `report.json` contains everything needed to rerun (`config` +
   `provenance`), and lists nondeterminism sources.
4. Interpretation and recommendations are visually and structurally distinct
   from measurements.
5. Tabular and LLM targets are visible as not implemented; nothing is faked.
6. Limitations are visible on every run page and in every report.
