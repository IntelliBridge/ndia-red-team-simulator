# redsim/ml — Master Implementation Plan (reconciled)

Status: v2.1, 2026-09-08 (later). Supersedes v1, amends v2. This version is
rebased on the **redsim platform** (the aegis platform kept whole under D1 and
renamed to the `redsim` namespace in commit `b39d933`) after the `main`
restructure of 2026-09-08.

## 0. What changed since v1 (read this first)

### v2.1 — 2026-09-08 (later): change note

What changed in this revision and why. Nothing below alters a D1–D13 decision
except D7, which the product owner amended.

Two commits earlier the same afternoon already touched every file in this
directory: `c582c40` (interop adopted as B2, the malicious-URLs dataset, the
`@redsim/*` web packages, CLAUDE.md marked current) and `836b0e1` (every
`aegis` path and identifier in the plans flipped to `redsim`). v2.1 builds on
both, adds what they did not carry (the amended D7 as the reason for the
rename, the frozen contract names on PR #8, the workstream status, the Pythia
access facts) and restates the rest so this file reads as one document.

- **(a) Rename.** D7 was amended by the product owner: redsim is the product
  name AND the code name. Commit `b39d933` renamed the Python package to
  `redsim/` (import `redsim.…`), the console script to `redsim`, environment
  variables to `REDSIM_*` (including `REDSIM_ML_LLM_MODEL`), the API title to
  "Redsim API", compose services and images to `redsim-*`, the Helm chart to
  `deploy/helm/redsim`, the config file to `redsim.yaml`, the CI workflow to
  `.github/workflows/redsim-ci.yml`, and the web packages to `@redsim/web` and
  `@redsim/design-system` (web env `NEXT_PUBLIC_REDSIM_API_URL`). The ML
  vertical is `redsim/ml/`. Every path and identifier in sections 2, 4 and 5 is
  updated. The v2 line "redsim retired" is struck. Mentions of "aegis" that
  refer to the upstream project or to history ("forked from aegis", "restored
  from the aegis head") stay correct and are kept.
- **(b) CLAUDE.md.** The v2 note calling the repo `CLAUDE.md` stale is
  withdrawn. It was rewritten on 2026-09-08 (commit `ce3ee02`) onto the
  platform architecture. See section 1 for the one caveat that remains.
- **(c) Tabular demo dataset.** The Kaggle malicious-URLs dataset
  (`sid321axn/malicious-urls-dataset`, CC0) is THE demo tabular dataset and
  `lacg030175/UNSW-NB15` is the fallback (spec section 11, rows 55 of the
  reconciliation table, decision register D001 and D005). v2 named UNSW-NB15 as
  primary. Section 2, section 3 and section 8 are corrected.
- **(d) Interoperability.** Re-proposed and adopted into the product spec as
  section 27, Phase B2 (spec row 57). v2 section 6 said "dropped, decision
  needed". It now records the decision taken.
- **(e) Frozen contracts.** Section 5 names the contracts as they exist on PR #8
  (`feat/ml-core`): `Scoring`, `RunRecord.scoring`, `RunRecord.atlas_coverage`,
  the `AttackInfo` ATLAS fields, `Measurement.severity`, the widened
  `RunConfig`, and the id-keyed `TARGETS` / `ATTACKS` registries. The MRI
  no-renormalize rule is restated beside them.
- **(f) Workstream status.** Section 4.1 maps our open and closed pull requests
  to the workstreams.
- **(g) Pythia access.** Section 5 carries the gateway facts a developer needs
  behind the corporate proxy.
- **(h) Demo-critical order.** Unchanged from D8. Section 7 is as in v2.

### v2 — 2026-09-08: what changed since v1

v1 of this plan was written against a standalone `redsim/` package with a
filesystem store, a thread-pool, no auth, and no audit. That package was
**deleted on `main`**. The repository now:

- keeps the ML vertical in **`redsim/ml/`** (contracts only today), inside the
  full platform restored from the aegis head and renamed;
- is governed by a new canonical product spec,
  `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`, which
  supersedes both the hackathon spec and the lean redsim design spec;
- adds a **Spec Kit feature layer**, `specs/F001`–`F008`, as the feature-level
  source of truth beneath that product spec.

Every architectural assumption in v1 is overridden. The corrections are in
sections 2 and 5. Two things we had **missed** and now cover: authentication
(F001) and the audit chain (F008). One thing that was dropped in the first
consolidation and has since been re-adopted as Phase B2: interoperability (see
section 6).

## 1. Authoritative sources (in order)

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md` — the
   product spec, 27 sections. Decisions D1–D13 (section 4) are final and
   override every source. Section 27 (Interoperability) is Phase B2.
2. `docs/project-brief.md` — governance brief. Its reporting principles are
   design constraints. "Decisions taken (2026-09-08)" records every decision
   and every knowing divergence from the brief and the constitution.
3. `specs/README.md` and `specs/00N-*/` — the Spec Kit feature layer
   (F001–F008), each with spec, plan, and tasks, plus
   `specs/_shared/{architecture,decisions,analysis}.md` (the D001–D007 register:
   D001–D005 resolved, D006 and D007 still open). Where a feature file
   conflicts with the product spec, the product spec wins.
4. This plan and its phase files (`docs/plans/`), the parallel-execution
   overlay.
5. `docs/architecture/*` — platform docs, still accurate for the platform.

Note on D7. The spec text of D7 and of reconciliation row 56 predates the
amendment and still reads "namespace `aegis`, vertical `aegis/ml/`, web app
`@aegis/web`". The product owner amended D7 on 2026-09-08 (later): the Python
namespace is `redsim`. Until those texts are refreshed, read every `aegis/…`
path, `aegis.…` import, `AEGIS_*` variable, `aegis-*` service and `@aegis/*`
package in the spec text, in item 7 of "Decisions taken" in
`docs/project-brief.md`, in the `CLAUDE.md` Naming section and in `README.md`
as `redsim/…`, `redsim.…`, `REDSIM_*`, `redsim-*` and `@redsim/*`. The plan
files in this directory and the `specs/` tree already use the `redsim` names
(commit `836b0e1`).

Note on `CLAUDE.md`. It was rewritten on 2026-09-08 (`ce3ee02`) onto the
platform architecture (Postgres, Celery, Keycloak, audit chain, `.venv` and
`make` workflow) and is no longer stale in the sense v2 meant. Its "Naming"
section and its environment table were written before the rename commit
`b39d933` and still say namespace `aegis` and `AEGIS_*`. Read those as
`redsim` and `REDSIM_*` until it is refreshed. Its "How to run things" and
"Working rules" sections are current. Build against it together with this plan.

## 2. Substrate correction (v1 → v2.1)

| Concern | v1 assumption (wrong now) | v2.1 authoritative (redsim platform) |
|---|---|---|
| Package | standalone `redsim/` (filesystem store, thread pool) | `redsim/ml/…` vertical inside the full platform (D7 as amended). The name survives, the substrate does not |
| Console script and CLI | none | `redsim` (`redsim ml build-assets`, `redsim ml attack`, `redsim audit verify`) |
| Persistence | filesystem `RunStore` on EFS | Postgres + RLS; run record as sha256 Artifact; `ml_campaigns` table; S3/MinIO for bytes (D1) |
| Run progress | `run.json` per stage | `Run.stage_table` JSON column + Redis run-event channel |
| Jobs | in-process thread pool `redsim/jobs.py` | Celery on Redis; admission→execution split; `redsim/workers/job_state.py`; task names prefixed `redsim.` |
| Model loading | in worker process | sandboxed child subprocess `python -m redsim.ml.sandbox_worker` (D2) |
| API | new `redsim/api/app.py:create_app` as a fresh app | routers under `redsim/api/v1/` mounted on the existing `redsim/api/app.py:create_app`; API title "Redsim API" |
| Auth | none | Keycloak OIDC + NextAuth + session cookie; role ranks `scanner<remediator<approver<admin` (F001) |
| Audit | none | hash-chained append-only audit + WORM to S3 (F008), inherited from aegis |
| Storage on AWS | EFS + RDS | RDS PostgreSQL 16 + ElastiCache Redis + **S3 (two buckets, one Object-Lock WORM); no EFS** |
| Config | `REDSIM_OUTPUT_DIR` and friends | `RedsimConfig` (`redsim/config.py`), `redsim.yaml`, `REDSIM_*` env (`REDSIM_DB_URL`, `REDSIM_BROKER_URL`, `REDSIM_BLOB_BACKEND`, `REDSIM_AUTH_MODE`, …) |
| LLM env | `REDSIM_LLM_MODEL` | `REDSIM_ML_LLM_MODEL`, via Pythia only. `redsim/llm/pythia.py` still reads the scaffold name `REDSIM_LLM_MODEL` until the M0 rename lands, and `.env.example` carries both |
| Services and images | two compose services | `redsim-api`, `redsim-worker` (`-Q scans`), `redsim-worker-default` (`-Q default`), `redsim-beat`, `redsim-web`, `redsim-log-ingest`; Helm chart `deploy/helm/redsim`; CI `.github/workflows/redsim-ci.yml` |
| Web | none | `@redsim/web` (Next.js 14, `web/`), `@redsim/design-system` (`packages/design-system/`), `NEXT_PUBLIC_REDSIM_API_URL`, cookies `redsim_api_session` / `redsim_csrf` |
| Demo data | CIFAR-10 | `leibnitz-lab/military_vehicles` (image, spec 11.3.1; `Illia56/Military-Aircraft-Detection` fallback) + Kaggle `sid321axn/malicious-urls-dataset` (tabular, CC0, spec 11.3.3); `lacg030175/UNSW-NB15` is the tabular fallback (11.3.4) and `mstz/spambase` the second fallback and CI tabular fixture (11.3.6); CIFAR-10 is the image CI fixture only (D3, D4(d)) |

## 3. Scope (canonical Phase A)

Image and tabular classifiers, both live end to end. Bundled models plus
white-box upload (ONNX preferred; PyTorch `state_dict` with declared
architecture; full pickles refused; loaded only in the sandboxed worker).
Attacks FGSM and PGD for image, PGD-surrogate and HopSkipJump for tabular, each
paired with a benign noise control, swept over ε `{0.01, 0.03, 0.1}` with a
robustness curve. The tabular target is a URL maliciousness classifier
(sklearn / XGBoost on lexical URL features) trained by the asset build on the
Kaggle malicious-URLs dataset. URL strings are inert data and are never fetched,
resolved or rendered, and feature-space perturbations carry the realizability
caveat of spec 12.9. SHAP explanations, the five-subscore MRI, deterministic
plus Pythia-written recommendations, the verify-after-harden loop with measured
ΔMRI, hash-chained audit, evidence and reports, the web UI, and Keycloak auth
with RLS. The spec states plainly that this scope exceeds a 1–2 day build.

## 4. Workstreams for 3–4 developers

The canonical spec owns the decomposition twice over: milestones **M0–M7**
(build order) and features **F001–F008** (outcome verticals). This plan does not
invent a third. It assigns those to parallel workstreams and gives the
integration waves. Each workstream cites the milestone(s) and feature(s) it
delivers.

| WS | Owner | Milestones | Features | Deliverable |
|---|---|---|---|---|
| **WS0 Scaffold** | Backend lead | M0 | cross-cutting | `redsim/ml/` package, migration `0010_ml_vertical` (`targets.detail` JSONB + `ml_campaigns` table), schema widening (`RunConfig` → attack set + ε grid + MRI weights, landed on #8), new `Action` members + `viewer` rank, `ml` dep group (+`onnx2torch`, `safetensors`), env rename `REDSIM_LLM_MODEL` → `REDSIM_ML_LLM_MODEL`, `/v1/scans` unmounted, `redsim ml build-assets` CLI skeleton. Blocks all. |
| **WS1 Catalog & ingest** | Dev A | M1, M4, M5b | F002 | `redsim/ml/targets/`, bundled-model seeding via `build-assets`, `POST /v1/models` upload, `model.validate` sandboxed task, `redsim/services/ml_models.py`, web `/models`. |
| **WS2 Attacks, engine & scoring** | Dev B | M1, M3, M4, M6 | F003, F004 | `redsim/ml/attacks/`, `campaign.py`, `eval.py`, `scoring.py`; the `attack.run` Celery chain (sample→clean_eval→control→attack); MRI + severity. |
| **WS3 Explain, recommend & findings** | Dev C | M2, M3, M6 | F005, F006 | `redsim/ml/explain/`, `recommend/{rules,narrative}.py`, `explain.run` / `harden.recommend` / `verify.replay` tasks, `Finding.schema_blob.ml` projection, dismissal + reviewer-notes routes. |
| **WS4 API & campaign service** | Backend lead | M1–M6 | F004 | routers `redsim/api/v1/{models,attacks,datasets,defenses,ml_capabilities,artifacts,compare,ml_findings}.py` mounted on `redsim/api/app.py`; `redsim/services/ml_campaigns.py`; WS events channel. |
| **WS5 Web UI** | Dev D | M5a, M5b | F005, F006, F007 UI | `@redsim/web` pages `/models`, `/models/[id]` launcher, 13-panel `/runs/[id]`, three-pane `/findings/[id]`; `@redsim/design-system` `MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`, `ObservationCard`. |
| **WS6 Reports & comparison** | rotates | M3, M6 | F007 | extend `redsim/report.py` to render the ML run record + scorecard; `GET /v1/runs/{id}/compare`; report Artifact rows. |
| **WS7 Infra, auth & deploy** | Dev D / lead | M7 | F001, F008 | ECS Fargate services (`redsim-api`, `redsim-worker`, `redsim-beat`, `redsim-web`, `redsim-log-ingest`) + ALB; RDS PostgreSQL 16; ElastiCache Redis; two S3 buckets (one Object-Lock); Secrets Manager; Keycloak on Fargate; activate the existing deploy pipeline. Reuse the audit chain (F008) already in the platform. |

F001 (auth) and F008 (audit) are largely **reused platform foundation**
(inherited from aegis), not new builds; the new work is emitting ML audit events
on the existing chain and wiring Keycloak on Fargate. These are the two features
v1 missed entirely.

### 4.1 Workstream status (2026-09-08, later)

Pull requests on `IntelliBridge/ndia-red-team-simulator` as of this revision.
No names are invented for unassigned work (D007 stays open).

| WS | Branch / PR | State | Notes |
|---|---|---|---|
| WS0 Scaffold (M0, P0) | owned by another engineer | in progress | Not ours. PR #10 `feat/ml-db-migration` (migration `0010_ml_vertical` + `Target` / `Job` kinds) was **closed** so that WS0/P0 has one owner. |
| WS1 targets (pure part), WS2 attacks / engine / scoring, WS3 explain / recommend | #8 `feat/ml-core` | open | Carries the frozen contracts of section 5 (`redsim/ml/{schema,registry,artifacts,errors}.py`, `targets/registry.py`, `attacks/registry.py`) and `docs/workstreams/ml-core.md`. Concrete adapters, explainers and rules land on the same branch as pure modules with no platform imports. |
| WS1 assets (bundled-model seeding) | #9 `feat/ml-assets` | open | Workstream opened (`docs/workstreams/ml-assets.md`). Delivers `redsim ml build-assets`: dataset fetch, bundled model training, `MANIFEST.json`. |
| Cross-cutting: Pythia transport | #11 `feat/pythia-access` | open | Workstream opened (`docs/workstreams/pythia-access.md`). Gateway URL, key provisioning, connectivity check. See the Pythia note in section 5. |
| F008 audit foundation contract | #12 `feat/audit-log-foundation` (William) | **merged** | Contract doc for the audit chain the ML events append to. |
| Earlier contributions | #2 (schema and registry contract tests), #4 (CIFAR-10 target and asset pipeline), both by Metz | closed by their author | Superseded by the platform substrate. CIFAR-10 stays a CI fixture. |
| Not mapped | #16 `feat/replit-redsim-migration` (Metz) | open | Targets a Replit port. D1 (reconciliation rows 1 and 30) rejected the Replit monorepo path. Needs a coordinator decision. Not part of this plan. |
| Dependabot | #13 (docker), #14 (actions), #15 (npm, `web/`) | open | Routine. |
| WS4, WS5, WS6, WS7 | none yet | not started | Start behind Gate 0 per section 7. |

## 5. Corrected shared contracts

- **Schema** (`redsim/ml/schema.py`): the `RunRecord`/`Measurement`/`Observation`/
  `Interpretation`/`CandidateRecommendation` evidence model stays. It is written
  as a sha256-addressed Artifact (`ml.run_record`) and **projected** onto
  `ml_campaigns.score` and `findings.schema_blob.ml`; a projection that
  disagrees with the record is a bug. Frozen on PR #8:
  - `Scoring`: `mri` (int 0–100), `grade` (`A`–`F`), `reading` (attack-scoped
    wording only), `subscores` (`S_acc`, `S_asr`, `S_eps`, `S_conf`, `S_expl`,
    each 0–100), `weights` (the vector used, never renormalized),
    `reference_eps`, `eps_grid`, `attack_ids`, `modality`, `inputs`
    (`acc_clean` and the per-attack `acc_adv` / `asr` / `pert` / `conf_gap` /
    `expl_shift`), `basis_measurements`, and for verify re-runs `delta_from`
    (baseline run id), `delta_mri`, `delta_subscores`. It carries
    `not_a_readiness_statement: Literal[True]`.
  - `RunRecord.scoring: Scoring | None` and `RunRecord.atlas_coverage:
    list[str]` (MITRE ATLAS technique ids exercised, filled in Phase B2, empty
    until then).
  - `AttackInfo.atlas_technique_id` / `atlas_technique_name` (for example
    `AML.T0043` / `Craft Adversarial Data`), `None` until B2 lands.
  - `Measurement.severity: Literal["critical","high","medium","low"] | None`,
    derived per spec 15.5, never hand-set.
  - `RunConfig` widened: `attack_ids` (campaign attack set, with `attack_id` kept
    for the single-attack form), `eps_grid` (default `[0.01, 0.03, 0.1]`),
    `reference_eps` (default `0.03`), `scoring_weights` (`None` means the spec
    defaults), `defense` (`{id, params}` for verify-after-harden re-runs),
    beside `params`, `n_samples`, `seed`, `include_control`, `explain_k`,
    `llm_narrative`.
  - `Provenance.redsim_version` (was `aegis_version` in the spec text).
  Spec 5.3 names `CampaignConfig`, `MRIRecord`, `MLFindingDetail` and
  `MLModelManifest` as M0 additions. On #8 the first two roles are filled by the
  widened `RunConfig` and `Scoring`, which the pure modules read. Whether WS0
  adds the spec names as the platform-side shapes that project from these, or
  the spec text is aligned to these names, is a WS0 / WS2 coordination item and
  not a blocker for #8.
- **Registries** (`redsim/ml/registry.py`): one id-keyed `Registry[T]` class
  with `register(item)` (`TypeError` when the item misses a non-empty string
  `id` or fails the protocol check, `DuplicateRegistration` on a repeated id),
  `get(id)` (`KeyError` on unknown), `maybe_get(id)`, `ids()` (sorted),
  `items()`, `__contains__`, iteration in id order, `len()`, and a `clear()`
  test hook. Singletons `TARGETS` (`redsim/ml/targets/registry.py`,
  `Registry[Target]`) and `ATTACKS` (`redsim/ml/attacks/registry.py`,
  `Registry[AttackAdapter]`). Concrete targets and adapters call
  `register(...)` at import. This is distinct from the name-keyed
  `redsim.registry.Registry` that does entry-point discovery for the platform.
- **Artifact sink** (`redsim/ml/artifacts.py`): `ArtifactSink` protocol
  (`put(name, data, content_type) -> run-relative path`, `sha256(name)`) and a
  `FilesystemSink` for tests. The Celery task adapts the blob store and
  `Artifact` rows to this protocol. Pure modules never import the platform.
- **Errors** (`redsim/ml/errors.py`): `MLError` and its subclasses
  `TargetUnavailable`, `UnsupportedArtifact`, `AttackNotApplicable`,
  `ExplainUnavailable`.
- **Migration**: exactly one — `0010_ml_vertical` — adding `targets.detail`
  (JSONB) and `ml_campaigns` (1:1 with `runs`, full RLS parity). Additive and
  reversible. Owned by WS0.
- **API** (all under `/v1`, on the redsim app, auth + RLS enforced): a campaign
  starts with `POST /v1/models/{id}/attacks`, **not** a generic `POST /v1/runs`.
  Read the campaign at `GET /v1/runs/{id}/campaign`; stream a blob at
  `GET /v1/artifacts/{id}`; act on findings via `POST /v1/findings/{id}/{explain,harden,verify}`;
  compare with `GET /v1/runs/{id}/compare?with=`. `POST /v1/scans` is unmounted
  at M0. Phase B2 routes (`POST /v1/runs/{id}/dataset`, `GET /v1/datasets/{id}`,
  `POST /v1/datasets`) return `501 not_implemented` until B2 (section 6).
- **Jobs**: Celery tasks `redsim.model_validate`, `redsim.attack_run`,
  `redsim.explain_run`, `redsim.harden_recommend`, `redsim.verify_replay`,
  `redsim.report_render` (the `redsim.` prefix is what `main` already uses:
  `redsim.scan_start`, `redsim.verify_replay`, `redsim.report_render`). Attacks
  run as a chain, one Job per attack. Admission is audit-first: the audit event
  is appended before any Run/Job row.
- **MRI** (unchanged formula): `round(0.35·S_acc + 0.25·S_asr + 0.20·S_eps +
  0.10·S_conf + 0.10·S_expl)`, computed **only when all five subscores exist**,
  **weights never renormalized** over the available dimensions (spec 15.4: the
  scorecard then shows the available subscores and "MRI not computed:
  <dimension> unavailable (<reason>)"), per campaign only, never shown without
  its subscores, per-family table with denominators, and ε curve.
  `Scoring.weights` records the vector used. A non-default vector puts a badge
  on the scorecard and makes the campaign incomparable with any other. Grade
  text is attack-scoped; the words "hardened", "deployment-ready", "certified",
  "safe" are banned. ΔMRI is the only sanctioned form of "gain" and appears only
  on a verify run whose `settings_hash` matches its baseline.
- **Env**: `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`,
  `PYTHIA_TIMEOUT_S`, `REDSIM_ML_LLM_MODEL`, `REDSIM_ML_WORK_DIR` (and the other
  `REDSIM_ML_*` knobs of spec 20.3, which the spec text still spells
  `AEGIS_ML_*`). LLM calls go through `redsim/llm/pythia.py` under the platform
  router and budget. Transitional state: `PythiaSettings.from_env` reads the
  scaffold's `REDSIM_LLM_MODEL` until the M0 rename lands, and `.env.example`
  carries both names with a comment saying so.
- **Pythia access** (cross-cutting, PR #11, facts as reported by that
  workstream on 2026-09-08): the gateway is
  `https://pythia.fdet.agiledefense.xyz`, reached through the corporate Zscaler
  proxy. The team key is entitled to 27 models, including
  `amazon/nova-lite-v1:0` (the id `tests/test_llm_pythia.py` uses) and the
  router alias `pythia/auto`. `curl` works because it uses the macOS keychain.
  Python clients (`httpx`, `requests`) fail with `CERTIFICATE_VERIFY_FAILED`
  unless they use the system trust store: either `import truststore;
  truststore.inject_into_ssl()` (`truststore` is installed in `.venv`) or
  `SSL_CERT_FILE` pointing at a bundle that contains the Zscaler root
  (`deploy/certs/README.md`). `uv` needs `--native-tls` for the same reason.
  The worker's `default` pool is the only process that makes the call. The API
  and the sandbox child have no Pythia egress.

## 6. Interoperability — decision taken: spec section 27, Phase B2

The interop work John added to the hackathon spec (S1 §14, commit `4acdb85`)
was missing from the first consolidation. It has since been **re-proposed and
adopted** into the product spec as section 27 (reconciliation row 57) and as
milestone **B2 | Interop** in spec section 23. It sits behind every Phase A item
and behind B1+ (D8). Nothing in it is implemented, and nothing in it changes
D1–D13: D3, D5 and D9 bind it.

What B2 delivers, in the consolidated vocabulary:

- **Contribute.** `POST /v1/runs/{id}/dataset` builds a **Croissant**
  (MLCommons JSON-LD) manifest over a Parquet payload from a terminal campaign
  or verify run: clean and adversarial inputs, true / clean / adversarial
  labels with confidences, attack id, norm, ε, `flipped`, and the source-slice
  indices with dataset id, revision and split. Content-addressed
  (`croissant.json` lists each file's sha256, and the manifest sha256 is the
  dataset version), written under `datasets/<run-id>/` and registered as
  `Artifact` rows (`ml.dataset.manifest`, `ml.dataset.parquet`,
  `ml.dataset.card`). `GET /v1/datasets/{id}` returns the manifest. Tabular
  exports carry feature vectors only, never URL strings. Imagery exports stay
  in the team bucket while D006 (export redaction) is open.
- **Consume.** Another team's model arrives as ONNX through the existing upload
  path (section 9 rules unchanged). Another team's evaluation slice arrives as
  Croissant + Parquet through `POST /v1/datasets`, parsed only in the sandbox
  child, refused without a license statement, and never compared with a
  campaign on a bundled dataset (D9(i)).
- **MITRE ATLAS.** Every Finding is tagged with the technique it demonstrates:
  `fgsm` / `pgd` → `AML.T0043 Craft Adversarial Data`, `hopskipjump` →
  `AML.T0040 ML Model Inference API Access`, `noise_control` → none. S1's path
  `Finding.schema_blob.atlas_technique` resolves to
  `Finding.schema_blob.ml.atlas_technique` because all ML detail lives in the
  `ml` block. The mapping is declared on the attack adapter (the
  `AttackInfo.atlas_technique_id` / `atlas_technique_name` fields already
  frozen on #8) and a per-campaign coverage block (`RunRecord.atlas_coverage`)
  lists the techniques exercised. Coverage is a description of the declared
  attack set, never a score.
- **Platform pushes.** Palantir **Foundry** is primary (scorecard and dataset
  written as Foundry datasets, always with subscores, denominators, ε points,
  `settings_hash` and the grade sentence). Anduril **Lattice** is exploratory
  and **text-only**: it conflicts with the D3 bound "no mission-system
  connections" and cannot be enabled without an explicit product-owner
  decision and a constitution amendment proposal. Both are env-selected, off by
  default, hold no standing credential, and make no LLM call.

Consequences for this plan: `docs/plans/07-p6-interoperability.md` maps to spec
section 27 / milestone B2 (its v1 body is still superseded for paths and
mechanisms). Phase A work should not block on it, but WS2 keeps the ATLAS
fields on `AttackInfo` populated as adapters land (cheap, and it is the only B2
item with a Phase A seam), and WS3 leaves `schema_blob.ml.atlas_technique` as
`None` rather than guessing. Every B2 route returns `501 not_implemented` and
every B2 control renders disabled with its reason until B2 lands.

## 7. Integration waves and demo-critical order

Build order follows D8, not numeric milestone order (unchanged in v2.1):

```
Gate 0:  WS0 (M0 scaffold + migration)            ── blocks all
Slice 1: F001 auth · F002 catalog · F008 audit    ── foundation (WS1, WS7 auth)
Slice 2: F003 profile · F004 runs · F005 evidence ── the engine (WS2, WS3, WS4, WS5)
Slice 3: F006 findings · F007 reports/compare     ── the tools (WS3, WS6)
```

Demo-critical path (D8, spec 3.4): image path end to end → MRI scorecard →
verify-after-harden → tabular path → ONNX upload → Fargate deploy. **M5a (the
image UI slice) is the cut line for a demo.** Everything in Phase B waits behind
Fargate, and B2 waits behind B1+.

## 8. Definition of done (canonical section 26)

The demo runs live on ECS Fargate: a campaign started from `/models` against the
bundled vehicle-imagery CNN and the bundled URL maliciousness classifier (Kaggle
malicious-URLs dataset; UNSW-NB15 only if the fallback had to be used, and then
the campaign says so) runs FGSM and PGD with the noise control and ε sweep;
`/runs/[id]` shows the MRI scorecard with its subscores, per-family table, and
robustness curve; `/findings/[id]` shows the three panes and a measured ΔMRI
after Verify; every action is on the audit chain and `redsim audit verify`
passes; access is gated by Keycloak with RLS; `pytest` and `vitest` pass.

## 9. Status of the P0–P7 phase files

The eight phase files `01`–`08` in this directory were written for v1 against
the deleted standalone `redsim/` substrate and then rebased. Their state as of
v2.1:

- `01`–`06` and `08` carry v2 bodies rebased onto the platform, and commit
  `836b0e1` flipped every path and identifier in them to the `redsim` names
  (`redsim/ml/`, `redsim ml …`, `REDSIM_*`, `redsim-*`, `redsim.*` tasks,
  `@redsim/web`). Their bodies still predate the frozen names of section 5:
  they use the spec 5.3 names `CampaignConfig` and `MRIRecord` where PR #8
  froze the widened `RunConfig` and `Scoring`, and `01` still lists the schema
  widening as WS0 work that #8 has since landed. Where a body disagrees with
  this plan, the canonical spec or `specs/F00#`, those win.
- `07` keeps its v1 body under a reconciliation banner. It maps to spec
  section 27 / milestone B2 (section 6 above). Use it for the
  parallel-execution shape only, not for the literal paths, signatures or
  mechanisms.
- `EXECUTION-CONTEXT.md` is current as of `836b0e1` (redsim names, B2, the
  malicious-URLs dataset). Its Zscaler certificate path is one operator's
  machine-local path. The portable options are in section 5 (Pythia access).

Use the phase files for the parallel-execution shape, not for the literal
contracts. Ask if you want any one of them fully rewritten onto the frozen
section 5 contracts.
