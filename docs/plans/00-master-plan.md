# redsim/ml — Master Implementation Plan (reconciled)

Status: v2.2, 2026-09-08 (evening). Supersedes v1, amends v2 and v2.1. This version is
rebased on the **redsim platform** (the aegis platform kept whole under D1 and
renamed to the `redsim` namespace in commit `b39d933`) after the `main`
restructure of 2026-09-08.

## 0. What changed since v1 (read this first)

### v2.2 (2026-09-08, evening): change note

P0 / M0 merged. PR #18 (branch `P0`, John Sasser) landed on `main` as
`4350d38` (868 passed and 30 skipped offline per the PR body), and PR #11
(Pythia access) followed as `5fa2d79`. P0 froze `redsim/ml/schema.py` under the spec 5.3 names, so the
"frozen on PR #8" contracts that v2.1 section 5 listed (`Scoring`,
`RunRecord.scoring`, `RunRecord.atlas_coverage`, the `AttackInfo` ATLAS
fields, `Measurement.severity`, the widened `RunConfig`) are superseded.
Section 5 now lists the P0 shapes, section 4.1 records #18 and #11 as merged
and #8 and #9 as rebased on P0 with adaptation in progress, and the WS0 / WS2
naming coordination item is closed. The eight points where P0 resolved spec
text in favour of the tree are recorded in spec section 4.5. Nothing in D1 to
D13 changes.

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
| LLM env | `REDSIM_LLM_MODEL` | `REDSIM_ML_LLM_MODEL`, via Pythia only. The M0 rename landed with P0 (`4350d38`): `redsim/llm/pythia.py`, `tests/test_llm_pythia.py` and `.env.example` use the new name, and PR #11 (`5fa2d79`) keeps the old one only as a deprecated alias |
| Services and images | two compose services | `redsim-api`, `redsim-worker` (`-Q scans`), `redsim-worker-default` (`-Q default`), `redsim-beat`, `redsim-web`, `redsim-log-ingest`; Helm chart `deploy/helm/redsim`; CI `.github/workflows/redsim-ci.yml` |
| Web | none | `@redsim/web` (Next.js 14, `web/`), `@redsim/design-system` (`packages/design-system/`), `NEXT_PUBLIC_REDSIM_API_URL`, cookies `redsim_api_session` / `redsim_csrf` |
| Demo data | CIFAR-10 | `leibnitz-lab/military_vehicles` (image, spec 11.3.1; `Illia56/Military-Aircraft-Detection` fallback) + Kaggle `sid321axn/malicious-urls-dataset` (tabular, CC0, spec 11.3.3); `lacg030175/UNSW-NB15` is the tabular fallback (11.3.4) and `mstz/spambase` the second fallback and CI tabular fixture (11.3.6); CIFAR-10 is the image CI fixture only (D3, D4(d)). Phase B, LLM track: the `idllresearch/malicious-gpt` jailbreak corpus (spec 11.6) as garak probe material, licence unresolved (D008) |

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

Phase B, LLM track, outside the scope above. The B1 milestone's garak-style
probes through Pythia (D6) have their probe material: the jailbreak prompts
of `idllresearch/malicious-gpt` (USENIX Security '24, commit `25be7cc`),
200 records combined into one JSON Lines file with provenance fields, recorded
in spec section 11.6. It is probe material only, never a classifier dataset
and never an MRI input (D9). The upstream repository declares no licence, so
the corpus is internal research material until the authors clarify (decision
register D008, open). No workstream reads it in Phase A.

## 4. Workstreams for 3–4 developers

The canonical spec owns the decomposition twice over: milestones **M0–M7**
(build order) and features **F001–F008** (outcome verticals). This plan does not
invent a third. It assigns those to parallel workstreams and gives the
integration waves. Each workstream cites the milestone(s) and feature(s) it
delivers.

| WS | Owner | Milestones | Features | Deliverable |
|---|---|---|---|---|
| **WS0 Scaffold** | Backend lead | M0 | cross-cutting | `redsim/ml/` package, migration `0010_ml_vertical` (`targets.detail` JSONB + `ml_campaigns` table), schema freeze (`CampaignConfig`, `ScoringConfig`, `MRIRecord`, `MLFindingDetail`, `MLModelManifest`, `CampaignRecord`, landed on #18), new `Action` members + `viewer` rank, `ml` dep group (+`onnx2torch`, `safetensors`), env rename `REDSIM_LLM_MODEL` → `REDSIM_ML_LLM_MODEL`, `/v1/scans` unmounted, `redsim ml build-assets` CLI skeleton. Blocks all. **Merged** as `4350d38`. |
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

### 4.1 Workstream status (2026-09-08, late evening)

Pull requests on `IntelliBridge/ndia-red-team-simulator` as of this revision.
No names are invented for unassigned work (D007 stays open).

| WS | Branch / PR | State | Notes |
|---|---|---|---|
| WS0 Scaffold (M0, P0) | #18 `P0` (John Sasser) | **merged** into `main` as `4350d38` (2026-09-08, 868 passed and 30 skipped offline per the PR body) | Not ours. Freezes `redsim/ml/schema.py` under the spec 5.3 names (section 5), migration `0010_ml_vertical`, the seven ML `Action` members and the `viewer` rank, the `REDSIM_ML_LLM_MODEL` rename, `/v1/scans` unmounted, the `redsim ml build-assets` skeleton (`BUILD_ASSETS_STATUS = "not_implemented"`) and the lint baseline. PR #10 `feat/ml-db-migration` was **closed** earlier so that WS0 / P0 had one owner. A change to the frozen contract follows `01-p0-contracts-api-skeleton.md` section 8. Spec section 4.5 records the eight points P0 resolved in favour of the tree. |
| WS1 targets (pure part), WS2 attacks / engine / scoring, WS3 explain / recommend | #8 `feat/ml-core` | **merged** into `main` as `ce33d21` (2026-09-08) | Adapted to the frozen P0 schema before merge (`CampaignConfig`, `MRIRecord`, the enriched `Measurement` / `Observation` / `Provenance`), no P0-owned file changed. On `main` now: `redsim/ml/{registry,artifacts,errors,defenses,eval,scoring,campaign}.py`, `targets/` (`registry`, `bundled`, `tabular`, `artifact`, `unavailable`), `attacks/` (`registry`, `fgsm`, `pgd`, `hopskipjump`, `noise_control`), `datasets/` (`cifar10`, `image_hub`, `sampling`), `explain/` (SHAP image and tabular, `stability`, `summary`), `recommend/{rules,narrative}.py` and `docs/workstreams/ml-core.md`, with no platform imports. `import redsim.ml.targets, redsim.ml.attacks` registers the targets `cifar10_smallcnn`, `endpoint_stub`, `url_trees`, `vehicles_cnn` and the attacks `fgsm`, `hopskipjump`, `noise_control`, `pgd`. The follow-up `5bb382f` adds an autouse fixture in `tests/ml/conftest.py` that isolates every ML test from a developer's `.env`. The sandbox child, the Celery tasks and the routes stay with WS4. |
| WS1 assets (bundled-model seeding) | #9 `feat/ml-assets` | **merged** into `main` as `1725728` (2026-09-08) | Workstream `docs/workstreams/ml-assets.md`. `redsim ml build-assets` is real on top of P0's `redsim/cli/ml.py`: `--dataset {image,tabular,cifar10,all}`, `--only`, `--epochs`, `--out`, `--cache-dir`, `--seed`. `redsim/ml/assets/` fetches by pinned revision (HuggingFace hub, Kaggle with `KAGGLE_API_TOKEN` as a bearer token or the older `KAGGLE_USERNAME` / `KAGGLE_KEY` pair, else the committed CI sample), trains `SmallCNN` (`targets/architectures.py`) and the URL tree ensemble (`datasets/url_features.py`) on CPU with a fixed seed, and writes `assets/MANIFEST.json` on `MLModelManifest`. The `tests/ml/test_cli_ml.py` open point was reconciled in the PR. The assets were built locally on 2026-09-08 with `--dataset all`, are gitignored, and carry their clean accuracy in the manifest. |
| Cross-cutting: Pythia transport | #11 `feat/pythia-access` | **merged** into `main` as `5fa2d79` (2026-09-08) | Gateway URL, key provisioning, trust-store TLS, `.env` loading, `python -m redsim.llm.pythia_check`, `docs/ops/pythia.md` and `docs/workstreams/pythia-access.md`. Reads `REDSIM_ML_LLM_MODEL` as frozen by P0. Two follow-up commits (`6f4d06d`, `6a0b8b9`) isolate the `.env` discovery tests. See the Pythia note in section 5. |
| F008 audit foundation contract | #12 `feat/audit-log-foundation` (William) | **merged** | Contract doc for the audit chain the ML events append to. |
| Earlier contributions | #2 (schema and registry contract tests), #4 (CIFAR-10 target and asset pipeline), both by Metz | closed by their author | Superseded by the platform substrate. CIFAR-10 stays a CI fixture. |
| WS5 Web UI | #16 `feat/replit-redsim-migration` (Metz) | **merged** into `main` as `1a9204e` (2026-09-08) | Reworked by its author into a P5-only change that keeps the platform auth and adds `/models`, `/models/[id]`, the MRI panels on `/runs/[id]` and the three-pane `/findings/[id]` with the design-system evidence components (`MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`, `ObservationCard`, `LabelBadge`, `PanelSection`, `CompatibilityList`). The earlier Replit-port shape that D1 rejected is gone. codex-pr-review verdict blocking with 10 confirmed findings, one fix commit per finding landed before the squash merge, and `7240220` (product owner) tightened the `not_implemented` wording on the model pages afterwards. The WS4 routes the pages call are not mounted, so they render `not_implemented` on 404 or 501. The web CI lanes have not run on `main` since `ea39f97` (see the CI row). |
| WS7 Fargate foundation | #19 `feat/p7-fargate-foundation` (William) | **merged** into `main` as `b40f7e1` (2026-09-08) | 26 new files under `deploy/terraform/`: existing-VPC selection with checks, private endpoints, an ALB with target groups but no listeners, RDS PostgreSQL 16, Redis, two S3 buckets (the audit bucket Object-Lock capable with no default retention), per-service IAM roles, mocked-plan tests behind `validate.sh`. No task definitions, no services, nothing applied. codex-pr-review verdict needs-changes with 2 confirmed findings (RDS storage autoscaling headroom validation, empty `plugin_args` expansion under Bash 3.2), both fixed on the branch before merge. |
| Docs | #20 `docs/refresh` | **merged** into `main` as `72eecc2` (2026-09-08) | README, CLAUDE.md, architecture and plan pages refreshed to the redsim / P0 truth, plus the Archify architecture diagrams under `docs/architecture/diagrams/`. |
| Web toolchain, CI, `viewer` role | #21 `ci/web-fixes` | **merged** into `main` as `ea39f97` (2026-09-08) | Reverts the #15 web bump (Next 14, React 18 and TypeScript 5 stay) and restores `pnpm-lock.yaml` to match, installs pnpm with `npm install -g pnpm@10.33.2` on `node:26` in `deploy/Dockerfile.web`, adds the `viewer` role to the Keycloak realm export and to the design-system `ROLES` with 0-based ranks matching `redsim/api/policy.py`. Redsim CI was fully green at this commit. |
| Dependabot | #13 (docker), #14 (actions), #15 (npm, `web/`) | **merged** (`ff24944`, `eb99386`, `4c928c5`) | Routine, with two regressions: #13 moved the web image to `node:26`, where corepack is gone, and #15 bumped `web/package.json` past the root lockfile. Both fixed by #21. |
| Cross-cutting: CI on `main` | Redsim CI | red on every run from `1725728` through `7240220` | Both unit lanes fail at the mypy step with `no-any-return` in `redsim/ml/datasets/image_hub.py:55` (`truststore` is in no pyproject extra, so CI types it as `Any`) and, on 3.13 only, `redsim/ml/assets/train_cnn.py:172` (no `ml` extra, so `torch` is `Any`). Local mypy is clean because the venv has both. `API integration`, `Next.js build` and `Build images` are skipped downstream, so nothing after `ea39f97` (#16's pages included) has been built by CI on `main`. One typed return per function, or `truststore` in the extras, fixes it. Not on any branch yet. |
| WS4, WS6 | none yet | not started | Start behind Gate 0 per section 7. WS5's pages (#16) and WS7's Terraform foundation (#19) are on `main`, the WS4 routes the pages need and the Fargate services are not. |

## 5. Corrected shared contracts

- **Schema** (`redsim/ml/schema.py`): the `RunRecord`/`Measurement`/`Observation`/
  `Interpretation`/`CandidateRecommendation` evidence model stays. It is written
  as a sha256-addressed Artifact (`ml.run_record`) and **projected** onto
  `ml_campaigns.score` and `findings.schema_blob.ml`; a projection that
  disagrees with the record is a bug. Frozen on `main` by P0 (PR #18,
  `4350d38`) under the spec 5.3 names. Read the module in full before
  building against it. The shapes, in brief:
  - `CampaignConfig` replaces `RunConfig`: `target_id`, `modality`,
    `attack_ids`, `attack_params`, `norm`, `eps_grid` (strictly ascending,
    each in (0, 1]), `reference_eps` (a member of the grid),
    `finding_asr_threshold`, `n_samples`, `seed`, `include_control`,
    `explain_k`, `dataset_id`, `dataset_revision`, `dataset_split`,
    `scoring: ScoringConfig`, `defense: DefenseConfig | None`,
    `llm_narrative`, `auto_recommend`, `target_snapshot`, `attacks`.
  - `ScoringConfig`: `version`, `weights: MRIWeights` (0.35 / 0.25 / 0.20 /
    0.10 / 0.10, validated to sum to 1), `severity`, `confidence` and
    `interpretation` thresholds. `finding_asr_threshold` is not inside it.
  - `MRIRecord` (`RunRecord.score`) replaces `Scoring` and
    `RunRecord.scoring`: `scoring_version`, `weights`, `eps_grid`,
    `reference_eps`, `norm`, `attack_ids`, `finding_asr_threshold`,
    `settings_hash`, `inputs: list[MRIInputRow]`, `per_attack: dict[str,
    PerAttackSubscores]`, `subscores: Subscores` (`S_acc`, `S_asr`, `S_eps`,
    `S_conf`, `S_expl`), `mri`, `grade`, `completeness`, `missing`,
    `reading`, `delta: MRIDelta | None`, `computed_at`. It refuses an `mri`
    without all five subscores, a `grade` that does not match the band
    (`schema.grade_for_mri`) and a `reading` with a banned readiness word.
    Weights are never renormalised.
  - `Measurement` has **no `severity` field**. Severity is finding-level
    (`MLFindingDetail`, `SeverityThresholds`, spec 15.5). It gains the scoring
    inputs (`n_clean_correct`, `attack_success_rate`, `pert_first_success_*`,
    `conf_gap_*`, `expl_shift_mean`, `expl_shift_n`, `expl_shift_n_excluded`,
    `expl_shift_noise_floor`, `expl_shift_noise_floor_n`, `queries_mean`), and
    `params` values may be `str`.
  - `AttackInfo` gains `phase`, `access`, `requires_gradients`, `status` and
    `reason` with defaults. It has **no ATLAS fields**, and there is no
    `RunRecord.atlas_coverage`: ATLAS is Phase B2 through
    `MLFindingDetail.atlas_technique: AtlasTechnique(id, name,
    atlas_version)`, "never back-filled by guesswork". Keep the
    attack-to-technique mapping as a module-level constant for B2 and stamp
    nothing on records in Phase A.
  - `Provenance` gains `baseline_run_id`, `dataset_revision`, `defense`,
    `llm`, `onnxruntime`, `parent_run_id`, `sample_indices_sha256`,
    `settings_hash`, `sklearn`, `thread_env` and `xgboost`.
  - `CandidateRecommendation.validation` is `Literal["not evaluated",
    "measured"]`, paired with `measured: MeasuredDelta | None`. A candidate
    carries no numeric gain until a verify run measures a delta.
  - `RunRecord` rejects dangling citations (`Interpretation.basis` and
    `CandidateRecommendation.triggered_by` must name existing measurement or
    observation ids) and carries `score: MRIRecord | None`. `RunStatus`
    includes `cancelled`. `CampaignRecord` extends it with `kind`,
    `completed_at`, `settings_hash`, `baseline_run_id`, `parent_run_id`,
    `curve: list[RobustnessCurve]`, `completeness`, `missing` and
    `score_status`. `RunSummary.attack_ids` replaces `attack_id`.
  - `standing_limitations(dataset_name, eps_grid)` builds the per-campaign
    limitations list. `STANDING_LIMITATIONS` no longer carries the CIFAR-10
    sentence.
  - `Provenance.redsim_version` (was `aegis_version` in the spec text).
  The WS0 / WS2 naming question of v2.1 is closed: P0 merged with the spec
  names, so the `RunConfig` and `Scoring` shapes on PR #8 are superseded and
  #8 is being adapted to P0's names and semantics (section 4.1). A change to
  the frozen contract follows `01-p0-contracts-api-skeleton.md` section 8:
  announce it first and prefer additive optional fields.
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
  compare with `GET /v1/runs/{id}/compare?with=`. `POST /v1/scans` was unmounted
  by P0 (`4350d38`). Phase B2 routes (`POST /v1/runs/{id}/dataset`, `GET /v1/datasets/{id}`,
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
  `MRIRecord.weights` records the vector used. A non-default vector puts a badge
  on the scorecard and makes the campaign incomparable with any other. Grade
  text is attack-scoped; the words "hardened", "deployment-ready", "certified",
  "safe" are banned. ΔMRI is the only sanctioned form of "gain" and appears only
  on a verify run whose `settings_hash` matches its baseline.
- **Env**: `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`,
  `PYTHIA_TIMEOUT_S`, `REDSIM_ML_LLM_MODEL`, `REDSIM_ML_WORK_DIR` (and the other
  `REDSIM_ML_*` knobs of spec 20.3). LLM calls go through
  `redsim/llm/pythia.py` under the platform router and budget. The M0 rename
  landed with P0 (`4350d38`): `PythiaSettings.from_env` reads
  `REDSIM_ML_LLM_MODEL`, `.env.example` and `tests/test_llm_pythia.py` use
  that name, and PR #11 (`5fa2d79`) keeps `REDSIM_LLM_MODEL` only as a
  deprecated alias.
- **Pythia access** (cross-cutting, PR #11, merged as `5fa2d79`, facts as
  reported by that workstream on 2026-09-08 and kept in `docs/ops/pythia.md`): the gateway is
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
  `ml` block. The mapping is declared beside the attack registry as a
  module-level constant (P0 froze `AttackInfo` without ATLAS fields and
  `RunRecord` without `atlas_coverage`), recorded with the ATLAS version it
  was checked against (spec 27.4), and B2 adds the per-campaign coverage view
  of spec 27.2 that lists the techniques exercised. Coverage is a description
  of the declared attack set, never a score.
- **Platform pushes.** Palantir **Foundry** is primary (scorecard and dataset
  written as Foundry datasets, always with subscores, denominators, ε points,
  `settings_hash` and the grade sentence). Anduril **Lattice** is exploratory
  and **text-only**: it conflicts with the D3 bound "no mission-system
  connections" and cannot be enabled without an explicit product-owner
  decision and a constitution amendment proposal. Both are env-selected, off by
  default, hold no standing credential, and make no LLM call.

Consequences for this plan: `docs/plans/07-p6-interoperability.md` maps to spec
section 27 / milestone B2 (its v1 body is still superseded for paths and
mechanisms). Phase A work should not block on it, but WS2 keeps the
attack-to-technique mapping as a module-level constant as adapters land (cheap,
and it is the only B2 item with a Phase A seam), stamps nothing on records in
Phase A, and WS3 leaves `schema_blob.ml.atlas_technique` as `None` rather than
guessing. Every B2 route returns `501 not_implemented` and
every B2 control renders disabled with its reason until B2 lands.

## 7. Integration waves and demo-critical order

Build order follows D8, not numeric milestone order (unchanged in v2.1):

```
Gate 0:  WS0 (M0 scaffold + migration)            ── blocks all
Slice 1: F001 auth · F002 catalog · F008 audit    ── foundation (WS1, WS7 auth)
Slice 2: F003 profile · F004 runs · F005 evidence ── the engine (WS2, WS3, WS4, WS5)
Slice 3: F006 findings · F007 reports/compare     ── the tools (WS3, WS6)
```

Gate 0 cleared on 2026-09-08 with PR #18 (`4350d38`), so Slices 1 to 3 build
against the frozen section 5 contracts.

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
  `@redsim/web`). Their bodies use the spec 5.3 names `CampaignConfig` and
  `MRIRecord`, which P0 (PR #18, `4350d38`) froze on `main`, so those names
  are current again. `01` closes with a dated Landed note (PR #18,
  `4350d38`) and its body still reads as the pre-merge plan. Where a body disagrees with this plan, the canonical spec or
  `specs/F00#`, those win.
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
