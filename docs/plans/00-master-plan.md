# redsim/ml — Master Implementation Plan (reconciled)

Status: v2, 2026-09-08. Supersedes v1. This version is rebased on the full
**redsim platform** after the `main` restructure of 2026-09-08.

## 0. What changed since v1 (read this first)

Naming note: on 2026-09-08 the team renamed the whole platform from the `aegis`
namespace to `redsim`. So the platform, its Python package, its env vars
(`REDSIM_*`), and its compose services (`redsim-*`) are all `redsim` now. This
plan uses those names.

v1 of this plan was written against a **stripped-down standalone `redsim/`
package** with a filesystem store, a thread-pool, no auth, and no audit. That
stripped package was **deleted on `main`**. The repository now:

- keeps the ML vertical as **`redsim/ml/`** (contracts only today), a vertical
  inside the full restored platform (not a standalone package);
- is governed by a new canonical product spec,
  `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`, which
  supersedes both the hackathon spec and the redsim design spec;
- adds a **Spec Kit feature layer**, `specs/F001`–`F008`, as the feature-level
  source of truth beneath that product spec.

Every architectural assumption in v1 is overridden. The corrections are in
sections 2 and 5. Two things we had **missed** and now cover: authentication
(F001) and the audit chain (F008). Interoperability is **adopted as Phase B2**,
beyond the Phase A demo (see section 6).

## 1. Authoritative sources (in order)

1. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md` — the
   product spec. Decisions D1–D13 are final and override every source.
2. `specs/` — the Spec Kit feature layer (F001–F008), each with spec, plan, and
   tasks. Where a feature file conflicts with the product spec, the product spec
   wins.
3. `specs/_shared/{architecture,decisions,analysis}.md` — shared contracts and
   the D001–D007 clarification register (D006, D007 still open).

The repo `CLAUDE.md` is current after the team's standardization pass: it
describes the redsim platform, the `redsim/ml/` vertical, and the naming rules
(product name **redsim**; Python namespace `redsim`; web packages `@redsim/web`
and `@redsim/design-system`; env `NEXT_PUBLIC_REDSIM_API_URL`). Read it.

## 2. Substrate correction (v1 → v2)

| Concern | v1 assumption (wrong now) | v2 authoritative (redsim) |
|---|---|---|
| Package | standalone stripped `redsim/` package | `redsim/ml/` vertical inside the full platform (D7); the platform namespace is `redsim` after the 2026-09-08 rename |
| Persistence | filesystem `RunStore` on EFS | Postgres + RLS; run record as sha256 Artifact; `ml_campaigns` table; S3/MinIO for bytes (D1) |
| Run progress | `run.json` per stage | `Run.stage_table` JSON column + Redis run-event channel |
| Jobs | in-process thread pool `redsim/jobs.py` | Celery on Redis; admission→execution split; `redsim/workers/job_state.py` |
| Model loading | in worker process | sandboxed child subprocess `python -m redsim.ml.sandbox_worker` (D2) |
| API | new `redsim/api/app.py:create_app` | routers under `redsim/api/v1/` mounted on the existing `redsim/api/app.py` |
| Auth | none | Keycloak OIDC + NextAuth + session cookie; role ranks `scanner<remediator<approver<admin` (F001) |
| Audit | none | hash-chained append-only audit + WORM to S3 (F008) |
| Storage on AWS | EFS + RDS | RDS PostgreSQL 16 + ElastiCache Redis + **S3 (two buckets, one Object-Lock WORM); no EFS** |
| LLM env | `REDSIM_LLM_MODEL` | `REDSIM_ML_LLM_MODEL`, via Pythia only |
| Demo data | CIFAR-10 | `leibnitz-lab/military_vehicles` (image) + Kaggle `sid321axn/malicious-urls-dataset` (tabular); CIFAR-10 is a CI fixture only (D3) |

## 3. Scope (canonical Phase A)

Image and tabular classifiers, both live end to end. Bundled models plus
white-box upload (ONNX preferred; PyTorch `state_dict` with declared
architecture; full pickles refused; loaded only in the sandboxed worker).
Attacks FGSM and PGD for image, PGD-surrogate and HopSkipJump for tabular, each
paired with a benign noise control, swept over ε `{0.01, 0.03, 0.1}` with a
robustness curve. SHAP explanations, the five-subscore MRI, deterministic plus
Pythia-written recommendations, the verify-after-harden loop with measured
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
| **WS0 Scaffold** | Backend lead | M0 | cross-cutting | `redsim/ml/` package, migration `0010_ml_vertical` (`targets.detail` JSONB + `ml_campaigns` table), schema widening (`RunConfig` → attack set + ε grid + MRI weights), new `Action` members + `viewer` rank, `ml` dep group (+`onnx2torch`, `safetensors`), env rename, `/v1/scans` unmounted, `redsim ml build-assets` CLI skeleton. Blocks all. |
| **WS1 Catalog & ingest** | Dev A | M1, M4, M5b | F002 | `redsim/ml/targets/`, bundled-model seeding via `build-assets`, `POST /v1/models` upload, `model.validate` sandboxed task, `redsim/services/ml_models.py`, web `/models`. |
| **WS2 Attacks, engine & scoring** | Dev B | M1, M3, M4, M6 | F003, F004 | `redsim/ml/attacks/`, `campaign.py`, `eval.py`, `scoring.py`; the `attack.run` Celery chain (sample→clean_eval→control→attack); MRI + severity. |
| **WS3 Explain, recommend & findings** | Dev C | M2, M3, M6 | F005, F006 | `redsim/ml/explain/`, `recommend/{rules,narrative}.py`, `explain.run` / `harden.recommend` / `verify.replay` tasks, `Finding.schema_blob.ml` projection, dismissal + reviewer-notes routes. |
| **WS4 API & campaign service** | Backend lead | M1–M6 | F004 | routers `redsim/api/v1/{models,attacks,datasets,defenses,ml_capabilities,artifacts,compare,ml_findings}.py` mounted on `redsim/api/app.py`; `redsim/services/ml_campaigns.py`; WS events channel. |
| **WS5 Web UI** | Dev D | M5a, M5b | F005, F006, F007 UI | `@redsim/web` pages `/models`, `/models/[id]` launcher, 13-panel `/runs/[id]`, three-pane `/findings/[id]`; design-system `MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`, `ObservationCard`. |
| **WS6 Reports & comparison** | rotates | M3, M6 | F007 | extend `redsim/report.py` to render the ML run record + scorecard; `GET /v1/runs/{id}/compare`; report Artifact rows. |
| **WS7 Infra, auth & deploy** | Dev D / lead | M7 | F001, F008 | ECS Fargate services (api, worker, beat, web, log-ingest) + ALB; RDS PostgreSQL 16; ElastiCache Redis; two S3 buckets (one Object-Lock); Secrets Manager; Keycloak on Fargate; activate the existing deploy pipeline. Reuse the audit chain (F008) already in redsim. |

F001 (auth) and F008 (audit) are largely **reused redsim foundation**, not new
builds; the new work is emitting ML audit events on the existing chain and
wiring Keycloak on Fargate. These are the two features v1 missed entirely.

## 5. Corrected shared contracts

- **Schema** (`redsim/ml/schema.py`): the `RunRecord`/`Measurement`/`Observation`/
  `Interpretation`/`CandidateRecommendation` evidence model stays. It is written
  as a sha256-addressed Artifact (`ml.run_record`) and **projected** onto
  `ml_campaigns.score` and `findings.schema_blob.ml`; a projection that
  disagrees with the record is a bug. Widen `RunConfig` to an attack set, ε
  grid, and MRI weight vector.
- **Migration**: exactly one — `0010_ml_vertical` — adding `targets.detail`
  (JSONB) and `ml_campaigns` (1:1 with `runs`, full RLS parity). Additive and
  reversible.
- **API** (all under `/v1`, on the redsim app, auth + RLS enforced): a campaign
  starts with `POST /v1/models/{id}/attacks`, **not** a generic `POST /v1/runs`.
  Read the campaign at `GET /v1/runs/{id}/campaign`; stream a blob at
  `GET /v1/artifacts/{id}`; act on findings via `POST /v1/findings/{id}/{explain,harden,verify}`;
  compare with `GET /v1/runs/{id}/compare?with=`. `POST /v1/scans` is unmounted
  at M0.
- **Jobs**: Celery tasks `redsim.model_validate`, `redsim.attack_run`,
  `redsim.explain_run`, `redsim.harden_recommend`, `redsim.verify_replay`,
  `redsim.report_render`. Attacks run as a chain, one Job per attack. Admission
  is audit-first: the audit event is appended before any Run/Job row.
- **MRI** (unchanged formula): `round(0.35·S_acc + 0.25·S_asr + 0.20·S_eps +
  0.10·S_conf + 0.10·S_expl)`, computed only when all five subscores exist,
  weights never renormalized, per campaign only, never shown without its
  subscores, per-family table, and ε curve. Grade text is attack-scoped; the
  words "hardened", "deployment-ready", "certified", "safe" are banned.
- **Env**: `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`,
  `REDSIM_ML_LLM_MODEL`, `REDSIM_ML_WORK_DIR`. LLM calls go through
  `redsim/llm/pythia.py` under the redsim router and budget.

## 6. Interoperability — adopted as Phase B2

The interop work is back in the canonical spec as **section 27,
"Interoperability (Phase B2)"**, and milestone **B2** in section 23. It is
adopted but sits **beyond Phase A**: specified, off by default, and not built.
It covers Croissant/Parquet adversarial-dataset export and its consume side
(ONNX models and evaluation slices from other teams), MITRE ATLAS technique
tags on findings with a per-campaign coverage view, and env-selected platform
pushes (Palantir Foundry primary; Anduril Lattice exploratory, blocked by the
D3 "no mission-system connections" bound until an explicit decision resolves it).

Concrete anchors for when B2 lands:

- **Routes** (section 17.4, each returns `501` with `phase: "B"` until B2):
  `POST /v1/runs/{id}/dataset`, `GET /v1/datasets/{id}`, and the consume-side
  `POST /v1/datasets` (multipart).
- **ATLAS tag** lives at `Finding.schema_blob.ml.atlas_technique` (section 5.7),
  stamped from the attack registry: `AML.T0043 Craft Adversarial Data` for
  `fgsm`/`pgd`, `AML.T0040 ML Model Inference API Access` for `hopskipjump`.
- **Features**: the export is F007's B2 addition; the consume side is F002's.

So this is **not planned for the Phase A demo**, but it is no longer dropped.
`docs/plans/07-p6-interoperability.md` maps to Phase B2, not to nothing.

## 7. Integration waves and demo-critical order

Build order follows D8, not numeric milestone order:

```
Gate 0:  WS0 (M0 scaffold + migration)            ── blocks all
Slice 1: F001 auth · F002 catalog · F008 audit    ── foundation (WS1, WS7 auth)
Slice 2: F003 profile · F004 runs · F005 evidence ── the engine (WS2, WS3, WS4, WS5)
Slice 3: F006 findings · F007 reports/compare     ── the tools (WS3, WS6)
```

Demo-critical path (D8): image path end to end → MRI scorecard → verify-after-
harden → tabular path → ONNX upload → Fargate deploy. **M5a (the image UI
slice) is the cut line for a demo.** Everything in Phase B waits behind Fargate.

## 8. Definition of done (canonical section 26)

The demo runs live on ECS Fargate: a campaign started from `/models` against the
bundled vehicle-imagery CNN and the malicious-URLs tabular model runs FGSM and PGD
with the noise control and ε sweep; `/runs/[id]` shows the MRI scorecard with
its subscores, per-family table, and robustness curve; `/findings/[id]` shows
the three panes and a measured ΔMRI after Verify; every action is on the audit
chain and `redsim audit verify` passes; access is gated by Keycloak with RLS;
`pytest` and `vitest` pass.

## 9. Status of the P0–P7 phase files

The eight phase files `01`–`08` in this directory were written for v1 against
the deleted `redsim/` substrate. Each now carries a reconciliation banner
mapping it to the redsim milestone(s) and feature(s) and listing its substrate
corrections. Their detailed bodies (paths, signatures, mechanisms) are
**superseded** by this master plan, the canonical spec, and `specs/F00#`. Use
them only for the parallel-execution shape, not for the literal contracts. Ask
if you want any one of them fully rewritten onto the redsim substrate.
