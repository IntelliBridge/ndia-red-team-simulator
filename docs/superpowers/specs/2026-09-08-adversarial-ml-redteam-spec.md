# Adversarial ML Red-Team Simulator (redsim) — Product Spec

| | |
|---|---|
| **Date** | 2026-09-08 |
| **Status** | Approved design; supersedes `docs/adversarial-ml-redteam-spec.md` and `docs/superpowers/specs/2026-09-08-redsim-design.md`; feature-level detail lives in `specs/` |
| **Authors** | Hackathon team: product owner; John Sasser (platform + scoring); William Yiu (Spec Kit feature tree); this merge |
| **Governance** | `docs/project-brief.md` (reporting principles are design constraints); `.specify/memory/constitution.md` (principles binding; amendment proposals of 2026-09-08 pending named approval) |
| **Repository** | `IntelliBridge/ndia-red-team-simulator` (fork of `IntelliBridge/aegis`), branch `redsim-implementation` |

This document consolidates three spec sources — John Sasser's product spec (S1), the lean brief-grounded design and its code contracts (S2), and William Yiu's Spec Kit feature tree (S3) — under the product owner's decisions of 2026-09-08 (D1–D13, indexed in section 4.1). Where a decision overrides a source, the override is stated where it binds and recorded in the reconciliation table (section 4). Nothing in this document claims that the ML vertical is implemented: as of this date `aegis/ml/` contains contracts only (section 2.2).

## Table of contents

1. [Purpose and goal](#1-purpose-and-goal)
2. [Why reuse aegis](#2-why-reuse-aegis)
3. [Scope and phasing](#3-scope-and-phasing)
4. [Reconciliation table](#4-reconciliation-table)
5. [Domain model mapping onto aegis tables](#5-domain-model-mapping-onto-aegis-tables)
6. [State contracts](#6-state-contracts)
7. [Roles and access](#7-roles-and-access)
8. [Architecture](#8-architecture)
9. [Model loading and isolation](#9-model-loading-and-isolation)
10. [Job and worker flow](#10-job-and-worker-flow)
11. [Datasets and data handling](#11-datasets-and-data-handling)
12. [Attack catalog](#12-attack-catalog)
13. [Explainability](#13-explainability)
14. [Evidence model and reporting principles](#14-evidence-model-and-reporting-principles)
15. [Scoring — Model Robustness Index](#15-scoring--model-robustness-index)
16. [Hardening recommendations](#16-hardening-recommendations)
17. [API surface](#17-api-surface)
18. [Web UI](#18-web-ui)
19. [Spec Kit feature mapping](#19-spec-kit-feature-mapping)
20. [Deployment](#20-deployment)
21. [Security and trust](#21-security-and-trust)
22. [Testing plan](#22-testing-plan)
23. [Milestones](#23-milestones)
24. [Demo script](#24-demo-script)
25. [Open risks](#25-open-risks)
26. [Completion criteria](#26-completion-criteria)
27. [Interoperability (Phase B2)](#27-interoperability-phase-b2)

## 1. Purpose and goal

The Adversarial ML Red-Team Simulator is a web tool that stress-tests a machine-learning classifier under adversarial evasion attacks before anyone relies on it. A user selects a model (bundled or uploaded), launches an attack campaign, and views the SHAP explanation and the hardening recommendations side by side, with the whole trail recorded on a hash-chained audit log. It is built as one new vertical (`aegis/ml/`) inside IntelliBridge's aegis security platform (this fork: `IntelliBridge/ndia-red-team-simulator`), reusing aegis's API, workers, storage, auth, RBAC, tenancy, audit chain and LLM policy layer (section 2).

The tool answers three questions for each model. The wording of the third question is constrained by the project brief and differs from the original product spec (S1 §1); see row 12 of the reconciliation table in section 4.

| # | Question | What the tool does | Where specified |
|---|---|---|---|
| 1 | **Can it be fooled?** | Generates adversarial examples with ART (FGSM, PGD, HopSkipJump) across an ε sweep, alongside a benign random-noise control at the same ε, and reports per-family accuracy with denominators. | sections 12, 14 |
| 2 | **Why did it fail?** | Uses SHAP to show which pixels or features drove the wrong output, clean vs adversarial, and measures how much the attribution moved (explanation stability). SHAP is presented as supporting evidence, not causal proof. | section 13 |
| 3 | **What might fix it, and does it?** | Emits natural-language hardening recommendations as **candidates** (rule layer, then an LLM writer reached only through Pythia), then runs the verify-after-harden loop: applies an ART preprocessing defense to an evaluation copy of the model, re-attacks, and reports the **measured** ΔMRI. A recommendation carries no numeric expected gain until that loop has measured it. | sections 15, 16 |

Every campaign is summarised by a Model Robustness Index (MRI, 0–100) computed for that one model, one modality, one declared attack set, one ε grid and one reference budget. The MRI is never shown without its five dimension subscores, the per-family accuracy table with denominators, and the robustness curve, and it is never aggregated across modalities or compared across campaigns with different settings (section 15).

### 1.1 Framing from the brief

The project brief (`docs/project-brief.md`) is the governance document for this work and its reporting principles are design constraints throughout this spec. In the brief's terms this is a **non-operational proof of concept on open, unclassified, public data** that demonstrates one documented, benign, reproducible evaluation workflow with human review. Concretely:

- Measurements (what was counted), observations (per-sample evidence), interpretation (inferred statements) and candidate recommendations are separate fields in the evidence model and separate panels in the UI (section 14, section 18). The labels `candidate`, `not evaluated`, `inferred` and `heuristic` are enforced by `Literal` types in `aegis/ml/schema.py`.
- Results are presented per test family (clean / evasion / control) with clear denominators and coverage; the benign noise control runs at the same ε as the attack.
- Every run records model and dataset versions, attack and explainer configuration, library versions and the known sources of nondeterminism, so it can be rerun and compared (section 14).
- Limitations are always present on the run page and in every report. Passing does not establish safety, robustness in general, or deployment readiness; no grade band is a readiness or certification statement.
- Illustrative numbers (including every number in the demo script, section 24) are labelled illustrative. No completed run, measured improvement or validated fix is ever invented; unimplemented paths are shown as unavailable with a reason, never faked.

Where the product owner's decisions of 2026-09-08 knowingly diverge from the brief or from the Spec Kit constitution, section 4 records the divergence, the decision that caused it, and the bounds placed on it. The two material divergences are the choice of aerial / military-vehicle demo imagery (D3) and the adoption of a single per-campaign summary score (D9).

### 1.2 What the tool is not

- It evaluates and hardens the robustness of a classifier. It never trains, optimises, or deploys targeting or weapons models, and it connects to no mission system (D3 bounds; section 21).
- It applies defenses only to an evaluation copy inside a campaign, to measure their effect. It never autonomously modifies a deployed model.
- It is not a certification tool. An MRI grade describes robustness under the in-scope attacks at the declared settings and nothing more.
- It is not a data-poisoning pipeline, a training platform or a model registry beyond upload.

### 1.3 Users and the shape of a session

The roles are analysts who register models and run campaigns, reviewers who confirm findings and approve configurations independently of their authors, owners/admins who manage projects, members and policy, and viewers who read evidence (section 7). A session follows the aegis lifecycle: register or pick a model → configure and launch a campaign → watch jobs complete → inspect the MRI scorecard, robustness curve and findings → open a finding's three-pane screen (input pair, SHAP, candidate recommendations) → run the verify loop → read the measured delta → export the report → inspect the audit trail (sections 10, 18, 24).

### 1.4 Vocabulary

| Term | Meaning in this spec |
|---|---|
| **Model target** | An aegis `Target` row with `kind` `ml_model_artifact` (Phase A) or `ml_model_endpoint` (Phase B); `value` is the blob location or the inference URL (section 5). |
| **ML target (protocol)** | The loaded model plus its evaluation dataset slice, as `aegis/ml/targets/base.py:Target` (`sample`, `predict_proba`, `art_classifier`, `torch_model`, `manifest`). Distinct from the ORM row above. |
| **Campaign** | One aegis `Run`: one model × one modality × a declared attack set × a declared ε grid × a reference budget × a sample dataset (with revision) × scoring weights. This is also the unit for which an MRI exists. |
| **Campaign configuration** | The approved evaluation profile (F003) stored immutably with the `Run` as `CampaignConfig` (section 5). |
| **Job** | One aegis `Job` of type `model.validate`, `attack.run`, `explain.run`, `harden.recommend` or `verify.replay` (section 10). |
| **Finding** | One aegis `Finding`: an attack family whose success rate crossed the configured threshold at some ε; severity derived per section 15. |
| **Measurement / Observation / Interpretation / Candidate recommendation** | The four separate evidence fields of `aegis/ml/schema.py` (section 14). |
| **MRI, ΔMRI** | The per-campaign Model Robustness Index and its measured change after the verify loop (section 15). |
| **Reference budget** | `reference_eps`: the ε at which `S_asr`, `S_conf`, `S_expl` and the explained sample set are read (written ε_ref in formulas); part of the campaign configuration. |
| **Eps grid** | `eps_grid`: the sorted ascending list of perturbation budgets the campaign sweeps (default `{0.01, 0.03, 0.1}`, L∞). |
| **Phase A / Phase B** | Phase A is what must land for the demo (section 3.1); Phase B is stretch work that waits behind every Phase A item (section 3.2). |
| **F001–F008** | The Spec Kit features of `specs/`, mapped onto aegis components in section 19. |

## 2. Why reuse aegis

Aegis already ships the platform the loop needs. Rather than strip it down (the lean "redsim" design, S2) or build on a different monorepo (the Spec Kit proposal, S3), the product owner decided (D1) to keep the full platform and add one vertical. The core insight from S1 stands: aegis red-teams **code and services**; this vertical red-teams **models**. The lifecycle (discover, exploit, explain, remediate, verify, audit) is identical, and most of the brief's governance requirements (managed authentication, server-side authorization on every object, append-only accountable history, provenance) are already implemented rather than promised.

### 2.1 Reuse table, updated for what is actually restored

The platform was restored from the aegis head (`5eb24ca`) and then pruned. The table lists what is present in this fork today and what each part does for the ML vertical.

| Aegis capability | Where it lives in this fork | Reuse for the ML red-team |
|---|---|---|
| FastAPI `/v1` API, Celery workers, Postgres, Redis | `aegis/api`, `aegis/workers` (`celery_app.py`, `bootstrap.py`, `job_state.py`, `tasks/`), `aegis/db`, `deploy/docker-compose.yml` | Validate, attack, explain, harden and verify jobs run asynchronously on workers; the API process never loads a model (section 10). |
| Hash-chained audit log (Postgres-backed, JSONL offline) with WORM export to S3 Object Lock | `aegis/audit/chain.py`, `aegis/audit/forensic.py`, `aegis/storage/worm.py`, `aegis/workers/tasks/worm_export.py`, `aegis audit verify` CLI | Every model upload, attack, explanation, hardening report and verify replay is a chained event; the demo ends on `/audit` (sections 5, 21). |
| RBAC on resource-scoped actions plus pluggable policy engine | `aegis/api/policy.py` (roles `scanner` < `remediator` < `approver` < `admin`, project memberships), `aegis/policy` (static / OPA / Cedar), `deploy/opa`, `deploy/cedar` | William's Owner / Analyst / Reviewer / Viewer matrix maps onto these roles; the independent-approval rule is enforced here (section 7). |
| Postgres row-level security by `org_id` | `aegis/db` models and migrations (`aegis/migrate`), `tests/test_tenant_rls.py` | Model artifacts, findings and artifacts inherit tenant isolation; one tenant never sees another's model or results. |
| `Run` / `Job` / `Finding` / `Artifact` models with typed vocabularies | `aegis/db/models.py`, `aegis/schema.py` (`Severity`, `Status`, `Confidence` literals), `aegis/workers/job_state.py` | Map directly to campaigns, attack jobs, adversarial findings and SHAP / adversarial-example outputs (sections 5, 6). |
| Generic registry with duplicate detection; scanner registry and capability vocabulary | `aegis/registry.py`, `aegis/scanners/registry.py`, `aegis/scanners/severity.py` | ART attack adapters and SHAP explainers register the same way scanner adapters did. New capability tags: `adversarial_ml`, `explainability`. The 14 pentest adapters and the `/tools` page are deleted, so attacks are listed at `GET /v1/attacks` and in the launcher UI instead (sections 12, 17). |
| Out-of-process plugin sandbox (`AEGIS_PLUGINS_SANDBOX`) | `aegis/scanners/sandbox.py`, `aegis/scanners/sandbox_worker.py`, `aegis/supply_chain` | Uploaded model files are loaded only inside this pattern on the worker: separate process, rlimits, wall-clock kill, minimal allow-listed environment, network off by default (section 9). |
| Verify-after-fix pattern (`verify.replay`) | `aegis/workers/tasks/verify.py`, `aegis/services/verify.py`, `aegis/verify.py` (`VerifyStatus` = `verified` / `still_vulnerable` / `inconclusive`, mapped by `_STATE_MAP` onto `Finding.validation_state` = `poc_passed` / `poc_failed` / `inconclusive`) | Re-attack after applying a preprocessing defense; write the measured ΔMRI and flip `validation_state` (sections 6, 10, 15, 16). |
| Admission pattern: audit event before enqueue, cancel service, stale-job reaper | `aegis/services/runs.py`, `aegis/services/scans.py`, `aegis/workers/tasks/reaper.py`, `tests/test_admission_audit_before_enqueue.py` | Campaign start, cancel and time-out semantics come for free (section 10). |
| Per-task LLM routing, budget caps, pricing, guardrails, redaction | `aegis/llm/router.py`, `aegis/llm/budget.py`, `aegis/llm/pricing.py`, `aegis/llm/guardrails.py`, `aegis/audit/redact.py` | Policy layer for the recommendation writer. Transport is Pythia only (`aegis/llm/pythia.py`, D5); no provider keys are held (section 16). |
| Managed authentication: Keycloak OIDC on the API, NextAuth in the web app, dev-token mode | `aegis/api/auth.py`, `aegis/api/session_cookie.py`, `deploy/keycloak`, `web/src/app/login`, `web/src/app/api` | Satisfies F001 and constitution principle IV; dev-token mode is allowed for the demo (D11 D002; section 7). |
| Next.js web app, design system, command palette, RBAC gating | `web/src/app/{login,dashboard,runs,findings,projects,targets,auth-profiles,logs,audit,cost}`, `packages/design-system` (`run-status-badge`, `stage-timeline`, `severity-chip`, `finding-card`, `evidence-diff`, `audit-chain-badge`, `role-gated`, primitives) | Extend with `/models`, the attack launcher, the MRI scorecard on `/runs/[id]` and the three-pane `/findings/[id]` screen (section 18). The `agents` and `tools` pages are deleted. |
| Blob storage abstraction (filesystem / S3 / MinIO) and run-state facade with sha256 artifact refs | `aegis/storage/blobs.py`, `aegis/storage/s3.py`, `aegis/state/{facade,filesystem,postgres}.py` | Models, adversarial examples, SHAP PNG/JSON and robustness curves are `Artifact` rows with content hashes (section 5). |
| XSS-safe Markdown → HTML report rendering | `aegis/report.py` (`html_escape`, `render_inline_markdown`, `_md_to_html_min`), `aegis/services/reports.py`, `aegis/workers/tasks/report.py` | Markdown / JSON / HTML campaign reports that preserve configuration and provenance (sections 14, 17). |
| Observability: OpenTelemetry, structured logs, Loki, log ingest | `aegis/observability.py`, `aegis/log_ingest`, `deploy/otel`, `deploy/loki`, `Dockerfile.log_ingest` | Worker and API tracing with secret redaction; `/logs` page. |
| Helm chart and container images | `deploy/helm`, `deploy/Dockerfile.{api,worker,web,postgres,log_ingest}`, `deploy/Makefile`, `deploy/kind.yaml` | Compose dev stack now; the images are the basis of the ECS Fargate target (section 20). |
| `AuthProfile` (Fernet-encrypted credentials) | `aegis/services/auth_profiles.py`, `web/src/app/auth-profiles` | Reserved for black-box endpoint credentials in Phase B (section 5). |
| Test harness | `tests/conftest.py` (sqlite session factory, `integration` marker), `pyproject.toml` `ml` marker, `tests/ml/fakes.py` (`TinyTarget`) | Offline unit tests for the ML vertical without the network or the real datasets (section 22). |

### 2.2 What was removed, and what is not yet built

Removed for good: the 14 pentest scanner adapters, `aegis/{agents,tools,integrations,remediate,runners}`, the Kali image, the CAI agents, the GitHub app and webhooks, ticketing, the CI gate, demo and vendor tooling, all git submodules, and the `agents` / `tools` web pages. `README.md` still carries the aegis pentest introduction; updating it is outside this spec.

Not yet built: the ML vertical itself. As of this spec `aegis/ml/` contains contracts only (`schema.py`, `targets/base.py`, `attacks/base.py`, empty `explain/` and `recommend/` packages), plus `aegis/llm/pythia.py` and `tests/ml/fakes.py`. No loader, attack adapter, explainer, rule set, Celery task, route or page for the ML vertical exists. The `ml` optional-dependency group in `pyproject.toml` (numpy, torch, torchvision, onnx, onnxruntime, scikit-learn, adversarial-robustness-toolbox, shap, matplotlib, pillow, pyarrow, httpx) is declared; it is installed only in the worker image (section 20). A concurrent code fix-up is making the restored platform import-clean.

### 2.3 The rejected alternative, for the record

S2 proposed stripping aegis to a `redsim/` package with no database, queue, auth, tenancy or audit chain, running attacks in a `ThreadPoolExecutor` inside the API process with `run.json` as state. Its rationale was speed to a 1–2 day demo and the fact that its milestone executed no untrusted artifacts. D1 rejects it because Phase A as decided (D2, D4) does load uploaded artifacts, does require a hash-chained trail for every action, and does need the F001/F008 access and governance features that aegis already provides. The cost of D1 is a heavier stack to keep import-clean and deploy, which is recorded as a risk in section 25 and addressed by the demo-critical order in section 3.4. S2's evidence model, reporting constraints, Pythia connector, testing approach and honesty rules are all carried into this spec unchanged.

## 3. Scope and phasing

S1's plan was all four modalities and both ingest paths, phased so the demo-day path is never at risk. The owner's decisions narrow and sharpen Phase A (D2, D4), move the endpoint connector and the LLM domain to Phase B (D2, D6), and fix the order inside Phase A (D8).

### 3.1 Phase A — demo-critical path (must land)

| Area | Phase A deliverable | Source and decision |
|---|---|---|
| Modalities | **Image classifier** (CV) and **tabular classifier**, both live end to end. The **LLM** domain is registered as a target kind whose connection shape is real (Pythia base URL, `pk_…` key, persona, canonical `<vendor>/<model>` id) but whose launch returns HTTP 501 with a stated reason. | S1 §3; S2's tabular stub overridden by D4(d); LLM stub retained from S2, Phase B per D6 |
| Ingest | **Bundled sample models** (the image CNN trained on the section 11 imagery dataset, the tabular tree-ensemble classifier on the section 11 tabular dataset, and the CIFAR-10 small CNN kept as the CI fixture) **and white-box artifact upload**: ONNX preferred; PyTorch `state_dict` accepted only with an explicit architecture declaration; full pickles refused by default with an explicit error (section 17); uploaded files are loaded only on the worker inside the plugin sandbox, never in the API process. TensorFlow SavedModel (S1) is not accepted in Phase A; convert to ONNX. | S1 §3, §5; D2; S2's "bundled only" overridden |
| Datasets | Open, unclassified, public datasets with a clear license only: the aerial / military-vehicle imagery dataset and the tabular dataset named in section 11. Dataset id and revision hash go into `Provenance`. CIFAR-10 (HF hub `uoft-cs/cifar10`, torchvision U. Toronto download as fallback only) is the CI/fixture dataset, not a demo dataset. Fixture results are labelled fixture and never presented as evidence. | D3; S2 §2.2 overridden for the demo, retained for CI; S3 "no fixture data as results" |
| Attacks | Image: FGSM, PGD (L∞ and L2). Tabular: PGD (white-box, by surrogate transfer), HopSkipJump (black-box access to the local model). Every attack family is paired with a **benign uniform random-noise control at the same ε**. **ε sweep** for L∞ image attacks over `{0.01, 0.03, 0.1}` (configurable in the campaign configuration) with a robustness curve; a `Finding` is created when the success rate crosses the configured threshold at any ε. | S1 §6; S2 §2.3 noise control; D4(b) |
| Explainability | Image: gradient-based SHAP saliency, clean vs adversarial, with the center-mass ratio labelled `heuristic`. Tabular: `TreeExplainer` bar and beeswarm plots. Explanation shift (`1 − cosine similarity` of clean vs adversarial attributions) feeds the MRI. PNG and raw-values artifacts written as `Artifact` rows. | S1 §7; S2 §2.4; D4(d); section 13 |
| Scoring | The Model Robustness Index per campaign: inputs, five subscores (weights 0.35 / 0.25 / 0.20 / 0.10 / 0.10), aggregate, grade bands with attack-scoped readings, derived finding severity, ΔMRI on verify, all under the binding constraints of D9. | S1 §8; D9 |
| Recommendations | Two layers: deterministic rules that cite the measurement ids that triggered them, then an LLM writer reached **only through Pythia** that receives metrics and a SHAP text summary, never images or model data, in one plain non-streaming chat completion. Every recommendation is `status: candidate`, `validation: not evaluated` until the verify loop measures it. | S1 §9; S2 §2.5; D5; D9(iv) |
| Verify-after-harden | Apply an ART preprocessing defense (feature squeezing or spatial smoothing) to an evaluation copy of the model, re-run the same attack set at the same ε grid and reference budget, report the measured ΔMRI and per-dimension and per-family deltas, set `Finding.validation_state`. | S1 §8.6, §14 M6; D4(a) |
| Audit | A hash-chained audit event for every model upload, validation, campaign start, attack job, explanation, hardening report, verify replay and report export; Postgres-backed chain with JSONL offline mode; WORM export. | S1 §2, §13; D4(c) |
| Evidence and reports | Measurements, observations, interpretation and candidate recommendations as separate fields and separate UI panels; per-family tables with `n`; provenance with nondeterminism sources; limitations always present; Markdown / JSON / HTML reports that preserve enough configuration to rerun. | S2 §3, §5; brief reporting principles; section 14 |
| Web UI | `/models` (list, upload dialog, bundled sample picker; "Connect endpoint" shown as Phase B / unavailable), `/models/[id]` (summary and "Run attack" launcher), `/runs/[id]` (campaign progress, MRI scorecard with the five bars, robustness curve, findings table, per-family table), `/findings/[id]` (three panes: input pair, SHAP clean vs adversarial, candidate recommendations with "Verify"), reuse of `/audit`, `/runs`, `/findings`, `/projects`, `/targets`. Not-implemented states are shown with their reason. | S1 §11; S2 §5; section 18 |
| Access and tenancy | Keycloak OIDC + NextAuth (dev-token mode allowed for the demo), aegis RBAC with William's matrix mapped onto aegis roles, Postgres RLS. | D1; D11 D002; section 7 |
| Deployment | Docker-compose dev stack (api, worker, web, postgres, redis, MinIO, Keycloak); ECS Fargate + RDS Postgres + S3 + ElastiCache Redis as the Phase A target (M7). `ml` extra only in the worker image. | S1 §12; D1; section 20 |
| Testing | pytest with the sqlite conftest, `TinyTarget` fake and the `ml` marker; vitest for the web panels; assertions on labels, denominators and refusal paths. | S2 §7; section 22 |

### 3.2 Phase B — stretch (add only after Phase A runs end to end)

- **Ingest:** black-box API endpoint connector (query-only), credentials in `AuthProfile`, `Target.kind = ml_model_endpoint`.
- **Modalities:** text / NLP classifier and object detection (YOLO-style).
- **Attacks:** Carlini-Wagner L2, DeepFool, image HopSkipJump, Zeroth-Order Optimization (tabular black-box), TextFooler-style word substitution, adversarial patch / DPatch for detection.
- **Explain:** KernelSHAP for black-box models; text token attributions.
- **Harden:** adversarial training on a bundled model with the measured delta; defensive distillation.
- **LLM-domain red-teaming:** garak probes against the LLM target, with garak's OpenAI-compatible generator pointed at Pythia (D6).
- **Review workflow:** the full `draft / in_review / confirmed / dismissed / retest_requested / resolved` finding review states from S3. Section 6 decides what ships in Phase A: reviewer **dismissal** (`Finding.status = false_positive` through `finding.review`, independent of the campaign author) plus free-text `reviewer_notes`; confirmation, revisions and `resolved` are Phase B.
- **Reports:** PDF export (S3 F007 asks for PDF and JSON; Phase A provides Markdown, JSON and HTML, the HTML being the printable form); run-comparison UI beyond the ΔMRI on verify (section 15).
- **Trust override for pickles:** none in Phase A; if ever added it is approver-gated, sandboxed and audited.
- **Interoperability (B2, section 27):** Croissant / Parquet adversarial-dataset export and its consume side (ONNX models and evaluation slices from other teams), MITRE ATLAS technique tags on findings with a per-campaign coverage view, and env-selected platform pushes (Palantir Foundry primary; Anduril Lattice exploratory and blocked by the D3 "no mission-system connections" bound until an explicit decision resolves it). Opt-in, off by default, data and REST integrations only, no LLM calls.

### 3.3 Non-goals for the hackathon

From S1, the brief and the constitution together:

- Training pipelines or model registries beyond upload.
- GPU. All demo models run on CPU; sample models stay small.
- Classified, operational or sensitive data; live connections to mission systems.
- Training, optimising or deploying targeting or weapons models; the tool evaluates and hardens the robustness of a classifier only (D3 bounds).
- A training-data poisoning pipeline (the original use case mentions poisoning; the brief and S1 exclude it).
- Autonomous application of mitigations to a deployed model. The verify loop wraps an evaluation copy inside the campaign only.
- Any claim of certification, causal certainty or deployment readiness.
- A universal score that mixes test families or domains. The MRI is per campaign and always travels with its denominators (section 15).
- Agent applications and tool-using agents (a separate scope per the brief; aegis's agent runtime is deleted).
- Simultaneous support for conventional ML, LLMs and agents; the LLM domain is a Phase B stub in Phase A.

### 3.4 Demo-critical order inside Phase A, and the timeline statement

The owner originally asked for a 1–2 day build. **Phase A as decided exceeds a 1–2 day build**: it adds upload with sandboxed loading, the ε sweep, the MRI scorecard, the verify loop, a second live modality and a Fargate deployment on top of the image path. S1's milestones M0–M7 and B1+ are kept (section 23), together with S1's "freeze Phase A first" rule: do not start text, detection, endpoints or garak until image and tabular run end to end. Inside Phase A the build order is fixed so that whatever is unfinished on demo day is the least important item and is shown as unavailable rather than faked:

| Order | Increment | What it proves on its own | Milestones |
|---|---|---|---|
| 1 | **Image path end to end**: bundled image model, FGSM and PGD, noise control, ε sweep with robustness curve, SHAP clean vs adversarial, rule-layer candidates, LLM writer via Pythia, audit events, evidence panels | Questions 1–3 of section 1 are answered for one real model with genuine evidence | M0, M1, M2, M3, M5a |
| 2 | **MRI scorecard** on `/runs/[id]`: subscores, grade, per-family table, curve, derived severities | One honest per-campaign summary that never leaves its denominators | M3, M5a |
| 3 | **Verify-after-harden**: ART preprocessing defense, re-attack, measured ΔMRI, `validation_state` | The only sanctioned form of "gain" is a measured delta | M6 |
| 4 | **Tabular path**: bundled tree-ensemble model, PGD (surrogate transfer) and HopSkipJump, TreeExplainer bar and beeswarm | A second modality with its own MRI, never merged with the first | M4 |
| 5 | **ONNX / state_dict upload** with sandboxed worker loading and pickle refusal | The upload boundary the brief asks to review before accepting | M1 (loader branch), M5b (dialog) |
| 6 | **Fargate deployment** | The stack runs off a laptop | M7 |

Everything in Phase B waits behind item 6.

## 4. Reconciliation table

Three spec sources, the brief and the constitution were consolidated into this document. This section lists every point where they diverged from each other or from the owner's decisions, the decision that settles it, and where the consequence lands. Decisions are identified D1–D13 and are final; they override every source where they conflict.

### 4.1 Decision index

| Id | Decision (2026-09-08, product owner) |
|---|---|
| D1 | Reuse the full aegis platform now (FastAPI, Celery, Postgres, Redis, S3/MinIO, Keycloak/NextAuth, RBAC, RLS, audit chain, LLM routing and budgets, observability). |
| D2 | Phase A ingest: bundled sample models and white-box upload (ONNX preferred; `state_dict` with explicit architecture; full pickles refused by default); loading only on the worker in the plugin sandbox. Endpoint connector is Phase B. |
| D3 | Demo data: open, unclassified, public aerial / military-vehicle imagery with a clear license; a knowing, bounded divergence from the brief's and constitution's non-operational language. CIFAR-10 is the CI fixture. |
| D4 | Phase A also includes the verify-after-harden loop, the ε sweep with robustness curve, hash-chained audit events for every action, and a live tabular classifier. |
| D5 | All LLM calls go through Pythia; aegis routing and budgets remain the policy layer; env `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `AEGIS_ML_LLM_MODEL`; text-only inputs; one plain non-streaming completion. |
| D6 | garak / LLM-domain red-teaming is Phase B only; garak's generator points at Pythia. |
| D7 | Names: product "Adversarial ML Red-Team Simulator"; namespace `aegis`, vertical `aegis/ml/`; web app `@aegis/web`; "redsim" retired except as history. |
| D8 | Keep M0–M7 and B1+; state that Phase A exceeds 1–2 days; fix the demo-critical order (section 3.4). |
| D9 | Adopt the MRI with binding constraints (i)–(vi): per campaign, never cross-modality, never without subscores + per-family table + curve, attack-scoped grade text, ΔMRI as the only "gain", illustrative numbers labelled, recorded as a divergence from the brief. |
| D10 | William's Spec Kit tree becomes the feature-level layer beneath this spec; F001–F008 mapped onto aegis components; Replit paths replaced by aegis paths; aegis state machines canonical. |
| D11 | Decision register: D001–D005 RESOLVED (approver "product owner (hackathon), 2026-09-08"); D006, D007 stay OPEN with no invented owners. |
| D12 | Constitution: principles unchanged; an "Amendment proposals (2026-09-08)" section is appended, status "proposed, pending named approval"; ratification not claimed. |
| D13 | Fold `docs/brief.md` into `docs/project-brief.md` (keep William's filename, add our additions), delete `docs/brief.md`, fix references in docs/specs/.specify. |

### 4.2 Divergences and their resolution

Source keys: **S1** = John Sasser's product spec (`docs/adversarial-ml-redteam-spec.md`); **S2** = the lean design (`docs/superpowers/specs/2026-09-08-redsim-design.md`) and the code contracts in `aegis/ml/`; **S3** = William Yiu's Spec Kit tree (`.specify/`, `specs/`); **Brief** = `docs/project-brief.md`; **Const.** = `.specify/memory/constitution.md`.

| # | Topic | Positions in the sources | Decision | Consequence in this spec |
|---|---|---|---|---|
| 1 | Platform and stack | **S1:** full aegis (API, Celery, Postgres, Redis, S3, auth, RBAC, RLS, audit). **S2:** strip aegis to `redsim/`; no DB, queue, auth, tenancy or audit; `ThreadPoolExecutor` in the API process, `run.json` state, SWR polling. **S3:** reuse the Replit pnpm monorepo (`artifacts/api-server`, `lib/api-spec`, `lib/db`, `artifacts/ai-assurance`); no worker runtime selected. **Brief:** no implementation implied. | D1 | Sections 2, 8, 20. S2's in-process runner and `run.json` are replaced by Celery jobs and Postgres; S3's paths are replaced by aegis paths (row 30). |
| 2 | Product, package and env naming | **S1:** aegis fork, `aegis/ml/`. **S2:** `redsim`, `redsim/` package, `@redsim/design-system`, `REDSIM_LLM_MODEL`, `redsim_version`, footer title "redsim". **S3:** "AI Assurance". | D7, D5 | Product is "Adversarial ML Red-Team Simulator"; namespace `aegis`, vertical `aegis/ml/`, web `@aegis/web`; `Provenance.aegis_version`. `aegis/llm/pythia.py` and the `RunConfig.llm_narrative` comment still read `REDSIM_LLM_MODEL` and change to `AEGIS_ML_LLM_MODEL` at M0 (sections 20, 22, 23). "AI Assurance" survives only as the constitution's title and the Spec Kit tree's name for the process layer. The short product name is settled in row 56. |
| 3 | First domain(s) | **S1:** image and tabular live in Phase A; text and detection Phase B. **S2:** image only; tabular and LLM registered as `not_implemented`. **S3:** D001 OPEN; proposal is a public/synthetic document-category classifier *or* a synthetic FAQ assistant, one domain only. **Brief:** choose one domain first; image-first was an assumption, not an approval. | D3, D4(d), D11 (D001 RESOLVED, diverges from the S3 proposal) | Image and tabular both live (section 3.1); this diverges from the brief's "one domain first" and is accepted because each modality is a separate campaign with its own MRI and is never merged (D9(i)). LLM target stays a 501 stub with a real Pythia connection shape (rows 21, 22). |
| 4 | Demo dataset | **S1:** bundled aerial-target CNN; demo shows a tank image. **S2:** CIFAR-10 test split, chosen over aircraft / vehicle / satellite datasets to keep the demo unambiguously non-operational; `STANDING_LIMITATIONS` hard-codes a CIFAR-10 sentence. **S3 / Const. II:** non-operational assurance on public or synthetic data; do not implement operational military model evaluation. **Brief:** source context is not authorization to build targeting systems. | D3, D12(a) | Open, unclassified, public aerial / military-vehicle imagery with a clear license (concrete dataset in section 11). Recorded as a knowing team divergence with bounds: open data only; the tool evaluates and hardens a classifier's robustness and never trains, optimises or deploys targeting or weapons models; no mission-system connections. CIFAR-10 remains the CI fixture. The dataset-specific limitation sentence becomes parameterised by the campaign's dataset (section 14). Constitution amendment (a) proposed, not ratified. |
| 5 | Model ingest | **S1:** upload (ONNX / SavedModel / `state_dict`), endpoint connector, bundled models; pickle allowed only with an explicit "I trust this file" box, still sandboxed. **S2:** bundled model only; no uploads, no endpoints; "Uploading and executing arbitrary model artifacts" out of scope. **S3:** F002 FR-004 rejects uploads and arbitrary endpoints pending D003; D003 proposal defers both. **Brief:** unrestricted execution of uploaded artifacts is out of scope; data handling and execution boundaries receive review before accepting uploads. | D2, D11 (D003 RESOLVED, diverges from the S3 proposal), D12(b) | Bundled models plus ONNX / `state_dict` upload with sandboxed worker-side loading; full pickles refused by default; TensorFlow SavedModel not accepted in Phase A; no trust-override box in Phase A (section 3.2). Endpoint connector Phase B. Refusal error codes in section 17; isolation rules in section 9; the bounded-not-unrestricted argument in section 21 and the proposed constitution amendment (b). |
| 6 | Execution environment | **S1:** load and run every uploaded model in the plugin sandbox on the worker; never in the API process. **S2:** in-process, local, no sandbox, justified because no untrusted artifacts were executed. **S3:** D004 OPEN; bounded worker separate from the web process; OpenSandbox only a candidate. **Const. IV:** never execute untrusted work in the web process. | D1, D2, D11 (D004 RESOLVED) | Celery worker plus the aegis plugin sandbox pattern; OpenSandbox not used. S2's justification lapses because D2 admits uploads. Sections 8, 9, 10. |
| 7 | Authentication and identity | **S1:** Keycloak on Fargate or Cognito via OIDC; dev mode acceptable for the demo. **S2:** no auth; delete login, NextAuth and jose. **S3:** D002 OPEN; managed provider, no custom passwords, no locally minted tokens; invitation flow. **Const. IV:** managed authentication. | D1, D11 (D002 RESOLVED) | Keycloak OIDC + NextAuth. Dev-token mode is allowed for the local compose stack and the demo only; it is not the Fargate configuration. S3's invitation flow maps onto aegis project memberships (section 7, section 19 F001). |
| 8 | Multi-tenancy and object-level authorization | **S1:** RBAC + Postgres RLS by `org_id`. **S2:** removed. **S3:** membership and object-level authorization on every action; "Replit collaborator ≠ application member". | D1 | RLS and project memberships as implemented in aegis; section 7. |
| 9 | Audit trail | **S1:** hash-chained audit, WORM to S3, `aegis audit verify`. **S2:** removed; provenance in `run.json` only. **S3:** F008 append-only event envelope, early foundation. **Brief / Const. V:** provenance, accountable history. | D1, D4(c) | Chained events for upload / validate / attack / explain / harden / verify / export; Postgres chain with JSONL offline; WORM export. `AuditEvent.action` values in section 5; ordering (audit before enqueue) in section 10; F008 mapping in section 19. |
| 10 | A single robustness score | **S1:** the MRI reduces every campaign to one number that drives scorecard, severities and ranked recommendations; comparable across runs at the same settings. **S2:** explicitly excludes "a universal robustness score that mixes test families or domains". **S3:** F005 FR-005 and F007 FR-008: unrelated metrics MUST NOT become a universal score. **Const. III:** evidence must remain distinguishable. **Brief:** present results by test family with denominators; avoid a universal score that mixes unrelated domains. | D9, D12(c) | The MRI is adopted with binding constraints: (i) computed per campaign (one model × one modality × declared attack set × ε grid × reference budget), never aggregated across modalities or domains, never compared across campaigns with different settings; (ii) never shown without its five subscores, the per-family accuracy table with `n`, and the ε curve; (iii) attack-scoped grade text, no readiness statement; (iv) ΔMRI is the only sanctioned "gain"; (v) demo numbers labelled illustrative. Recorded as a divergence from the brief's principle, justified as a per-campaign summary that never mixes domains and always travels with its denominators. Section 15; constitution amendment (c) proposed. |
| 11 | Grade-band wording | **S1 §8.4:** "Hardened", "Harden before fielding", "Not deployment-ready". **Brief / Const. III:** passing is not certification or operational readiness. | D9(iii) | Readings reworded to describe robustness under the in-scope attacks at the reference budget only; each band carries the statement that no grade is a readiness or certification statement. Section 15. |
| 12 | "Expected robustness gain" on recommendations | **S1:** question 3 is "scored by expected robustness gain"; the LLM writes "expected robustness gain"; the UI shows recommendations "with expected gain"; §8.6 checks expected gain against ΔMRI. **S2:** every recommendation is `status: candidate`, `validation: not evaluated`; no gain figure. **Brief:** treat recommendations as candidates until a separate evaluation; do not invent measured improvements or validated fixes. | D9(iv) | No numeric expected gain is shown or written until the verify loop has measured it on this model at these settings. `CandidateRecommendation` keeps its `Literal` status; after verify, the measured ΔMRI is attached to the recommendation as a measurement (`validation: measured`, section 16.4), not a prediction. Section 1 rewords question 3; sections 16 and 18 carry the rule. |
| 13 | Finding severity | **S1 §8.5:** derived from ε at first success and ASR; written to `Finding.severity`. **S2:** no findings or severities; measurements only. **S3:** F006 severity is a reviewer judgment among reviewable fields. | D9, D11 (D005 RESOLVED: thresholds per S1 §8.5) | Severity is derived, labelled as derived from the in-scope attacks, and is not a review verdict; review (row 27) is separate. Section 15. |
| 14 | Verify-after-harden and "resolution" | **S1:** Phase A M6; reuse `verify.replay`; the finding "flips to `verified`". **S2:** out of scope; autonomous application of mitigations excluded; `validation: not evaluated` is permanent within a run. **S3:** F006 resolution requires a compatible, independently reviewed retest; a rerun alone is not resolution. **Brief:** no autonomous application; measured improvements only from a separate evaluation. | D4(a) | The verify loop is Phase A. The defense wraps an evaluation copy (an ART preprocessor around the estimator) inside the campaign; no deployed model is modified. The worker's `VerifyStatus` (`verified` / `still_vulnerable` / `inconclusive`) is mapped by the existing `_STATE_MAP` onto `Finding.validation_state` (`poc_passed` / `poc_failed` / `inconclusive`) from the measured re-attack; S3's human `resolved` state is handled in section 6. ΔMRI is reported with per-dimension and per-family deltas. Sections 6, 15, 16. |
| 15 | Benign noise control | **S1:** none. **S2:** `noise_control` in the same L∞ ball at the same ε, no gradient. **S3:** F003 requires benign controls. **Brief:** include benign controls. | D4 (retained), D11 (D005) | Every attack family is paired with a uniform random-noise control at the same ε; its accuracy appears in the per-family table and is cited by the "gradient-aligned failure" rule. Sections 12, 14, 16. |
| 16 | ε sweep | **S1:** sweep `{0.01, 0.03, 0.1}` L∞, robustness curve, finding on threshold at any ε. **S2:** single ε (default 0.03); "single eps unless swept" listed as a limitation. | D4(b) | Sweep is Phase A; `S_eps` (area under the robust-accuracy vs ε curve) is a subscore; the campaign configuration stores the grid and the reference budget. Sections 12, 15. |
| 17 | SHAP method and heuristics | **S1 §7:** `DeepExplainer` or `PartitionExplainer` (image); `TreeExplainer` / `KernelExplainer` (tabular); `PartitionExplainer` (text); `KernelExplainer` (black-box). **S2:** `shap.GradientExplainer` with a 50-image background, first `k` flipped and `k` unflipped samples, center-mass ratio labelled `heuristic`. **S3 / Brief:** SHAP only where meaningful and supported; not causal; not required for every modality. | D4(d); no override | Section 13 fixes the image explainer and keeps S1's alternatives as documented options; `TreeExplainer` for tabular; the center-mass ratio stays `heuristic`; explanation shift feeds `S_expl`; the LLM stub has no SHAP; "SHAP is not causal" is a standing limitation. |
| 18 | Evidence model | **S1:** `Finding.schema_blob` carries attack name, ε, success rate, confidence drop, SHAP artifact ids (and, from S1 §14, the MITRE ATLAS technique; row 57); `Artifact` rows for examples, saliency, curves. **S2:** `RunRecord` with separate `measurements`, `observations`, `interpretation`, `recommendations`, `limitations`, `provenance`, `reviewer_notes`. **S3:** Evidence / Finding / Recommendation / Review / ReportSnapshot entities with schema versions. **Brief:** observations, interpretation and candidates separated. | D1, D10 | Both are kept: S2's `RunRecord` fields are distributed across `Finding.schema_blob`, `Artifact` rows and the campaign/score record exactly as section 5 specifies; S1's confidence drop becomes a measurement-level `conf_gap` next to S2's per-observation confidences; the four fields remain four UI panels (sections 14, 18). |
| 19 | When a finding is created | **S1:** when ASR crosses a configurable threshold at any budget. **S2:** no findings; a run is a record of measurements. | S1 kept | Threshold per attack / test family (`finding_asr_threshold`, default 0.2) lives in the campaign configuration (F003) and is stored with the `Run`. Sections 5, 12, 15. |
| 20 | LLM access | **S1:** reuse per-task routing and budget caps (aegis historically routed to providers). **S2:** Pythia only, default off, `REDSIM_LLM_MODEL`, optional `pythia_sdk` with httpx fallback, guardrails, "may not introduce new claims". **S3:** no provider SDK selected. | D5 | Pythia is the only transport; aegis routing and budgets remain the policy layer; env renamed; the writer receives only metrics and a SHAP text summary; one plain non-streaming chat completion; no tools, vision or structured output; no provider keys anywhere. Sections 16, 21. |
| 21 | garak and the LLM domain | **S1:** not mentioned; text classifier via TextFooler in Phase B. **S2:** LLM target is a stub describing a Pythia connection; garak's generator would point at Pythia. **S3 / Brief:** garak informs scope, not a selected dependency; TIP paper informs coverage only. | D6 | Phase B only; garak's OpenAI-compatible generator points at Pythia. Section 3.2. |
| 22 | Web UI | **S1:** `/models`, `/models/[id]`, `/runs/[id]` with MRI scorecard, three-pane `/findings/[id]`, reuse `/audit`. **S2:** `/targets`, `/runs/new`, `/runs/[id]` two columns (Evidence vs Interpretation & candidates), footer disclaimer, delete login / projects / audit / findings pages. **S3:** F005 evidence workbench, F006 review queue. | D1, D10 | S1's pages, with S2's panel separation inside `/runs/[id]` and `/findings/[id]` and S2's footer line on every page; aegis's `login`, `dashboard`, `runs`, `findings`, `projects`, `targets`, `auth-profiles`, `logs`, `audit`, `cost` pages retained; `agents` and `tools` deleted. Section 18. |
| 23 | API | **S1:** `/v1/models`, `/v1/models/{id}/attacks`, `/v1/findings/{id}/{explain,harden,verify}`, reuse `/v1/runs/{id}`, `/v1/findings`, `/v1/artifacts/{id}`. **S2:** `/health`, `/v1/targets`, `/v1/attacks`, `/v1/runs` (202 / 501 / 422), `PATCH /v1/runs/{id}/reviewer-notes`, run-confined artifact paths, `report.{md,json,html}` with a strict CSP; no auth. **S3:** contract-first OpenAPI at `lib/api-spec/openapi.yaml` with generated clients. | D1, D10 | Merged in section 17 under aegis auth: S1's routes plus S2's `/v1/attacks`, 501 for stubs, reviewer notes and report routes; S3's contract path is replaced by the FastAPI-generated OpenAPI consumed by `web/src/lib/api.ts`. |
| 24 | Reports | **S1:** LLM-written hardening report. **S2:** Markdown / JSON / HTML preserving `config` + `provenance`; JSON equals `RunRecord.model_dump()`. **S3:** F007 immutable snapshots, PDF and JSON exports. | D1, D10 | Markdown, JSON and HTML via `aegis/report.py` in Phase A; PDF is Phase B, HTML is the printable form. Sections 14, 17. |
| 25 | Comparing runs | **S1:** ΔMRI and per-dimension deltas after verify; scores comparable only at the same settings. **S3:** F007 compares only compatible runs, lists changed / unchanged / unknown variables, blocks incompatible pairs, no universal score. **Brief:** the report supports a follow-up comparison. | D9(i), D9(iv) | ΔMRI is computed only between compatible campaigns (equal `settings_hash`: same model, modality, attack set, ε grid, reference budget, dataset id and revision, slice size, seed and scoring settings) and is presented with the list of changed variables; incompatible pairs are blocked with reasons. Sections 15, 17, 19 (F007). |
| 26 | Run states | **aegis (S1):** `Job` machine `queued → running | cancelled`, `running → succeeded | failed | cancelled | queued` (retry requeue), terminal sinks; `Run.status`. **S2:** `queued / running / succeeded / failed / not_implemented` with a `stage` field and `STAGES`. **S3:** `queued / running / cancel_requested / completed / failed / cancelled / timed_out` with ordering rules for racing completion. | D10 | aegis's `Job` machine (`aegis/workers/job_state.py`) is canonical. S3's states map onto it in section 6 (`completed` ↔ `succeeded`; `timed_out` ↔ `failed` with a reaper or timeout reason; `cancel_requested` ↔ the cancel service's transient). S2's `not_implemented` is an admission-time 501, never a `Job`; S2's `stage` becomes per-job progress on the stage table. |
| 27 | Finding review states | **aegis:** `Finding.status` `open / fixing / fixed / failed / false_positive`; `validation_state` `unvalidated / poc_passed / poc_failed / inconclusive`. **S2:** a free-text `reviewer_notes` field. **S3:** `draft / in_review / confirmed / dismissed / retest_requested / resolved`, independent approval, revisions, retest links. | D10 | aegis enums are canonical; the mapping and the Phase A / Phase B decision on the review workflow are stated in section 6 (dismissal in Phase A; confirm / resolve Phase B). Phase A keeps `reviewer_notes`. |
| 28 | Roles | **aegis:** `scanner` < `remediator` < `approver` < `admin` plus project memberships (`aegis/api/policy.py`). **S3:** Owner / Analyst / Reviewer / Viewer with "approve, except own authored item", last-owner protection, invitation lifecycle. **S2:** none. | D1, D10 | William's matrix is mapped onto aegis roles in section 7 (read ↔ membership; register / start / cancel ↔ `scanner` and `remediator`; approve / confirm ↔ `approver`; manage ↔ `admin`); the independent-approval rule is enforced for profile approval and finding confirmation. |
| 29 | Campaign configuration (evaluation profile) | **S1:** attack body (modality, attacks, budget grid, dataset id); `scoring` weights overridable per project; reference budget and ε grid stored with each score. **S2:** `RunConfig` (target, attack, params, `n_samples`, `seed`, `include_control`, `explain_k`, `llm_narrative`). **S3:** F003 versioned, immutable, independently approved `ProfileVersion` with controls, denominators, limits, explanation settings. | D10 | An approved campaign configuration (`CampaignConfig`) = attack set, ε grid, reference budget, sample dataset id + revision, `n_samples`, `seed`, `include_control`, `explain_k`, scoring weights, finding threshold; stored immutably with the `Run` (section 5); approval rule in section 7; F003 mapping in section 19. Per-project weight overrides are Phase B. |
| 30 | Implementation locations | **S3:** `artifacts/api-server/src/{routes,services}/assurance/`, `lib/api-spec`, `lib/api-client-react`, `lib/api-zod`, `lib/db/src/schema/`, `artifacts/ai-assurance/`. **S1:** `aegis/ml/{loaders.py,attacks/,explain/,harden.py,eval.py}`, `aegis/workers/tasks/{attack,explain,harden}.py`. **S2:** `redsim/…`. | D7, D10 | aegis paths only (section 8 layout); S3's paths are replaced in section 19 and in the feature plans. |
| 31 | Governance of exceptions | **Const.:** exceptions require written rationale and named approval; Principle II exclusions are not bypassed by a feature plan; ratification "Not yet". **S3 README:** ratify the constitution at Gate 0. | D12 | Principles are not rewritten. An "Amendment proposals (2026-09-08)" section is appended with (a) Principle II vs D3, (b) Principle II "unrestricted execution" vs D2, (c) Principle III vs D9; status "proposed, pending named approval"; ratification not claimed. Sections 19, 26. |
| 32 | Decision register | **S3:** D001–D007 all OPEN with suggested owners by role. | D11 | D001–D005 RESOLVED in the register's own format, approver "product owner (hackathon), 2026-09-08", with divergences from the proposals stated (D001, D003). D006 (retention, export redaction, licence restrictions) and D007 (named owners and reviewers) remain OPEN; no owners or names are invented. Section 19. |
| 33 | Two copies of the brief and "the brief wins" | **S2 header and `docs/brief.md`:** "Where this spec and the brief differ, the brief wins"; `docs/brief.md` adds the original use-case text, additional references (Pythia, garak, TIP, OpenSandbox) and a "Decisions taken" section that recorded S2's choices. **S3:** `docs/project-brief.md` is William's copy with a link to `references/original-use-case.docx`. | D13 | One brief at `docs/project-brief.md` with the additions folded in and a "Decisions taken (2026-09-08)" section reflecting D1–D13; `docs/brief.md` deleted; references fixed in docs/, specs/, .specify/ (references in code and `README.md` are reported, not edited). The brief remains the governance source; where this spec diverges from it (rows 3, 4, 10) the divergence is explicit and bounded rather than silent. |
| 34 | Timeline | **S1:** "ordered for a 2-day hackathon", M0–M7. **Owner:** 1–2 days. **S3:** pick a single story-sized increment, not a multi-domain platform. | D8 | Section 3.4 states that Phase A as decided exceeds a 1–2 day build, keeps M0–M7 and B1+, keeps "freeze Phase A first", and fixes the demo-critical order. Section 23 aligns milestones with Spec Kit slices. |
| 35 | Testing | **S1:** none specified. **S2:** offline pytest suite under 60 s (registry, schema literals, attacks on a random-weight model, noise control, rules, report XSS, API 501 / traversal); vitest for labels. **aegis:** sqlite conftest, `integration` marker; `ml` marker already declared in `pyproject.toml`; `tests/ml/fakes.py:TinyTarget`. | D1 with S2 retained | Section 22: sqlite conftest, `TinyTarget`, `ml` marker; assertions on labels, denominators, refusal paths, audit-before-enqueue, and 501 stubs. |
| 36 | Numbers in the demo script | **S1 §15:** MRI "about 38 (grade F)", "about 71 (grade C)", "ΔMRI of +33". **Brief:** label illustrative results; do not invent measured improvements. | D9(v) | Every number in section 24 is labelled illustrative; real values come only from a completed campaign. |
| 37 | Limitations | **S2:** `limitations` always non-empty; standing sentences include "CIFAR-10 is not a proxy for any operational domain". **S1:** none. **S3:** F003 requires explicit limitations; F005 shows explanation limitations. | Retained; D3 | Limitations always present on the run page and in every report; the dataset sentence is parameterised by the campaign's dataset and its licence; `STANDING_LIMITATIONS` in `aegis/ml/schema.py` changes accordingly (section 14). |
| 38 | Determinism claims | **S1 §8:** the MRI "is deterministic and reproducible from the stored metrics". **S2 / Const. V:** disclose nondeterminism (GradientExplainer sampling, CPU float32 reductions); no bit-for-bit promises. | Both, reconciled | The MRI is a deterministic function of stored metrics; the metrics themselves come from a run whose `Provenance.nondeterminism` lists SHAP sampling, attack random initialisation and float reductions. Comparability claims are limited accordingly (sections 14, 15). |
| 39 | Dataset fetch path | **S2 / `docs/brief.md`:** CIFAR-10 from the HF mirror `uoft-cs/cifar10`, torchvision as fallback. **Scouting (section 11):** HF hub reachable; torchvision's U. Toronto download not reachable. | D3 | CIFAR-10 fixture via the HF hub with torchvision as fallback only; demo datasets and their exact load paths, licences, classes and sizes in section 11; dataset id and revision hash in `Provenance`. |
| 40 | Deployment | **S1:** ECS Fargate + RDS + S3 + ElastiCache; Terraform or Copilot; Keycloak or Cognito. **S2:** docker-compose with two services (api, web). **S3:** Replit. | D1 | aegis compose dev stack (api, worker, web, postgres, redis, MinIO, Keycloak) now; Fargate at M7; `ml` extra only in the worker image. Section 20. |
| 41 | Secrets | **S1 §12:** Secrets Manager holds "LLM keys, worker signing key, Fernet key". **S2:** no provider credential; Pythia key only. | D5 | Secrets are the Pythia `pk_…` key, the worker signing key, the Fernet key and DB credentials; no provider keys exist anywhere. Section 21. |
| 42 | Listing attacks in `/tools` | **S1:** attacks register "so they list in `/tools`". **Repo state:** `/tools` page and `tool.invoke` deleted. | D1 (as restored) | Attacks and explainers register through `aegis/registry.py` with the `adversarial_ml` / `explainability` tags and are listed at `GET /v1/attacks` and in the launcher (sections 12, 17). |
| 43 | Bundled sample count | **S1:** seed 3 sample models and 2 sample datasets on first deploy. **S2:** one CIFAR-10 CNN with `MANIFEST.json`. | D3, D4(d) | Three models in the asset manifest: image CNN (section 11 imagery; also exported to ONNX to exercise the upload loader), tabular classifier (section 11 tabular dataset), CIFAR-10 small CNN (CI fixture). Two demo datasets plus the CIFAR-10 fixture. Clean accuracies are recorded in the asset manifest at build time, never hard-coded. |
| 44 | ORM `Target` vs protocol `Target` | **aegis:** `aegis/db/models.py:Target` row (`kind`, `value`). **S2 / code:** `aegis/ml/targets/base.py:Target` protocol (loaded model + slice). | D7 | Both names are kept; this spec says "model target" for the row and "ML target" for the protocol object (section 1.4); section 5 describes how a `Target` row of kind `ml_model_artifact` is resolved to an ML target on the worker. |
| 45 | Text and detection modalities | **S1:** Phase B. **S3:** adding another modality is a deferred extension. **Brief:** no simultaneous domain support. | D8 | Phase B only, behind item 6 of the demo-critical order. |
| 46 | Data poisoning | **Original use case:** mentions poisoning. **Brief:** excluded. **S1:** not included. | Non-goal | Section 3.3. |
| 47 | Agents and tool-using agents | **Brief:** agent applications are a separate scope. **aegis:** agent runtime deleted. **S3:** deferred extension. | Non-goal | Section 3.3. |
| 48 | Retention, export redaction, licence restrictions | **S3:** D006 OPEN; minimise retained content; block destructive purge until approved. **S1:** WORM Object Lock; redaction on the LLM path. | D11 (stays OPEN) | Phase A uses aegis redaction on LLM inputs and audit exports and adds no retention or purge operation; the row stays open in the register with no invented owner. Sections 19, 21. |
| 49 | Named owners and reviewers | **S3:** D007 OPEN; all feature owners unassigned. | D11 (stays OPEN) | No names invented. Known contributors are recorded only as authors of this spec's sources. Section 19. |
| 50 | Saved-model formats | **S1 §5:** ONNX and TensorFlow SavedModel preferred. **D2:** ONNX preferred, `state_dict` accepted. | D2 | SavedModel is not accepted in Phase A (no TensorFlow in the worker image); users convert to ONNX. Section 9. |
| 51 | New tables | **S1 §4:** "No new core tables are required for Phase A". **D9 / D10:** a campaign needs stored weights, ε grid, reference budget, MRI, subscores and deltas. | D9, D10 | Section 5 specifies the one added column (`targets.detail`) and the one added table (`ml_campaigns`), and which `Target.kind` and `Job.type` values are added; S1's "two enum values and one detail shape" is extended accordingly. |
| 52 | When an uploaded model is first loaded | **S1 §5:** loaders run on the worker; no separate validation step named. **Writers of sections 9/17 (first draft):** validate lazily during the first campaign. **Writers of sections 5/6:** a dedicated `model.validate` job in an `ml.ingest` run, so a target is `available` or `refused` before any campaign is admitted. | D2 (as reconciled here) | The dedicated `model.validate` job is adopted (sections 5, 6.6, 9.3, 10): an upload gets its refusal or acceptance before a user configures a campaign, and every later campaign load re-checks the digest and format (`model.load`). |
| 53 | Job granularity | **Sections 5, 6, 12, 17 (first drafts):** one `attack.run` Job per attack in the declared set. **Section 10 (first draft):** one `attack.run` Job for the whole campaign. | D4(b), D10 (as reconciled here) | One `attack.run` Job per attack, run as a chain; the first attack job also runs the `sample`, `clean_eval` and `control` stages (section 10.3). Cancel, failure and stage semantics follow from the per-job machine (section 6). |
| 54 | Where the rule layer runs | **Section 16 (first draft):** in-line at the end of `attack.run`. **Sections 5, 6, 10:** in the `harden.recommend` job after `explain.run`. | reconciled here | The rule layer runs in `harden.recommend`, because its rules R3/R3t read explanation outputs (section 16.1); the job is pre-created at admission so every completed campaign has candidates without a user action. |
| 55 | Tabular dataset | **S1:** an unspecified bundled "XGBoost/sklearn model" (§14 M4) with no dataset named. **S2:** tabular registered as a `not_implemented` stub; no tabular dataset. **First merge draft of section 11:** intrusion-detection data (`lacg030175/UNSW-NB15`) with UCI Spambase as fallback and fixture. **Brief / Const. II:** open or synthetic public data, non-operational. | Owner decision 2026-09-08 (D4(d) as sourced here) | The Kaggle **malicious-URLs dataset** (`sid321axn/malicious-urls-dataset`, "CC0: Public Domain") is the tabular dataset; the bundled tabular target is a URL maliciousness classifier (sklearn/XGBoost on lexical URL features), trained by the asset script, clean metrics recorded in the asset manifest (section 11.3.3). UNSW-NB15 is demoted to fallback (11.3.4); Spambase stays a CI fixture (11.3.6). URL strings are data and are never fetched, resolved or rendered as links; feature-space perturbations are decision-surface evidence with a stated realizability caveat (section 12.9). The tabular MRI is its own campaign and is never combined with the image campaign's (D9(i)). |
| 56 | Product short name | **D7:** "redsim" retired except as history. **S1 §14 (added 2026-09-08):** uses "redsim" as the product's short name throughout. **S2:** "redsim" was both the package and the product name. **Repo:** the branch is `redsim-implementation`. | D7 as amended by this merge: short name accepted | The short name **redsim** is accepted for the product, and the long form stays "Adversarial ML Red-Team Simulator". The title of this spec reads "Adversarial ML Red-Team Simulator (redsim)". No code identifier is renamed by this row: the Python namespace is `aegis`, the vertical is `aegis/ml/`, environment variables are `AEGIS_*`, the web header brand keeps the long form (section 18), compose services and images stay `aegis-*`, and `REDSIM_LLM_MODEL` still becomes `AEGIS_ML_LLM_MODEL` at M0 (row 2). |
| 57 | Interoperability | **S1 §14 (new; commit `4acdb85`, pushed after the first consolidation pass had read S1):** Croissant / Parquet adversarial-dataset export with a consume side accepting ONNX models and Croissant / Parquet slices, `POST /v1/runs/{id}/dataset` and `GET /v1/datasets/{id}`, S3 location `datasets/<run-id>/` with a content-addressed manifest; MITRE ATLAS technique tag at `Finding.schema_blob.atlas_technique` (FGSM / PGD → `AML.T0043 Craft Adversarial Data`, black-box query → `AML.T0040 ML Model Inference API Access`) shown in the findings table, report and dataset manifest, plus a per-campaign ATLAS coverage view; env-selected Palantir Foundry (primary) and Anduril Lattice (exploratory) pushes, off by default; milestone row "B2 \| Interop". **S2 / S3:** absent. **Brief / Const. II / D3 bounds:** no mission-system connections. | Adopted as Phase B2 per S1's own milestone row; no D1–D13 decision changes, and D3, D5 and D9 bind it | Section 27 restates S1 §14.1 to §14.3 in the consolidated vocabulary (`Run`, `Finding`, `Artifact`, `MRIRecord`): opt-in, off by default, data and REST integrations only (no LLM call, D5 untouched), no standing credentials. The ATLAS tag lives at `schema_blob.ml.atlas_technique` (section 5.7); routes in 17.4; UI in 18; F002 consume side and F007 export in 19; "B2 \| Interop" in 23; security in 21.8; risks in 25. The Lattice push conflicts with the D3 bound "no mission-system connections" and stays text-only until an explicit product-owner decision resolves it (27.3). Nothing in section 27 is implemented. |

### 4.3 Constraints carried forward unchanged

These items did not conflict and are binding throughout the spec:

- Measurements, observations, interpretation and candidate recommendations are separate fields (`aegis/ml/schema.py`) and separate UI panels; the labels `candidate`, `not evaluated`, `inferred`, `heuristic` are `Literal` types (S2; Brief; Const. III).
- Results per test family with denominators (`n`, `n_correct`, per-class counts) and coverage; a zero or unknown denominator yields no percentage (S2; S3 F005 FR-005).
- Provenance for rerun: model sha256, dataset id and revision, split, slice indices and seed, attack and explainer parameters, library versions (`torch`, `art`, `shap`, `numpy`, `aegis_version`), host and device, nondeterminism sources (S2; Const. V; Brief).
- Illustrative results are labelled; fixture data is labelled fixture and never presented as evidence; no fabricated completed runs, improvements or validated fixes (S2; S3 architecture note; Brief; Const. III).
- Unsupported and unimplemented paths fail explicitly (HTTP 501 with a reason, "unavailable" states in the UI) and are never silently bypassed or mocked (S2; Const. IV, VI).
- SHAP attributions are supporting evidence, not causal proof; the center-mass ratio is a heuristic (S2; Brief; Const. III).
- Passing a suite establishes neither safety nor operational readiness; no certification claim (S1 §13 "unclassified, open sample data" note; S2; Brief; Const. III).
- Audit event before enqueue for every mutating call (S1 §10; aegis admission pattern).
- Only the SHAP text summary and metrics reach the LLM writer, with secrets redacted (S1 §13; S2; D5).
- Model files are untrusted input and are never loaded in the API process (S1 §5, §13; Const. IV).
- The readiness checklist (`specs/_shared/readiness-checklist.md`) is the approval gate for each feature package, and specification approval is separate from "done" (S3).
- "Freeze Phase A first"; keep sample models small; CPU only (S1 §3, §16).

### 4.4 Items left open on purpose

- D006 (retention period, export redaction, licence restrictions, audit metadata retention) and D007 (named feature owners and independent reviewers) remain OPEN in `specs/_shared/decisions.md`.
- The constitution is not ratified; the three amendment proposals of D12 await named approval.
- The decision on whether S3's finding review states ship in Phase A is made and stated in section 6 (dismissal ships; confirmation and resolution are Phase B).

## 5. Domain model mapping onto aegis tables

### 5.1 Ground rules

- The ML vertical reuses the aegis tables in `aegis/db/models.py` (`Organization`, `Project`, `User`, `ProjectMembership`, `Target`, `AuthProfile`, `Run`, `Job`, `Finding`, `Artifact`, `LLMUsage`, `AuditEvent`, `AuditChainHead`, `ApplicationLog`). Every row keeps its `project_id`, and the eight RLS-scoped tables keep their trigger-backfilled `org_id` (section 7.6).
- S1 §4 stated "No new core tables are required for Phase A." That statement is **overridden by D2 and D9**: a model target needs a manifest that `Target` has no column for, and an `Artifact` row requires a `run_id`, so an uploaded model that has not been attacked yet cannot be described by an Artifact. Phase A therefore adds exactly one JSONB column (`targets.detail`) and one table (`ml_campaigns`), both in one Alembic migration (`0010_ml_vertical`). Nothing else in the schema changes shape; everything else is a new enum value or a new JSONB payload.
- The aegis idiom for typed JSONB payloads is a `TypedDict` or Pydantic model next to the column (`FixJobDetail`, `VerifyJobDetail`, `AegisFinding` for `findings.schema_blob`). The ML payloads follow that idiom and are validated **at write time on the worker** with the Pydantic models in `aegis/ml/schema.py`; reads stay lenient the way `AegisFinding.from_dict` is.
- The single source of truth for one campaign's evidence is the `RunRecord` (S2, `aegis/ml/schema.py`) written as an immutable, sha256-addressed Artifact (kind `ml.run_record`). Everything that lands in `Finding.schema_blob` or `ml_campaigns.score` is a **projection** of that record, never a second computation. A projection that disagrees with the record is a bug; the testing plan (section 22) asserts equality.

### 5.2 Existing concept to ML meaning (S1 §4, extended)

| Existing concept (code) | ML red-team meaning | Decision |
|---|---|---|
| `Target.kind` (`String(32)`; values today `url`, `github_repo`, `image`) | Add `ml_model_artifact` (bundled sample model or uploaded ONNX / PyTorch `state_dict`) and `ml_model_endpoint` (black-box inference URL). `ml_model_endpoint` rows may be created in Phase A but no job accepts them until Phase B (`501`, section 17). | D2 |
| `Target.value` (`String(1024)`) | Blob-store location of the model file for uploads (`aegis_output/blobs/...` or `s3://bucket/<project>/models/<target>/<sha256>`), the bundled asset id (`bundled:<id>`) for sample models, or the inference URL for endpoints. | D2 |
| `Target.detail` (**new** JSONB, nullable) | `MLModelManifest` (section 5.5): display name, modality, format, sha256, class names, input shape, validation status and refusal reason, dataset binding, clean accuracy "recorded in the asset manifest at build time". `NULL` for non-ML kinds. | D2, D3 |
| `Target.verified`, `allowlist_until`, `installation_id` | Untouched. Ownership verification returns `501` in this build (`aegis/api/v1/targets.py`) and is not needed for model artifacts; sandbox validation status lives in `detail.status`, not in `verified`. | D2 |
| `Run` | One **campaign**: one model × one modality × a declared attack set × a declared eps grid × a reference budget (D9 i). `Run.scanner` (`String(64)`) discriminates the ML run kinds: `ml.campaign` (attack), `ml.verify` (verify-after-harden re-attack), `ml.ingest` (upload validation). `Run.mode` = `api` as for scans. `Run.target_id` is set (it is nullable today; ML runs always fill it). | D1, D9 |
| `Run.stage_table` (JSONB) | Campaign progress in the `STAGES` vocabulary of `aegis/ml/schema.py` (`load_target, sample, clean_eval, attack, control, explain, score, interpret, recommend, report`; `score` is added by this spec), plus per-job status (section 6.5). Not the place for scores. | S2 |
| `ml_campaigns` (**new** table, 1:1 with `runs`) | The campaign/score record: `CampaignConfig`, `Provenance`, `MRIRecord` (score, five subscores, inputs table with denominators, eps grid, reference budget, weights, completeness), limitations, `baseline_run_id` for verify campaigns, `parent_run_id` for reruns, `settings_hash` for compatibility (section 5.6). | D9 |
| `Job.type` (`String(64)`) | Add `model.validate`, `attack.run`, `explain.run`, `harden.recommend`; reuse `verify.replay` and `report.render`. | D4 |
| `Job.detail` (JSONB) | One `TypedDict` per type (section 5.9). Never carries secrets, model bytes, images, or prompt text. | S1 §13 |
| `Finding` | One adversarial vulnerability: **one attack whose success rate crosses the configured threshold at any eps in the grid** (section 12). One row per attack per campaign. | S1 §6 |
| `Finding.schema_blob` (`AegisFinding` dict) | Carries the measured summary fields in the existing `AegisFinding` fields (title, severity, description, evidence, references) and the full ML detail in a new optional `ml` field (`MLFindingDetail`, section 5.7): the attack's eps-sweep measurements with `n`, the control rows at the same eps, observation ids and artifact ids, the interpretation rows that rest on them, and the candidate recommendations they trigger. Phase B2 adds the MITRE ATLAS technique tag inside the same block (`ml.atlas_technique`, section 27.2). | S2; S1 §14 (B2) |
| `Finding.severity` | Derived from eps at first success and ASR per S1 §8.5 (section 15). Written to the existing column so filters and the findings table work unchanged. | D9 |
| `Finding.status` | aegis vocabulary `open / fixing / fixed / failed / false_positive` (canonical, section 6.4). | D10 |
| `Finding.validation_state` | aegis vocabulary `unvalidated / poc_passed / poc_failed / inconclusive` (canonical; written by `verify.replay`, section 6.4). S1 §4's "`verified` / `still_vulnerable`" are the worker's `VerifyStatus` values that map onto these through the existing `_STATE_MAP`. | D10 |
| `Finding.dedup_key` | `ml:<model_sha256[:16]>:<attack_id>:<settings_hash[:16]>` so the same vulnerability on the same model at the same settings links across the baseline campaign and its verify campaign, while a different grid or dataset does not. | D9 iv |
| `Artifact` | Adversarial examples, SHAP overlays and raw values, perturbation maps, robustness curves, the `RunRecord`, and rendered reports; one row per file, sha256-addressed, `(run_id, kind, sha256)` unique (section 5.8). | S1 §7 |
| `AuthProfile` (`kind` in `form / bearer / header / cookie`, Fernet-encrypted secret) | Reused unchanged for `ml_model_endpoint` credentials in Phase B (`bearer` or `header`). Phase A uses no AuthProfile. | D2 |
| `LLMUsage` | One row per Pythia call made by `harden.recommend` (`task = "ml.harden_narrative"`, `model` = the canonical `<vendor>/<model>` id sent to Pythia). This is the budget layer D5 keeps. | D5 |
| `AuditEvent` chain | Upload, validation, each attack, each explanation, each recommendation, each verify, each review decision and each score are chained events (section 5.11). | D4 c |
| Scanner registry vocabulary (`aegis/scanners/registry.py`) | New capability tags `adversarial_ml`, `explainability`. Attack adapters register there so they list the way scanner adapters did. | S1 §4 |

### 5.3 Schema changes in migration `0010_ml_vertical` and in `aegis/ml/schema.py`

| Change | DDL / code | Why |
|---|---|---|
| `targets.detail` | `ADD COLUMN detail JSONB NULL` | Model manifest (5.5). |
| `ml_campaigns` | New table, columns in 5.6. `run_id` is PK and FK to `runs.id`; `project_id` NOT NULL FK; `org_id` nullable FK with the `aegis_set_org_id_ml_campaigns` BEFORE INSERT trigger, the `aegis_check_org_id_ml_campaigns` BEFORE UPDATE guard, `ENABLE` + `FORCE ROW LEVEL SECURITY`, and the `aegis_tenant_isolation` policy copied verbatim from `0006_tenant_rls.py` / `0009_tenant_org_id_guard.py`. | Campaign/score record; tenant isolation parity with the other eight scoped tables. |
| `Target.kind` values | No DDL (column is `String(32)`); the API validates `kind in {"url","github_repo","image","ml_model_artifact","ml_model_endpoint"}`. | Two enum values (S1 §4). |
| `Job.type` values | No DDL (`String(64)`). | Four new job types. |
| `Run.scanner` values | No DDL (`String(64)`). | `ml.campaign`, `ml.verify`, `ml.ingest`. |
| `AegisFinding.finding_type` | Add `"adversarial_ml"` to the `FindingType` Literal in `aegis/schema.py`. | New writes are validated at construction; an out-of-vocabulary type fails at the source. |
| `AegisFinding.ml` | Add `ml: dict[str, Any] | None = None` to `AegisFinding`. The dict is the `model_dump()` of `MLFindingDetail` (defined in `aegis/ml/schema.py`, validated by the worker before `to_dict()`). Keeping the field a plain dict in `aegis/schema.py` avoids an import from `aegis.ml` in the core schema and keeps `extra="ignore"` semantics: without this field the ML detail would be **silently dropped** by `AegisFinding.model_validate`. | Field placement (5.7). |
| `aegis/ml/schema.py` additions | New models `CampaignConfig`, `ScoringConfig`, `DefenseConfig`, `MRIInputRow`, `MRIRecord`, `MRIDelta`, `MeasuredDelta`, `MLFindingDetail`, `MLModelManifest`. `RunConfig` is generalised into `CampaignConfig` (5.6: `attack_ids`, `attack_params`, `norm`, `eps_grid`, `reference_eps`, `finding_asr_threshold`, `scoring`, `defense`, dataset binding, plus the existing `n_samples`, `seed`, `include_control`, `explain_k`, `llm_narrative`); `RunRecord.config` becomes `CampaignConfig` and `RunRecord.attack` becomes `attacks: list[AttackInfo]`. `Provenance` gains `dataset_revision`, `sample_indices_sha256`, `settings_hash`, `baseline_run_id`, `parent_run_id`, `defense`, `llm`, `thread_env`, `onnxruntime`, `sklearn`, `xgboost` (sections 11, 14.4). `Measurement` gains the scoring inputs of sections 12.5 and 15.1 (`n_clean_correct`, `attack_success_rate`, `pert_first_success_mean`, `pert_first_success_n`, `conf_gap_mean`, `conf_gap_n`, `expl_shift_mean`, `expl_shift_n`, `queries_mean`). `Observation` gains `expl_shift`, `top_features_clean`, `top_features_adv` (section 13.3); `Observation.artifacts` values become `Artifact.id`s (not run-relative paths). `CandidateRecommendation.validation` becomes `Literal["not evaluated", "measured"]` with a paired `measured: MeasuredDelta | None` (section 16.4). `RunRecord` gains a model validator rejecting dangling citations (section 14.1). `STAGES` gains `score` after `explain`. `RunStatus` and `Domain` are unchanged. | Sections 5.4 to 5.7, 12, 13, 14, 15, 16. |
| `STANDING_LIMITATIONS` | The first entry is parameterised by dataset id (section 14.5): "`<dataset_id>` is an open, unclassified public benchmark; it is not a proxy for any operational domain, sensor, or deployment condition." because D3 replaces CIFAR-10 as the demo dataset. | D3 |

No column is renamed and no existing row changes meaning, so the migration is additive and reversible (`downgrade` drops the column and the table).

### 5.4 Where every `RunRecord` field lives

`RunRecord` (S2 §3, `aegis/ml/schema.py`) is generalised from one attack per run to one campaign per run: `config` becomes `CampaignConfig`, `attack` becomes the list of attacks in the declared set, and measurements carry one row per (family, attack, eps). The record itself is always written whole as the `ml.run_record` Artifact. The table says where each field is **also** projected so the API and UI can query it without parsing the record.

| `RunRecord` field | Canonical store | Queryable projection | Notes |
|---|---|---|---|
| `run_id` | `runs.id` | — | Campaign id = run id. |
| `status` | derived from `jobs.status` (section 6.2) | `runs.status` | `not_implemented` is never persisted; a stub target is refused at admission with `501` before any row exists. |
| `stage`, `stages_done` | `runs.stage_table["stage"]`, `["stages_done"]` | same | Written by the worker as each stage completes. |
| `error` | `jobs.error` (per job) | `runs.stage_table["error"]` (first failing job's class and message, no traceback) | `jobs.error` keeps the traceback. |
| `created_at` | `runs.created_at` | — | |
| `config` (`CampaignConfig`) | `ml_campaigns.config` | `jobs.detail` carries the per-attack subset (`AttackJobDetail`) | Immutable after admission (William: immutable input snapshot). |
| `target` (`TargetInfo`) | `targets` row (`kind`, `value`, `detail`) plus a frozen copy in `ml_campaigns.config["target_snapshot"]` | — | The snapshot protects the campaign from later manifest edits. |
| `attacks` (`AttackInfo`, one per attack in the set) | `ml_campaigns.config["attacks"]` (snapshots from the registry) | `jobs.detail["attack"]` | |
| `provenance` (`Provenance`) | `ml_campaigns.provenance` | — | Includes `nondeterminism`, `dataset_revision`, `sample_indices_sha256`, `settings_hash` (sections 11, 14.4). |
| `measurements[]` | run record Artifact | `ml_campaigns.score["inputs"]` (MRI input rows with `n`), `findings.schema_blob.ml.measurements` (the rows belonging to that finding's attack: its eps sweep, the clean row, and the control rows at the same eps) | Every projected row keeps `n`, `n_correct`, `accuracy`, `per_class`. |
| `observations[]` | run record Artifact; each referenced file is an `artifacts` row | `findings.schema_blob.ml.observations` (ids, labels, flipped flag, confidences, `center_mass_ratio_*` with `metric_kind="heuristic"`, `expl_shift`, `artifacts` name to `Artifact.id`, `artifact_sha256`) | |
| `interpretation[]` | run record Artifact | `findings.schema_blob.ml.interpretation` (rows whose `basis` cites a measurement or observation of this finding) | `kind="inferred"` enforced by the Literal. |
| `recommendations[]` | run record Artifact | `findings.schema_blob.ml.recommendations` (rows whose `triggered_by` cites this finding); `schema_blob.remediation_steps` carries a plain-text rendering prefixed `CANDIDATE (not evaluated):` so existing report/UI surfaces never show unlabelled advice | `status="candidate"` enforced by the Literal; `validation` is `"not evaluated"` until a verify run attaches a `MeasuredDelta` (section 16.4). |
| `limitations[]` | `ml_campaigns.limitations` | `findings.schema_blob.ml.limitations` (copy) | Non-empty for every succeeded run (validator in `RunRecord`). |
| `reviewer_notes` | `ml_campaigns.reviewer_notes` (campaign level); `findings.schema_blob.ml.review.notes` (finding level) | — | Written only through `finding.annotate` / `finding.review` (section 7.4). |

### 5.5 `MLModelManifest` (`targets.detail` for `ml_model_*` kinds)

| Field | Type | Source |
|---|---|---|
| `name` | `str` | user-supplied or bundled asset name |
| `modality` | `Literal["image","tabular"]` | declared at registration; Phase B adds `"llm"` connections (D6) |
| `format` | `Literal["onnx","torch_state_dict","safetensors_state_dict","sklearn_joblib","xgboost_json","endpoint"]` | detected worker-side from file signature and cross-checked against the declaration (section 9) |
| `sha256`, `size_bytes` | `str`, `int` | computed at upload by the API on the stream (no deserialisation) and re-verified on the worker |
| `architecture_id` | `str | None` | required for `torch_state_dict` / `safetensors_state_dict`: the id of a bundled architecture definition (`aegis/ml/targets/architectures.py`); free-form code is never accepted |
| `input_shape`, `n_classes`, `class_names` | `list[int]`, `int`, `list[str]` | from the ONNX graph / manifest; for tabular, feature names and dtypes in `features` |
| `features` | `list[{"name","dtype","min","max","perturbable"}] | None` | tabular only; for the bundled URL maliciousness classifier these are the lexical URL features of section 11.3.3 with their training-split ranges; `perturbable` marks the declared continuous features attacks may touch (section 12.9) |
| `surrogate` | `{"kind", "sha256", "agreement_clean": {"value", "n"}} | None` | tabular tree ensembles only: the build-time differentiable surrogate used for PGD by transfer (section 12.2) |
| `dataset_id`, `dataset_revision`, `dataset_split` | `str` | the evaluation dataset the model is bound to (section 11) |
| `clean_accuracy` | `{"value": float, "n": int, "split": str} | None` | recorded in the asset manifest at build time for bundled models; `None` for uploads until a campaign measures it |
| `status` | `Literal["registered","validating","available","refused"]` | section 6.6 |
| `refusal_reason` | `Literal["pickle_refused","unsupported_format","architecture_missing","load_failed","shape_mismatch","size_limit","timeout"] | None` | set by `model.validate` |
| `gradients` | `bool | None` | set by `model.validate`: whether a differentiable estimator is available (native torch, converted ONNX, or declared surrogate); decides which attacks the launcher offers (sections 9.2, 12.1) |
| `bundled` | `bool` | `True` for seeded sample models |
| `license`, `source_url` | `str` | for bundled models and datasets (D3 open/unclassified rule, section 11) |
| `manifest_sha256` | `str` | sha256 of the canonical manifest JSON, copied into `Provenance.model_manifest` |

Phase A bundled targets carried by this manifest (seeded by `aegis ml build-assets`, sections 11 and 20): the image CNN on the vehicle-imagery dataset (11.3.1), also exported to ONNX; the **URL maliciousness classifier (sklearn/XGBoost on lexical URL features), trained by the asset script; clean metrics recorded in the asset manifest** (dataset 11.3.3; features and perturbability in 12.9); and the CIFAR-10 small CNN, which is the CI fixture and is never registered in the demo catalog.

### 5.6 Campaign/score record (`ml_campaigns`)

| Column | Type | Content |
|---|---|---|
| `run_id` | `String(64)` PK, FK `runs.id` | |
| `project_id`, `org_id` | FK | RLS scope (7.6) |
| `target_id` | FK `targets.id` NOT NULL | the model |
| `kind` | `String(16)` | `attack`, `verify` or `ingest` |
| `modality` | `String(16)` | `image` or `tabular` |
| `baseline_run_id` | `String(64)` FK `runs.id`, nullable | verify campaigns only: the campaign being re-attacked; ΔMRI is computed against it |
| `parent_run_id` | `String(64)` FK `runs.id`, nullable | reruns only: the campaign the "Rerun with same config" button started from (lineage; section 10.6) |
| `settings_hash` | `String(64)` indexed | sha256 over the canonical JSON of `config` **excluding** `defense`, `llm_narrative` and `target_snapshot`, concatenated with the model `sha256`. Because `config` carries the dataset id and revision, `n_samples`, `seed`, attack set and params, `norm`, `eps_grid`, `reference_eps`, `finding_asr_threshold` and `scoring`, two campaigns are comparable iff their `settings_hash` is equal (D9 i). `Provenance.sample_indices_sha256` must also match; it is a redundant check that the same rows were evaluated. |
| `config` | JSONB NOT NULL | `CampaignConfig`: `target_id`, `modality`, `attack_ids`, `attack_params` (per attack), `norm` (`linf`/`l2`), `eps_grid` (sorted ascending, e.g. `[0.01, 0.03, 0.1]`), `reference_eps` (must be a member of `eps_grid`), `finding_asr_threshold` (default 0.2), `n_samples` (10 to 1000, default 200), `seed`, `include_control`, `explain_k`, `dataset_id`, `dataset_revision`, `dataset_split`, `scoring` (`ScoringConfig`: weights `S_acc 0.35 / S_asr 0.25 / S_eps 0.20 / S_conf 0.10 / S_expl 0.10`, severity and confidence thresholds, interpretation thresholds, `version`; section 15.3), `defense` (`DefenseConfig | None`: ART defense name and params; verify only), `llm_narrative` (bool), `auto_recommend` (bool), `target_snapshot`, `attacks` |
| `provenance` | JSONB nullable | `Provenance` |
| `score` | JSONB nullable | `MRIRecord`: `scoring_version`, `weights`, `eps_grid`, `reference_eps`, `norm`, `attack_ids`, `finding_asr_threshold`, `settings_hash`, `inputs: list[MRIInputRow]` (per attack x eps: `acc_clean`, `acc_adv`, `asr`, `pert`, `conf_gap`, `expl_shift`, `queries`, with `n`, `n_correct_clean`, `n_attacked`, `n_explained`), `per_attack` (each subscore per attack with its denominator), `subscores` (`S_acc`, `S_asr`, `S_eps`, `S_conf`, `S_expl`, each `float | None`), `mri: int | None`, `grade: Literal["A","B","C","D","F"] | None`, `completeness: Literal["complete","partial"]`, `missing: list[str]` (the unavailable dimensions and their reasons; empty when complete), `reading` (attack-scoped text, D9 iii), `delta: MRIDelta | None` (`baseline_run_id`, `mri_before`, `mri_after`, `delta`, per-dimension deltas, `delta_acc_clean` with both fractions; verify only), `computed_at` |
| `limitations` | JSONB NOT NULL default `[]` | `STANDING_LIMITATIONS` plus run-specific entries |
| `reviewer_notes` | `Text` nullable | free text, `finding.annotate` tier |
| `created_at`, `completed_at` | timestamps | |

Rules that follow from D9 and are enforced by the record shape:

- `score` is `NULL` until the campaign's explain stage has finished, because `S_expl` needs SHAP; if any subscore cannot be computed (SHAP timeout, control missing, `n` below the configured minimum, an attack with no rows), `mri` and `grade` stay `NULL`, `completeness = "partial"` and `missing` names the subscore and reason. Nothing is imputed and weights are never renormalised (section 15.4).
- `score.weights` and `scoring_version` are frozen into the record at scoring time. S1 §8.3's "overridable per project" is implemented as the deployment default in `AegisConfig` (`ml.scoring`) copied into `config.scoring` at admission; a per-project override UI is Phase B.
- The API never returns `score.mri` without `score.subscores`, `score.inputs` and the eps curve artifact id (D9 ii); the serializer in section 17 emits them as one object.
- `delta` exists only on `kind = "verify"` rows and is the **only** place a numeric gain is ever stored (D9 iv). `CandidateRecommendation` has no gain field; its `measured` block (section 16.4) is a copy of `delta` for the recommendation whose defense the verify run applied.

### 5.7 ML findings

Field use inside the existing `AegisFinding`:

| `AegisFinding` field | ML value |
|---|---|
| `id` (= `findings.scanner_finding_id`) | `ml.<attack_id>` (unique per run by the `(run_id, scanner_finding_id)` constraint) |
| `title` | `"<attack name> flips predictions at ε=<first-success ε> (<norm>; ASR <n_flipped>/<n_correct_clean>)"` (section 15.5) |
| `severity` | S1 §8.5 rule (section 15.5): critical / high / medium / low |
| `finding_type` | `adversarial_ml` |
| `description` | rules-generated measured summary (no LLM), citing measurement ids |
| `source_tool` | `aegis.ml/<attack_id>` (e.g. `aegis.ml/fgsm`, `aegis.ml/pgd`, `aegis.ml/hopskipjump`) so the findings list filter works per attack and the worker's `aegis.ml/` prefix check (section 9.4) holds |
| `source_run_id` | `run_id` |
| `affected_component` | `targets.id` of the model |
| `target` | `targets.value` (bundled id or blob location; never a host for artifacts) |
| `confidence` | slice-size rule from section 15.5, labelled as such in the UI: `high` when `m.clean.n_correct ≥ 100`, `medium` when `≥ 30`, else `low` (the thresholds are `scoring.confidence.n_high` / `n_medium`) |
| `status` | `open` at creation (section 6.4) |
| `evidence` | JSON string listing the measurement and observation ids the finding rests on |
| `references` | attack references from `AttackInfo.references` |
| `artifact_path` | `Artifact.id` of the `ml.run_record` artifact |
| `remediation_steps` | `"CANDIDATE (not evaluated): ..."` rendering of the rules-layer candidates |
| `ml` | `MLFindingDetail` (below) |
| `cvss`, `cve`, `cwe`, `endpoint`, `method`, `code_locations`, `poc_*`, dependency and Strix fields | `None` |

`MLFindingDetail`:

| Field | Type |
|---|---|
| `attack_id`, `attack_name`, `family` (`evasion`) | `str` |
| `norm`, `eps_grid`, `reference_eps` | from the campaign |
| `first_success_eps`, `asr_at_reference`, `asr_by_eps` (`dict[str, float]`), `threshold` | measured |
| `measurements` | `list[Measurement]` (clean row, this attack's rows per eps, control rows per eps) |
| `observations` | `list[Observation]` |
| `interpretation` | `list[Interpretation]` |
| `recommendations` | `list[CandidateRecommendation]` |
| `limitations` | `list[str]` |
| `artifacts` | `dict[str, str]` name to `Artifact.id` (robustness curve, SHAP pairs, adversarial pairs) |
| `review` | `{"state": "unreviewed" | "dismissed", "reviewer": str | None, "reason": str | None, "at": datetime | None, "notes": str | None}` (Phase A vocabulary; section 6.4) |
| `verify` | `{"run_id": str, "defense": DefenseConfig, "outcome": "verified" | "still_vulnerable" | "inconclusive", "delta": MRIDelta | None} | None` (written by `verify.replay`) |
| `atlas_technique` | `{"id": str, "name": str, "atlas_version": str} \| None`. **Phase B2** (section 27.2): the MITRE ATLAS technique the finding demonstrates, stamped from the attack registry when the finding is created: `AML.T0043 Craft Adversarial Data` for the gradient evasion attacks (`fgsm`, `pgd`), `AML.T0040 ML Model Inference API Access` for black-box query attacks (`hopskipjump`). S1 §14.2's path `Finding.schema_blob.atlas_technique` resolves to this field, because the consolidated spec keeps all ML detail inside the `ml` block. `None` on every finding written before B2 lands; never back-filled by guesswork. Shown in the findings table, the report and the adversarial-dataset manifest. |

### 5.8 Artifact kinds

`Artifact.kind` is `String(64)`; uniqueness is `(run_id, kind, sha256)`, so many files share a kind. Locations come from `PostgresRunState.record_artifact` (`<project_id>/<run_id>/<kind>/<sha256>` in the blob store). Content types are set so section 17's streaming route can apply the strict CSP. This is the canonical vocabulary; sections 12 and 13 describe what each file contains.

| `kind` | Content | Content type | Written by |
|---|---|---|---|
| `ml.run_record` | `RunRecord.model_dump_json()` | `application/json` | every ML task, whole, on completion or failure |
| `ml.validation_report` | `model.validate` outcome (format detection, shapes, gradients, refusal reason) | `application/json` | `model.validate` |
| `ml.adv_slice` | full `x_adv` for one (attack, eps), float32 `.npz`, when under `AEGIS_ML_MAX_ADV_ARTIFACT_MB` (section 12.8) | `application/octet-stream` | `attack.run` |
| `ml.flip_matrix` | per-sample flipped/not-flipped per eps for one attack, with clean-correct flags (section 15.1 `pert`) | `application/json` | `attack.run` |
| `ml.curve` | robust accuracy and ASR vs eps, with control, with `n` per point (`robustness_curve.json`) and its rendering (`robustness_curve.png`) | `application/json`, `image/png` | `attack.run` |
| `ml.input.clean`, `ml.input.adv` | clean and adversarial input for one observation (image) | `image/png` | `explain.run` |
| `ml.perturbation` | scaled `|x_adv − x_clean|` map for one observation (image) | `image/png` | `explain.run` |
| `ml.feature_diff` | per-feature clean / adversarial values, Δ raw and scaled, frozen flags for one observation (tabular) | `application/json` | `explain.run` |
| `ml.shap.image` | SHAP overlays: `shap_clean.png`, `shap_adv.png`, `shap_adv_predclass.png` (image) | `image/png` | `explain.run` |
| `ml.shap.values` | raw SHAP arrays for the explained samples (`.npz`) | `application/octet-stream` | `explain.run` |
| `ml.shap.meta` | explainer name/version, class explained, background size, `nsamples`, seed, heuristic ratios, `expl_shift`, wall time | `application/json` | `explain.run` |
| `ml.shap.force`, `ml.shap.bar`, `ml.shap.beeswarm` | per-sample force plots; campaign-level bar and beeswarm, clean and adversarial (tabular) | `image/png` | `explain.run` |
| `ml.shap.summary` | campaign-level explanation aggregates with denominators, per attack | `application/json` | `explain.run` |
| `ml.shap.summary_text` | the SHAP **text** summary, the only explanation-derived content the LLM writer receives (section 13.7) | `text/plain` | `explain.run` |
| `ml.score` | copy of `MRIRecord` at scoring time (the DB column is the queryable copy) | `application/json` | `explain.run` (score stage), `verify.replay` |
| `ml.harden.prompt`, `ml.harden.completion` | the exact text sent to and received from Pythia (redacted); digests go on the audit row | `text/plain` | `harden.recommend` |
| `ml.harden.narrative` | the narrative as displayed, prefixed with the `narrative_source="llm"` label and the model id | `text/markdown` | `harden.recommend` |
| `report.md`, `report.json`, `report.html` | rendered reports (`report.render`) | as named | `harden.recommend` / `report.render` |

### 5.9 `Job.detail` shapes

| `Job.type` | TypedDict | Required keys | `NotRequired` keys |
|---|---|---|---|
| `model.validate` | `ModelValidateJobDetail` | `target_id`, `blob_location`, `declared_format`, `declared_sha256` | `architecture_id` |
| `attack.run` | `AttackJobDetail` | `target_id`, `attack_id`, `attack_params`, `norm`, `eps_grid`, `reference_eps`, `finding_asr_threshold`, `n_samples`, `seed`, `include_control`, `explain_k`, `dataset_id`, `dataset_revision`, `dataset_split`, `chain_position` (index in the attack chain; the first job runs `sample`, `clean_eval`, `control`) | `defense` (present only inside a verify campaign) |
| `explain.run` | `ExplainJobDetail` | `finding_id` (or `null` for the campaign-wide pass), `observation_ids`, `explainer`, `k` | |
| `harden.recommend` | `HardenJobDetail` | `finding_id` (or `null` for the campaign-wide pass), `llm_narrative` | `model` (the canonical Pythia model id from `AEGIS_ML_LLM_MODEL`, recorded for provenance; never a key) |
| `verify.replay` | `VerifyJobDetail` (existing: `finding_id`; `repo_path` stays `NotRequired` and unused for ML) | `finding_id` | `defense`, `defense_params`, `baseline_run_id` |
| `report.render` | existing | | |

No detail carries model bytes, images, SHAP arrays, prompt text, or secrets; those are Artifacts or are never persisted.

### 5.10 `AuthProfile`

Unchanged. `VALID_KINDS` remain `form / bearer / header / cookie`; `config` holds only non-secret fields; `secret_ciphertext` is decrypted only by `services.auth_profiles.resolve_auth_for_scan` on the worker. In Phase B an `ml_model_endpoint` Target references an AuthProfile id in `AttackJobDetail["auth_profile_id"]` exactly as scans did; the secret is never written back to `Job.detail`, logs, or audit events. Phase A has no consumer.

### 5.11 `AuditEvent` actions

The chain shape is unchanged (`chain_id`, `seq`, `actor`, `action`, `target`, `allowlist_check`, `override`, `success`, `detail`, `prev_hash`, `this_hash`). Chain ids follow `aegis/audit/chain.py::_chain_id`: `run:<run_id>` when a run exists, else `project:<project_id>`, else `system`. Every ML event goes through `aegis.safety.authorize`, which is the only emitter. For `ml_model_artifact` targets the `target` argument is `None`, so `allowlist_check = "n/a"`; the target id goes in `detail`. For `ml_model_endpoint` targets (Phase B) the inference URL is the `target`, so the host allowlist applies exactly as it does for scans. `detail` is passed through `aegis.audit.redact.redact_audit_detail`. Action names are ≤ 64 characters (`AuditEvent.action` is `String(64)`). This table is the canonical list; section 10.5 states the order in which the tasks emit them.

| `action` | Emitted by | Chain | `detail` (non-secret) |
|---|---|---|---|
| `model.register` | API admission (`POST /v1/models`, bundled pick or upload; also `success=False` for a refused upload) | project | `target_id`, `kind`, `source` (`bundled` / `upload`), `declared_format`, `sha256`, `size_bytes`, `architecture_id`, `modality`, `filename`, `reason` on refusal |
| `model.validate` | worker (`model.validate` job) | run (`ml.ingest`) | `target_id`, `detected_format`, `status`, `gradients`, `onnx_torch_argmax_agreement`, library versions, `refusal_reason`; `success=False` on refusal |
| `attack.run` | API admission (`POST /v1/models/{id}/attacks`) | project, then the Run is created | `target_id`, `attack_ids`, `norm`, `eps_grid`, `reference_eps`, `finding_asr_threshold`, `n_samples`, `seed`, `dataset_id`, `dataset_revision`, `settings_hash`, `scoring_weights` |
| `model.load` | worker, from the child's load outcome at the start of every campaign or verify job | run | `format`, `sha256`, `gradients`, `onnx_torch_argmax_agreement`, library versions; `success=False` with `reason` on digest mismatch or load refusal |
| `attack.execute.<attack_id>` | worker re-check before each attack (mirrors `scan.execute.<scanner>`) | run | `job_id`, `attack_id`, `eps_grid`, resolved params, `not_run` reason when applicable |
| `explain.run` | API admission (`POST /v1/findings/{id}/explain`) or the campaign chain | run | `finding_id`, `explainer`, `k` |
| `explain.execute` | worker | run | `job_id`, `n_observations`, `background_size`, `explain_k`, artifact digests, `wall_time_s` |
| `campaign.score` | worker, when `MRIRecord` is written | run | `mri`, `grade`, `completeness`, `missing`, `settings_hash`, `scoring_version`, score record sha256 |
| `harden.recommend` | API admission (`POST /v1/findings/{id}/harden`) or the campaign chain | run | `finding_id`, `llm_narrative` |
| `harden.execute` | worker | run | `job_id`, `rules_fired`, `n_candidates`, `llm_used`, `narrative_source`, `PythiaSettings.redacted()` (gateway, base URL, model, persona — never the key), `prompt_sha256`, `completion_sha256`, `prompt_tokens`, `completion_tokens`, `cost_cents` or `unpriced_model`, `skipped_reason`; never prompt or completion text |
| `verify.replay` (existing) | API admission (`POST /v1/findings/{id}/verify`) | project, then the verify Run | `finding_id`, `defense`, `defense_params`, `baseline_run_id` |
| `verify.execute` | worker | run (`ml.verify`) | `job_id`, `defense`, `outcome`, `validation_state`, `delta_mri`, per-dimension deltas |
| `job.complete` | worker, at the end of every ML task | run | `job_type`, `status`, counts (findings, artifacts, measurements), envelope sha256; `success=False` on failure with the error class |
| `finding.review` | API (`PATCH /v1/findings/{id}/status`) | run | `from_status`, `to_status`, `reason`, `reviewer`, `campaign_creator` |
| `finding.annotate` | API (notes: `PATCH /v1/runs/{id}/reviewer-notes`, finding notes) | run | `finding_id` or `run_id`, `author`, `length`, text sha256 |
| `report.render` | worker | run | `formats` |
| `run.cancel` (existing) | API admission | run | unchanged |
| `target.manage` (existing) | API (`DELETE /v1/models/{id}`, endpoint registration) | project | `op`, `kind`, `target_id` |
| `audit.worm_export`, `tenant.integrity_check` (existing) | beat tasks | system | unchanged |

`aegis audit verify` and `GET /v1/audit/verify` prove the trail of a whole campaign because every event above shares the campaign's `run:<run_id>` chain (the admission events sit on the project chain and carry the resulting `run_id` in `detail`).

### 5.12 `LLMUsage`

`harden.recommend` writes one `LLMUsage` row per Pythia call: `project_id`, `run_id`, `model` (canonical id), `task = "ml.harden_narrative"`, token counts from the completion response, `cost_cents` from the router's price table. The existing per-project daily cap (`Project.daily_llm_budget_cents`) and per-org monthly cap (`Organization.monthly_llm_budget_cents`) apply before the call is made; an exhausted budget yields a rules-only report with `narrative_source="rules"`, never an error hidden as content.

## 6. State contracts

### 6.1 Job lifecycle (canonical, from `aegis/workers/job_state.py`)

The `jobs.status` machine is the authoritative execution lifecycle. Every write goes through `set_job_status`; an illegal edge raises `IllegalJobTransition`.

```
queued    -> running | cancelled
running   -> succeeded | failed | cancelled | queued
succeeded | failed | cancelled  -> (terminal)
```

- `running -> queued` is the **transient-retry requeue** (`task_context` in `aegis/workers/bootstrap.py`): on `ConnectionError`, `TimeoutError`, SQLAlchemy `OperationalError` / `InterfaceError` with retries remaining, the body is rolled back, the row reset to `queued`, and `task.retry` re-raised. ML tasks are declared `bind=True, max_retries=2` like `scan_start` and `verify_replay`.
- `task_context` runs a job only if it is `queued`; any other status yields `skip=True` and the task body returns without work. This is the cancellation and at-least-once redelivery guard, and it is why a cancelled attack can never re-fire.
- Terminal failure: the body session is rolled back, then `failed`, `completed_at`, and `error` (`"<ExceptionType>: <message>\n<traceback>"`) are committed on the same session. Consequence for the ML tasks: **anything written to `Job.detail` or `Run.stage_table` inside a failing body is lost**; partial evidence that must survive a failure is written as Artifacts and committed before the failing step (section 10).
- The beat reaper (`aegis.reap_stale_jobs`) flips `running` jobs older than `AegisConfig.job_max_runtime_seconds` (default 3600) to `failed` with `error = "reaped: exceeded max runtime TTL"`.
- Lifecycle events are published to the run's WebSocket channel on `running`, `failed`, `succeeded` (`aegis/workers/events.py`); the UI uses them for progress, never as the source of truth.

### 6.2 Run status

`runs.status` is `String(32)`, default `running`. Restored code writes only `queued` (`create_scan_job`), `running` (`PostgresRunState`), and `cancelled` (`cancel_run`); no restored path writes a terminal success or failure. The ML vertical defines and writes the full vocabulary, which is the `Job` vocabulary so the two never need translating:

| `runs.status` | Rule (evaluated by the worker at each job's terminal transition, inside the same transaction) |
|---|---|
| `queued` | all campaign jobs `queued` |
| `running` | any campaign job `running`, or a mix of `queued` and terminal |
| `succeeded` | all campaign jobs terminal, at least one `succeeded`, none `failed` |
| `failed` | all campaign jobs terminal and at least one `failed` |
| `cancelled` | set by `services.runs.cancel_run` |

"Campaign jobs" are the jobs created at admission: one `attack.run` job per attack in the set, the campaign-wide `explain.run`, and the rules-layer `harden.recommend` (section 10.3). `completed_at` is set when the status becomes terminal. **Follow-on jobs** requested later on the same run (`explain.run` for more observations, `harden.recommend` with `llm_narrative=true`, `report.render`) attach to the run for `run_id` and RLS purposes but do not reopen `runs.status`; their state is shown from `runs.stage_table["jobs"]`. This keeps William's invariant that a terminal run never becomes running again.

### 6.3 William's run states mapped (F004, `specs/_shared/architecture.md`)

| William state | aegis canonical | How it is realised |
|---|---|---|
| `queued` | `jobs.status = queued` / `runs.status = queued` | admission creates the rows before enqueue |
| `running` | `running` | `task_context` sets it on pickup |
| `cancel_requested` | no persisted state | `cancel_run` is synchronous: it emits `run.cancel`, sets `runs.status = cancelled`, flips every `queued`/`running` job to `cancelled` through `set_job_status`, and revokes the Celery tasks. The window until the worker notices is covered by the redelivery guard and the cooperative kill (section 10.7), not by a state. The UI shows "cancelling" while the cancel request is in flight. |
| `completed` | `succeeded` | |
| `failed` | `failed` | `jobs.error` holds the class and message |
| `cancelled` | `cancelled` | |
| `timed_out` | `failed` with `error` beginning `SandboxTimeout:` (the ML task's own per-stage wall-clock budget, raised before `task_context` records the failure) or `reaped:` (reaper TTL) | the UI derives the "timed out" chip from the `error` prefix; there is no separate status |

Rules carried over from the shared contract and how they hold here:

- *Racing completion.* `cancel_run` filters jobs with `status IN ('queued','running')`, so a job that committed `succeeded` before the cancel transaction keeps it; the ordering is retained by `jobs.completed_at` versus the `run.cancel` audit event `ts`. **Required change:** `cancel_run` today sets `runs.status = cancelled` unconditionally; for ML runs the API returns `409` when the run is already terminal and leaves it untouched (William: "a terminal run ... is rejected without changing provenance").
- *Terminal states never become running again.* Guaranteed by `ALLOWED` in `job_state.py` and by 6.2.
- *A retry or rerun creates a new linked run.* A rerun at the same settings is a new `Run` with a new `ml_campaigns` row, the same `settings_hash` and `parent_run_id` set; a verify is a new `Run` with `baseline_run_id` set. Nothing edits the original.
- *Transport failure, skipped cases, unavailable explanations, and incomplete evidence are not model success or failure.* A `failed` or `cancelled` campaign has no `score`; a campaign whose SHAP stage failed keeps its measurements and has `score.completeness = "partial"`. Neither is ever rendered as "robust" or "not robust".
- *Preserve partial evidence with explicit completeness.* Measurements and artifacts are committed per stage; the run record written on failure carries `status="failed"` and `stages_done`, and the UI labels it "partial: stopped after `<stage>`".
- *Duplicate request identity.* An `Idempotency-Key` header on `POST /v1/models/{id}/attacks` is Phase B (section 17.3); Phase A relies on the worker redelivery guard and on the UI disabling the launch control while a request is in flight.

### 6.4 Finding states (canonical: `Finding.status` and `Finding.validation_state`)

`Finding.status` uses the `Status` Literal in `aegis/schema.py`: `open / fixing / fixed / failed / false_positive`. `Finding.validation_state` uses the values `aegis/workers/tasks/verify.py` writes: `unvalidated` (default) / `poc_passed` / `poc_failed` / `inconclusive`. Both vocabularies are already understood by the findings API, the run page chips (`web/src/app/runs/[id]/page.tsx`), and the report renderer.

ML meaning of `status`:

| `status` | Set by | Meaning | UI label (attack-scoped, D9 iii) |
|---|---|---|---|
| `open` | `attack.run` at creation; `verify.replay` on `inconclusive` | measured vulnerability awaiting human review or a verify | "Open, unreviewed" |
| `fixing` | `verify.replay` admission | a verify campaign for this finding is queued or running | "Verify in progress" |
| `fixed` | `verify.replay` on outcome `verified` | after the named defense, ASR is below the finding threshold at **every** eps in the grid | "Defense verified at these settings (ΔMRI measured); not independently reviewed" |
| `failed` | `verify.replay` on outcome `still_vulnerable` | after the named defense, ASR still crosses the threshold at some eps | "Defense did not remove the vulnerability at these settings" |
| `false_positive` | `finding.review` (approver tier, independent, section 7.7) | reviewer dismissal with a stated reason | "Dismissed by reviewer" |

ML meaning of `validation_state` (written by the verify task through the existing `_STATE_MAP`):

| Worker `VerifyStatus` | `validation_state` | ML condition |
|---|---|---|
| `verified` | `poc_passed` | re-attack at identical settings with the defense applied: ASR below threshold at every grid eps; `ml_campaigns.score.delta` computed |
| `still_vulnerable` | `poc_failed` | ASR at or above threshold at any grid eps |
| `inconclusive` | `inconclusive` | defense not applicable to this model or modality, sample mismatch, timeout, or `score.completeness = "partial"` on the verify run |

`validated_at` is set on every write. `poc_passed` never means safe, certified, or ready; it means measured at these settings. The UI never renders it as "fixed" or "resolved": the label is "verified: attack no longer crosses threshold at these settings with `<defense>`" (section 15.6).

William's finding states (F006) mapped, and the D10 decision:

| William state | Phase A realisation | Phase B |
|---|---|---|
| `draft` | not applicable: Phase A findings are machine-authored by `attack.run` | analyst-authored findings and revisions (`schema_blob.ml.revisions`) |
| `in_review` | `open` with `ml.review.state = "unreviewed"` | submission step |
| `confirmed` | not represented; `open` is shown as "unreviewed", never as "confirmed" | `ml.review.state = "confirmed"` with reviewer, reason, timestamp, via `finding.review` |
| `dismissed` | `false_positive` with `ml.review = {state: "dismissed", reviewer, reason, at}` | unchanged |
| `retest_requested` | `fixing` (a verify campaign exists, `ml.verify.run_id`) | unchanged |
| `resolved` | not represented. `fixed` is a **measured** state; William's `resolved` additionally requires independent review of the compatible retest. Until Phase B the UI must not label `fixed` as resolved. | `ml.review.state = "resolved"` requires `validation_state = poc_passed`, equal `settings_hash` on baseline and verify runs, and a reviewer other than the campaign creator |

Decision (D10): review states beyond dismissal are **Phase B**. Dismissal is implemented in Phase A because it is one status write through the existing `update_finding_status` path plus one audit event, and because the demo must show that a human can reject a machine finding. Confirmation and resolution need revision history and a review record that Phase A does not have time to build honestly.

Transition rules enforced in the service layer (not only in the UI):

- `open -> fixing` only through verify admission; `fixing -> fixed | failed | open` only by the verify worker; `open | failed -> false_positive` only through `finding.review` with a non-empty reason and an independent reviewer (7.7); `false_positive` is terminal in Phase A (reopening is Phase B).
- A stale write (client sends `expected_status` that no longer matches) returns `409`.
- `harden.recommend` never changes `status`; candidates are attached to the finding, not applied (F006 FR-008; brief).

### 6.5 Campaign stage progression (`runs.stage_table`)

```
{
  "stage": "explain",
  "stages_done": ["load_target", "sample", "clean_eval", "attack:fgsm", "attack:pgd", "control"],
  "stages": {
    "load_target": {"status": "succeeded", "started_at": "...", "finished_at": "...", "job_id": "<job_1>"},
    "attack:pgd":  {"status": "succeeded", "started_at": "...", "finished_at": "...", "job_id": "<job_2>"},
    "explain":     {"status": "running",   "started_at": "...", "finished_at": null,  "job_id": "<job_3>"}
  },
  "jobs": { "<job_id>": {"type": "attack.run", "attack_id": "pgd", "status": "succeeded"}, ... },
  "error": null
}
```

Stage keys are the `STAGES` tuple in `aegis/ml/schema.py` (`load_target`, `sample`, `clean_eval`, `attack`, `control`, `explain`, `score`, `interpret`, `recommend`, `report`), with `attack` written per attack as `attack:<attack_id>`; the verify campaign reuses the same stages with `defense_apply` inserted after `load_target` and `verify:<defense_id>` recorded for the re-attack. Per-stage `status` is `queued | running | succeeded | failed | skipped | cancelled | timed_out`. Stages advance monotonically; `report` is the last. This table is the source for the UI stage timeline and for the completeness flag (sections 10.3, 18.3).

### 6.6 Model target states (`targets.detail.status`)

```
registered -> validating -> available | refused
```

- `registered`: `POST /v1/models` stored the file in the blob store and created the `Target` row; the API computed `sha256` on the stream and **did not deserialise the file**.
- `validating`: the `ml.ingest` Run and `model.validate` Job exist (created by the same admission service, section 9.3).
- `available`: the worker loaded the model inside the plugin sandbox (section 9), the detected format matched the declaration, and input/output shapes matched the manifest. Only `available` targets are accepted by `attack.run` admission (`409 model_load_refused` otherwise, section 17).
- `refused`: terminal; `refusal_reason` is set and the blob is deleted. Re-upload creates a new Target.
- Bundled models are seeded `available` with a manifest from the asset manifest; every campaign still re-loads them through the same sandboxed path and re-emits `model.load`.
- The LLM domain is not a Target row in Phase A; `/v1/models` lists it from the registry as `TargetInfo.status = "not_implemented"` with a reason, and launching against it returns `501` (S2 honesty rule, D6).

### 6.7 Invariants

1. A terminal Job or Run is never mutated except for `finding.review` and `finding.annotate` writes on its findings.
2. No `score` without `completeness`; no `mri` without all five subscores.
3. A `Finding` is created only by a worker from measured rows; a fixture `RunRecord` (tests, `TinyTarget`) is never persisted through the production path (section 14).
4. Every status change that a human can trigger produces a chained audit event before the row changes (`authorize` first, then DB).

## 7. Roles and access

### 7.1 aegis roles and identities as implemented

`aegis/api/policy.py`:

```
_ROLE_RANK = {"scanner": 1, "remediator": 2, "approver": 3, "admin": 4}
```

Mutating routes call `check(user, Action, project_id)`, which delegates to the configured `PolicyEngine` (`AEGIS_POLICY_ENGINE`: `static` default, `opa`, `cedar`; external engines fail closed). `StaticPolicyEngine` allows a system principal unconditionally, otherwise compares the caller's role on that project against `_ACTION_MIN_ROLE`. Read routes use `has_project_access` / `ensure_project_access` (any membership on the project, or `is_system`), `accessible_project_ids` (list scoping; `None` = unrestricted for system principals) and `ensure_run_access` (resolves the run's project; `404` unknown run, `403` no membership). A membership role that is not in `_ROLE_RANK` (for example `viewer`) ranks `0`: it passes every read gate and fails every `check`.

Identity sources (`aegis/api/auth.py`):

| Source | Format | Membership |
|---|---|---|
| OIDC bearer JWT (Keycloak) | validated against `AEGIS_OIDC_JWKS_URL` and `oidc_audience` | claim `aegis_project_roles: {project_id: role}` |
| NextAuth session cookie | `api_session_cookie_name`, minted by the web callback | `project_memberships` from the cookie claims |
| Dev token | `dev:<email>`, only when `auth_mode == "dev"` and not `is_prod` | `{"default": "admin"}` |
| Worker service token | `worker:v<n>.<worker_id>.<exp>.<sig>` (HMAC, rotating key) | `is_system=True`, actor `service:worker:<id>` |

Keycloak realm roles in `deploy/keycloak/realm-export.json` are `scanner`, `remediator`, `approver`, `admin`. `ProjectMembership.role` is `String(32)`. `GET /v1/projects` returns the caller's role per project; `GET /v1/projects/{slug}/membership` lists members (any member may read); `PUT /v1/projects/{slug}/settings` is gated at admin via `Action.TARGET_MANAGE`. There is **no API route that changes a membership**; roles are managed in the identity provider and arrive as claims.

### 7.2 William's roles mapped onto aegis roles (D10, F001)

| William role | aegis role | Divergence to record |
|---|---|---|
| Owner | `admin` (rank 4) | none for actions; member management happens in Keycloak, not in the app (7.8) |
| Analyst | `remediator` (rank 2) | none |
| Reviewer | `approver` (rank 3) | aegis roles are ranked, so an `approver` can also do everything a `remediator` can (start and cancel campaigns, request hardening and verify). William's Reviewer is read-plus-approve only. The independence rule is enforced by the author check (7.7), not by removing abilities. A non-ranked `reviewer` role is a Phase B option. |
| Viewer | `viewer` (rank 0) | `viewer` must be added to `_ROLE_RANK` explicitly (rank 0), to the Keycloak realm roles, and to the design-system `ROLES` tuple (`packages/design-system/src/components/role-gated.tsx`, today `["scanner","remediator","approver","admin"]`). The web tests already use `viewer`. |
| (none) | `scanner` (rank 1) | aegis-only tier between Viewer and Analyst; may launch attacks and explanations but not harden, verify, cancel, or review. Harmless; documented. |

### 7.3 Access matrix (William's rows) realised as aegis gates

Columns show the William role, its aegis role in parentheses, and the concrete gate. "Yes*" marks the independence rule (7.7). Section 17 uses these `Action` names and minimum roles verbatim.

| Action (William) | Owner (admin) | Analyst (remediator) | Reviewer (approver) | Viewer (viewer) | aegis gate |
|---|---|---|---|---|---|
| Read project evidence, runs, findings, artifacts, MRI scorecard | Yes | Yes | Yes | Yes | `ensure_project_access` / `ensure_run_access` (any membership); RLS by `org_id` |
| Register catalog entries (bundled model pick, artifact upload) | Yes | Yes | Yes (rank) | No | `Action.MODEL_REGISTER` min `remediator` (new). Upload introduces untrusted bytes, but every byte is handled by the sandboxed worker (section 9); the gate is therefore William's Analyst tier, not admin. |
| Register a black-box endpoint (Phase B) | Yes | No | No | No | `Action.TARGET_MANAGE` (`admin`), because it authorises queries against a host |
| Draft evaluation profiles | Phase A: choose a campaign configuration at launch (no persisted draft) | same | same | No | covered by `attack.run`; F003 drafts and approval are Phase B |
| Start an attack campaign / request explanations | Yes | Yes | Yes (rank) | No | `Action.ATTACK_RUN`, `Action.EXPLAIN_RUN` min `scanner` (new; parity with `scan.start`) |
| Cancel a run | Yes | Yes | Yes (rank) | No | `Action.RUN_CANCEL` (`remediator`, existing) |
| Request hardening recommendations (spends LLM budget when `llm_narrative`) | Yes | Yes | Yes (rank) | No | `Action.HARDEN_RECOMMEND` min `remediator` (new; parity with `fix.generate`) |
| Request verify-after-harden | Yes | Yes | Yes (rank) | No | `Action.VERIFY_REPLAY` (`remediator`, existing) |
| Create/edit finding drafts and candidate recommendations | Phase B (machine-authored findings only in Phase A); notes: Yes | notes: Yes | notes: Yes | No | `Action.FINDING_ANNOTATE` min `remediator` (new) |
| Approve catalog versions and profiles | Phase B | No | Phase B | No | bundled assets are approved by the team at build time in the asset manifest; uploads are registered and validated, not approved, in Phase A (divergence from F002 FR-006, recorded under D2/D3) |
| Confirm / dismiss findings | Yes* (dismiss) | No | Yes* (dismiss) | No | `Action.FINDING_REVIEW` min `approver` (new) plus the independence check; confirm is Phase B |
| Export reports (md/json/html) | Yes | Yes | Yes | No | `Action.REPORT_EXPORT` min `scanner` (new). Today `GET /v1/runs/{run_id}/report.{ext}` is gated by `ensure_run_access` only, which would let a Viewer export; adding one `check()` closes the divergence (section 17.1) |
| Browse audit chain / verify chain | Yes | No | No | No | `Action.AUDIT_VERIFY` (`admin`, existing); logs likewise (`/v1/logs`) |
| Manage members | Yes (in Keycloak) | No | No | No | not an aegis API; see 7.8 |
| Project settings (LLM budget) | Yes | No | No | No | `PUT /v1/projects/{slug}/settings` (`admin`) |
| Manage auth profiles (Phase B endpoints) | Yes | No | No | No | `Action.AUTH_PROFILE_MANAGE` (`admin`, existing) |
| Delete a model target | Yes | No | No | No | `Action.TARGET_MANAGE` (`admin`); refused with `409` if any Run references the target (William: deletion limited to unused items) |
| Retention / purge | not implemented (D006 OPEN) | | | | no route; WORM export exists as a beat task |

### 7.4 New `Action` members

| `Action` | value | min role | Notes |
|---|---|---|---|
| `MODEL_REGISTER` | `model.register` | `remediator` | bundled pick or artifact upload; `ml_model_endpoint` uses `TARGET_MANAGE` |
| `ATTACK_RUN` | `attack.run` | `scanner` | admission of a campaign |
| `EXPLAIN_RUN` | `explain.run` | `scanner` | on-demand explanations |
| `HARDEN_RECOMMEND` | `harden.recommend` | `remediator` | rules layer plus optional Pythia narrative |
| `FINDING_REVIEW` | `finding.review` | `approver` | dismiss (Phase A); confirm/resolve (Phase B); independence check in the service |
| `FINDING_ANNOTATE` | `finding.annotate` | `remediator` | reviewer notes on a finding or campaign; no state change |
| `REPORT_EXPORT` | `report.export` | `scanner` | closes the Viewer export gap |

Existing members reused unchanged: `VERIFY_REPLAY` (`remediator`), `RUN_CANCEL` (`remediator`), `TARGET_MANAGE` (`admin`), `AUTH_PROFILE_MANAGE` (`admin`), `AUDIT_VERIFY` (`admin`). Members with no ML caller (`AGENT_RUN`, `AGENT_EXECUTE`, `FIX_GENERATE`, `FIX_APPLY`, `TOOL_INVOKE`, `TICKET_SYNC`) are pruned at M0 together with the routes that used them (section 17.1). Because `StaticPolicyEngine` reads `_ACTION_MIN_ROLE`, and the OPA/Cedar engines receive `action` as a string, the new values need a table row and, for external engines, a policy entry; an unknown action fails closed.

### 7.5 Read-side rules

- Every ML read route resolves the resource's `project_id` first and calls `ensure_project_access` (single resource) or filters by `accessible_project_ids` (lists). `404` for an unknown id, `403` for no membership; the `403` body never reveals whether the id exists in another project.
- Artifact streaming (section 17) resolves `artifacts.run_id -> runs.project_id` through `ensure_run_access` and serves with the strict CSP; artifact ids are unguessable UUIDs but are **not** the access control.
- System principals (workers) read everything; no human token is ever `is_system`.

### 7.6 Row-level security

Migration `0006_tenant_rls.py` enables and forces RLS with the `aegis_tenant_isolation` policy on `projects` and the eight scoped tables `targets, runs, jobs, findings, llm_usage, artifacts, remediation_attempts, application_logs`; `0010_ml_vertical` adds `ml_campaigns` with the identical trigger pair and policy. The predicate reads the transaction-local GUC `app.current_tenants`, set by `aegis/api/middleware/tenant.py` from the distinct `org_id`s of the caller's member projects; an empty GUC is the system path (worker, migrations) and bypasses the filter. `org_id` is trigger-backfilled on insert and guarded against drift on update (`0009`), so ML code never sets it. Not RLS-scoped: `organizations`, `users`, `project_memberships`, `auth_profiles` (app-scoped by `project_id` checks), `audit_events` / `audit_chain_heads` (append-only, chain-scoped, `project_id` nullable), `finding_tickets`. Production must connect as the non-superuser `aegis_app` role; `aegis/db/session.py` logs a warning once if a tenant-scoped session runs as a superuser, because a superuser bypasses RLS. RLS is defence in depth for the API read path; the application-layer gates in 7.3 and 7.5 remain the primary control, exactly as documented in `aegis/db/session.py`.

### 7.7 Independent-approval rule

William's matrix: approvals for catalog versions, profile approval and finding confirmation must come from someone other than the author, and an Owner may not bypass this. Phase A scope and mechanism:

- **Finding dismissal** (`finding.review`, the only review action in Phase A): the service in `aegis/services/ml_findings.py` rejects the write with `403` when `user.sub` equals the campaign creator (`runs.created_by`, stored as `user:<sub>`) or when `user.is_system`. The check lives in the service, not in the policy engine, so neither an `admin` role nor an OPA/Cedar policy can relax it. Machine-authored findings have the campaign launcher as their author for this purpose.
- **Phase B**: the same check applies to analyst-authored finding revisions (author of the revision), profile approval (author of the profile version), and upload approval (uploader), once those workflows exist (F002 US2, F003 US2, F006 US2).
- The dev-token demo has a single `admin` identity. The demo script (section 24) therefore shows dismissal with a second dev identity (`dev:<other-email>`) or states that the dismissal step is skipped; it never disables the check.

### 7.8 Membership management and onboarding (F001)

- Roles are claims. Adding, suspending, or removing a member and enforcing "a project keeps at least one Owner" are done in Keycloak (realm roles and the `aegis_project_roles` mapper), not in aegis. The app enforces the result on every request and lists membership read-only. William's invitation flow (`pending / accepted / expired / revoked / delivery_failed`) is the identity provider's invitation, outside aegis; aegis never mints invitation or auth tokens (F001 FR-001).
- Dev-token mode (`dev:<email>`, `admin` on `default`) is allowed for the demo per D11/D002 and is refused when `is_prod`.
- Sign-out and identity expiry are enforced by JWT `exp` validation and the session-cookie TTL; the JWKS cache TTL bounds acceptance of a rotated key.
- Denied actions are audited by the F008 rule only where an admission service runs (`authorize` emits `success=False` on allowlist failure); role-check denials return `403` and are logged to `application_logs` with `request_id`, not chained. Recorded as a known gap for section 25.

### 7.9 UI gating

`RoleGated minRole=...` in the web app is cosmetic (`aegis/api/v1/projects.py` docstring: "Mutation routes still enforce RBAC server side; the UI gating is cosmetic"). ML pages use: `scanner` for "Run attack" and "Explain", `remediator` for "Add model" (bundled or upload), "Recommend hardening", "Verify fix", "Cancel", and notes, `approver` for "Dismiss", `admin` for delete and endpoint registration. Controls hidden by role are also absent from the DOM, and the server still returns `403` if called directly (F001 FR-011).

### 7.10 What no role can reach

- Provider API keys: none exist in aegis; Pythia holds them (D5). The only secret is `PYTHIA_API_KEY`, read on the worker from the environment.
- Model bytes and images never leave the worker except as Artifacts served through the gated streaming route; the LLM writer receives metrics and a SHAP text summary only.
- `AuthProfile.secret_ciphertext` is never returned by any route.
- Audit rows cannot be edited or deleted through the application (`0004_audit_append_only.py`).

## 8. Architecture

### 8.1 Decision summary

The lean single-process design in S2 §2 (FastAPI + `ThreadPoolExecutor`, `run.json` on disk, no database, no queue, no auth) is **retired by D1**. The product runs on the full aegis platform that is restored in this repository: FastAPI `/v1` with RBAC and Postgres row-level security, Celery workers on Redis, Postgres for runs/jobs/findings/artifacts/audit, S3/MinIO for bytes, Keycloak/NextAuth for identity, the hash-chained audit log, per-task LLM routing with budget caps, and the OTel/structlog observability path. The adversarial-ML work is one new vertical, `aegis/ml/`, added to that platform (D7). Two things that S2 got right survive as constraints rather than as architecture: the evidence model (measurements, observations, interpretation, candidate recommendations kept apart; section 14) and the Pythia-only LLM path (D5).

S2 §2.1's "modules copied from aegis nearly verbatim" table (registry, redact, guardrails, state facade/filesystem, `report.html_escape`) is void: those modules are used in place, unrenamed, from the `aegis` package. S2's `redsim/jobs.py` thread pool is replaced by Celery `Job` rows and `task_context`; S2's `run.json` stage persistence is replaced by `Run.stage_table` plus the Redis run-event channel; S2's `setup_assets.py` becomes the `aegis ml build-assets` CLI command (section 11, section 20); S2's `recommend/pythia_client.py` is `aegis/llm/pythia.py`.

### 8.2 System diagram

```
                ┌───────────────────────────────┐          ┌─────────────────────────────────┐
  Browser ─────►│ @aegis/web  (Next.js 14)      │◄────────►│ Keycloak (OIDC)  ↔  NextAuth     │
                │ /models /models/[id] /runs/[id]│          │ dev-token mode allowed for demo  │
                │ /findings/[id] /audit /cost    │          └─────────────────────────────────┘
                └───────────────┬───────────────┘
                                │ aegis_api_session cookie + CSRF   (CLI/CI: Authorization: Bearer)
                                ▼
                ┌──────────────────────────────────────────────────────────────────────────────┐
                │ aegis-api   FastAPI /v1  — RBAC (policy.check), tenant GUC → Postgres RLS      │
                │  reuse: /runs /runs/{id} /runs/{id}/cancel /runs/{id}/events(WS) /findings     │
                │         /findings/{id}/verify /targets /audit/verify /reports /projects /logs  │
                │  new:   /models (multipart upload → S3)  /models/{id}/attacks  /attacks        │
                │         /findings/{id}/explain  /findings/{id}/harden  /artifacts/{id}         │
                │  invariant: never imports torch / ART / onnxruntime; never opens a model file  │
                └──────┬────────────────────────────┬─────────────────────────────┬────────────┘
   admission order:    │ 1. authorize() → audit row │ 2. Run + Job rows           │ 3. task.delay()
                       ▼                            ▼                             ▼
            ┌────────────────────┐        ┌──────────────────────┐       ┌────────────────────────┐
            │ Postgres (RDS)     │        │ S3 / MinIO           │       │ Redis (ElastiCache)    │
            │ runs jobs findings │        │ models/   upload     │       │ Celery broker + result │
            │ artifacts targets  │        │   bytes (content-    │       │ pub/sub                │
            │ ml_campaigns       │        │   addressed, sha256) │       │  run:{run_id}:events   │
            │ audit_events +     │        │ artifacts/ adv. ex., │       └───────────┬────────────┘
            │  chain heads       │        │   SHAP png/npz,      │                   │ consume
            │ llm_usage          │        │   curves, prompts    │                   ▼
            │ application_logs   │        │ reports/ md json html│   ┌────────────────────────────────────┐
            └─────────▲──────────┘        │ WORM bucket (audit)  │   │ aegis-worker  (Celery; `ml` extra) │
                      │                   └──────────┬───────────┘   │  -Q scans   model.validate         │
                      │        get model + slice     │  put artifacts│             attack.run explain.run │
                      │        ◄─────────────────────┼──────────────►│             verify.replay          │
                      └──────────────────────────────┼──────────────►│  -Q default harden.recommend       │
                                                     │               │             report.render reaper   │
                                                     │               │  task_context: job status, audit   │
                                                     │               │  writer, run_state, blob store     │
                                                     │               └────────┬──────────────────┬────────┘
                                                     │  per-job work dir      │                  │ text only:
                                                     ▼  (model, slice.npz)    ▼                  │ metrics + SHAP summary
                              ┌──────────────────────────────────────────────────┐               ▼
                              │ sandbox child, one per stage                     │   ┌───────────────────────────┐
                              │ python -m aegis.ml.sandbox_worker                │   │ Pythia gateway            │
                              │  own session/process group, POSIX rlimits,       │   │ POST {PYTHIA_BASE_URL}    │
                              │  wall-clock kill, allowlisted env (no AEGIS_*    │   │  /v1/chat/completions     │
                              │  secrets, no S3/DB creds), proxy vars stripped   │   │ Authorization: Bearer pk_ │
                              │  load model → ART estimator → attacks / SHAP /   │   │ X-Pythia-Persona          │
                              │  defense replay → files + ONE json envelope      │   │ holds all provider keys   │
                              └──────────────────────────────────────────────────┘   └───────────────────────────┘
```

Reading the diagram:

- **Upload path (D2).** Browser → `POST /v1/models` (multipart) → the API streams the bytes to the blob store while computing sha256 → `Target` row (`kind=ml_model_artifact`, `value` = blob URI) plus the model manifest defined in section 5 → audit row → `ml.ingest` Run and `model.validate` Job (section 9.3). The API never deserializes the file. The worker fetches the bytes from S3 into a per-job work directory and hands a path to the sandbox child. Model bytes therefore touch exactly three places: S3, the worker's work directory, and the child process.
- **Pythia egress (D5).** The only outbound network call the platform makes on behalf of a campaign is from the `harden.recommend` task to the Pythia gateway. It carries metrics and a SHAP text summary, never images, model bytes, or dataset rows (section 16, section 21). Provider credentials live in Pythia; aegis holds a `pk_…` key only. The sandbox child has no network configuration at all.
- **Audit first.** Every mutating call emits a chained audit event through `safety.authorize()` before any `Run`/`Job` row is created and before Celery is touched; the worker re-authorizes at execution and appends completion rows (section 10). `tests/test_admission_audit_before_enqueue.py` already asserts the ordering for the existing services; the new admission services join that test (section 22).
- **Tenancy.** The API sets the `app.current_tenants` GUC per request (`aegis/api/middleware/tenant.py`, `aegis/db/session.py`) so RLS filters `targets`, `runs`, `jobs`, `findings`, `artifacts`, `llm_usage`, `application_logs` and `ml_campaigns` by `org_id`. The worker runs in system scope (GUC empty) and is trusted to act only on the `Job` it was handed (section 10.4).
- **Live UI.** `task_context` publishes job transitions to `run:{run_id}:events`; the ML tasks publish stage transitions on the same channel; `/v1/runs/{run_id}/events` (WebSocket, origin- and cookie/bearer-checked) streams them to the browser. SWR polling of `/v1/runs/{id}` remains the fallback (S2 §2).
- **Observability.** `configure_otel` / `configure_structlog` in both API and worker propagate `request_id`, `run_id`, `job_id`, `project_id`; the `aegis-log-ingest` sidecar mirrors logs into `application_logs`; `/metrics` serves Prometheus.

### 8.3 Package layout (`aegis/ml/` and neighbours)

S1 §5 proposed six modules; the scaffold that exists today fixes the protocols. The table reconciles both and states which files exist now and which are to be written. Nothing in this table is implemented beyond the rows marked "exists".

| S1 §5 proposal | This spec | Status | Notes |
|---|---|---|---|
| `aegis/ml/loaders.py` — load artifact/endpoint into an ART estimator, detect framework by file signature | `aegis/ml/targets/base.py` (`Target` protocol, `Sample`), `aegis/ml/targets/bundled.py` (bundled model catalog + asset manifest reader), `aegis/ml/targets/artifact.py` (ONNX / state_dict / safetensors / XGBoost-JSON loaders), `aegis/ml/targets/architectures.py` (in-tree architecture catalog for state_dict uploads), `aegis/ml/targets/tabular.py`, `aegis/ml/targets/endpoint.py` (Phase B stub, `status=not_implemented`) | `base.py` exists; rest new | Loaders are imported **only inside the sandbox child** (section 9). File-signature detection happens at admission (cheap sniff) and again in the child (full parse). |
| `aegis/ml/attacks/` — one module per ART attack, registered through the existing registry | `aegis/ml/attacks/base.py` (`AttackAdapter`, `AttackOutput`), `fgsm.py`, `pgd.py`, `noise_control.py`, `hopskipjump.py`, `registry.py` | `base.py` exists; rest new | `registry.py` is an instance of the generic `aegis.registry.Registry` (duplicate detection, protocol check, opt-in entry-point discovery under group `aegis.ml.attacks`, gated by `AEGIS_PLUGINS=1` and the Ed25519 signature gate like scanner plugins). S1's "list in `/tools`" becomes `GET /v1/attacks` (section 17) and `aegis plugins list`. |
| — | `aegis/ml/campaign.py` — `CampaignScannerAdapter` (`name="ml-campaign"`, `capabilities={"adversarial_ml","explainability"}`) plus the stage pipeline (`load_target → sample → clean_eval → attack×eps → control → explain → score → interpret → recommend → report`) | new | Satisfies the S1 §2 row "ART attacks register the same way scanner adapters do": the façade is a built-in `ScannerAdapter` registered in `aegis.scanners.registry`, so `list_scanners()`, `dispatch()`, and the offline CLI see the vertical. `KNOWN_CAPABILITIES` gains `adversarial_ml` and `explainability` (S1 §4). `health_check()` reports whether the `ml` extra imports and the sandbox worker launches. `POST /v1/scans` is **not** the ML entry point (section 17). |
| `aegis/ml/explain/` — SHAP per modality, PNG + JSON artifacts | `aegis/ml/explain/shap_image.py`, `shap_tabular.py`, `stability.py` (`expl_shift`, center-mass heuristic), `summary.py` (the deterministic SHAP text summary, section 13.7) | package exists, empty | Section 13. |
| `aegis/ml/harden.py` — rules → ranked defenses → LLM prose | `aegis/ml/recommend/interpret.py` (interpretation rules, section 14.6), `aegis/ml/recommend/rules.py` (deterministic recommendation rules, cite measurement ids), `aegis/ml/recommend/narrative.py` (Pythia writer, text only), `aegis/ml/defenses.py` (ART preprocessors: feature squeezing, spatial smoothing, JPEG compression — applied only inside the sandbox for the verify loop) | package exists, empty | S2 naming retained. Section 16. |
| `aegis/ml/eval.py` — clean/robust accuracy, ASR, mean perturbation, confidence drop | `aegis/ml/eval.py` (metrics → `Measurement` rows), `aegis/ml/scoring.py` (MRI, subscores, ΔMRI) | new | Sections 12 and 15. |
| `aegis/workers/tasks/{attack,explain,harden}.py` mirroring scan/fix/verify | `aegis/workers/tasks/model_validate.py` (`aegis.model_validate`), `attack.py` (`aegis.attack_run`), `explain.py` (`aegis.explain_run`), `harden.py` (`aegis.harden_recommend`); `verify.py` gains an ML branch for `aegis.verify_replay` | new / modified | Section 10. |
| — | `aegis/ml/sandbox.py`, `aegis/ml/sandbox_worker.py` | new | The model-loading boundary (section 9.4). Reuses `SandboxConfig`, `_rlimit_preexec`, `_child_env`, `_kill_process_group` and the envelope conventions from `aegis/scanners/sandbox.py`; those helpers are promoted to public names in a shared module as part of the code fix-up. |
| — | `aegis/ml/datasets/` | new | Dataset catalog, licences, revision hashes, stratified sampling (section 11). |
| — | `aegis/ml/errors.py` | new | Typed failure classes whose names are the first token of `Job.error` (section 10.6). |
| — | `aegis/ml/schema.py` | exists | `TargetInfo`, `AttackInfo`, `RunConfig`, `Provenance`, `Measurement`, `Observation`, `Interpretation`, `CandidateRecommendation`, `RunRecord`, `STANDING_LIMITATIONS`. The scaffold's `RunConfig` names a single `attack_id`; the campaign configuration in section 5 (`CampaignConfig`) carries `attack_ids`, `eps_grid`, `reference_eps`, scoring weights and the finding threshold. The tasks in section 10 read the section 5 shape. |
| — | `aegis/services/ml_models.py` (`register_bundled_model`, `upload_model_artifact`), `aegis/services/ml_campaigns.py` (`create_attack_campaign`, `create_explain_job`, `create_harden_job`), `aegis/services/ml_findings.py` (`review_finding`, `annotate`) | new | Admission halves, same shape as `services/scans.py::create_scan_job`. |
| — | `aegis/api/v1/{models,attacks,datasets,defenses,ml_capabilities,artifacts,compare,ml_findings}.py` | new | Section 17. `/v1/artifacts/{id}` is new: no artifact-streaming route exists today; reports stream from `/v1/runs/{id}/report.{ext}` with the strict CSP in `aegis/api/security_headers.py`. |
| — | `aegis/llm/pythia.py` | exists | Transport (D5). `PythiaSettings.from_env` reads `REDSIM_LLM_MODEL` today; it changes to `AEGIS_ML_LLM_MODEL` at M0 (D5), with `tests/test_llm_pythia.py` and the comment in `aegis/ml/schema.py` updated in the same change. |
| — | `aegis/cli/ml.py` — `aegis ml build-assets`, `aegis ml attack` (offline) | new | Offline path mirrors `services.scans.start_scan`: filesystem `RunState`, `JsonlAuditWriter` at `<run_path>/audit.jsonl`, same sandbox child. |
| — | `tests/ml/fakes.py` (`TinyTarget`) | exists | Section 22. |

Router registration and queue routing changes: `aegis/workers/celery_app.py` `include` gains the four new task modules; `task_routes` gains `aegis.model_validate` → `scans`, `aegis.attack_run` → `scans`, `aegis.explain_run` → `scans`, `aegis.harden_recommend` → `default` (`aegis.verify_replay` already routes to `scans`). `aegis/api/app.py` mounts the new routers under `/v1`. `Job.type` (`String(64)`) and `Target.kind` (`String(32)`) are unconstrained strings in the ORM, so the new values need no enum migration; section 5 states the migrations for the new column and the campaign/score record.

### 8.4 Image boundaries

The API image (`deploy/Dockerfile.api`) installs `.[api,worker]` and stays free of the `ml` extra; the worker image (`deploy/Dockerfile.worker`) installs `.[worker]` today and adds `ml` (section 20). The `ml` extra in `pyproject.toml` currently lists numpy, torch, torchvision, onnx, onnxruntime, scikit-learn, adversarial-robustness-toolbox, shap, matplotlib, pillow, pyarrow, httpx; section 9 requires `onnx2torch` (ONNX → `torch.nn.Module` for gradient attacks) and `safetensors` (pickle-free state_dict format) to be added, and `xgboost` when the bundled tabular model is an XGBoost booster (section 20.2). A test (section 22) imports `aegis.api.app` with `torch`, `art`, `onnxruntime`, `shap` blocked in `sys.modules` and asserts the app still builds — the "never in the API process" rule is enforced, not assumed.

## 9. Model loading and isolation

### 9.1 Threat statement and rules

Untrusted model files are dangerous: a pickle executes code on load, a protobuf parser or an inference runtime can have memory-safety bugs, and a large graph can exhaust CPU or memory. S1 §5 and §13 set the rules; D2 fixes the formats. The rules, in force for Phase A:

1. **Preferred format is ONNX.** PyTorch `state_dict` is accepted only with an explicit architecture id from the in-tree catalog. Full pickles are refused; there is no override path in Phase A (S1 §13's "I trust this file" checkbox is a Phase B item and, if built, requires the `admin` role, an operator-set worker flag `AEGIS_ML_ALLOW_PICKLE=1`, an audit row with `override=true`, and still runs in the sandbox). TensorFlow SavedModel, listed as preferred in S1 §5, is deferred to Phase B: D2 names ONNX and state_dict only, and the `ml` extra carries no TensorFlow.
2. **Never load a model file in the API process.** The API streams bytes to S3, sniffs a few leading bytes, computes sha256, and writes rows. It does not import torch, onnx, onnxruntime, ART, or SHAP (section 8.4).
3. **Load and run only on the worker, inside the sandbox child.** Every stage that touches model bytes — validation, load, clean evaluation, attack, control, explanation, defended replay — runs in `python -m aegis.ml.sandbox_worker`, a separate process with rlimits, its own process group, a minimal environment, a wall-clock kill, and no credentials. This applies to bundled models as well as uploads: one path, exercised on every run.
4. **Black-box endpoints are Phase B.** `Target.kind=ml_model_endpoint` is registered as a kind, `aegis/ml/targets/endpoint.py` returns `status=not_implemented` with a reason, and launching a campaign against one returns HTTP 501 (section 17). When built, endpoint credentials reuse `AuthProfile` (Fernet-encrypted; decrypted worker-side only, as `resolve_auth_for_scan` does for scans) and the endpoint host must pass the target allowlist.

### 9.2 Accepted formats and what "loading" means for each

| Declared format | File | Admission sniff (API) | Child-side load | ART estimator | Gradients | Refused when |
|---|---|---|---|---|---|---|
| `onnx` | `.onnx` protobuf `ModelProto` | not zip, not pickle opcode; size ≤ cap | `onnx.load(path, load_external_data=False)` → `onnx.checker.check_model`; `onnxruntime.InferenceSession` with default CPU provider, `intra_op_num_threads` bounded, no custom-op libraries; for gradient attacks `onnx2torch.convert` → `torch.nn.Module`, agreement with onnxruntime measured on the evaluation slice and recorded in provenance as `onnx_torch_argmax_agreement` | `PyTorchClassifier` over the converted module when conversion succeeds; otherwise `BlackBoxClassifier` over the onnxruntime `predict` | yes if converted; no otherwise (white-box attacks recorded as `not_run: unsupported_onnx_op`, black-box attacks still run — never silently substituted) | external-data tensors referenced; custom operator domains; opset outside onnxruntime's supported range; checker failure; input rank/shape or output class count disagreeing with the manifest |
| `torch_state_dict` | `.pt` / `.pth` zip archive | zip signature `PK\x03\x04` at byte 0; architecture id present and in catalog | `torch.load(path, map_location="cpu", weights_only=True)`; instantiate the catalog architecture; `load_state_dict(strict=True)` | `PyTorchClassifier` | yes | `weights_only` load raises (non-tensor pickled objects — this is what "full pickle" means operationally); missing/unexpected keys or shape mismatch; architecture id unknown |
| `safetensors_state_dict` | `.safetensors` | 8-byte header length + JSON header starting `{` | `safetensors.torch.load_file`; same architecture instantiation | `PyTorchClassifier` | yes | header malformed; key/shape mismatch; architecture id unknown |
| legacy torch pickle / joblib / `.pkl` | pickle stream (`\x80` PROTO opcode at byte 0, or `.pkl` extension) | refused at admission, HTTP 415 | never reached | — | — | always in Phase A |
| `xgboost_json` (tabular) | `.json` / `.ubj` written by `Booster.save_model` | JSON object or UBJSON magic | `xgboost.Booster.load_model` (no pickle) | ART `XGBoostClassifier` | no (tree ensemble); PGD by surrogate transfer only when the manifest declares a build-time surrogate (section 12.2) | schema not an XGBoost model; feature count disagrees with the dataset manifest |
| bundled sklearn (tabular, **bundled only**) | joblib file shipped by `aegis ml build-assets` | not an upload path | `joblib.load` **only** if the file's sha256 equals the digest in the asset manifest written at build time | ART `SklearnClassifier` (`ScikitlearnLogisticRegression` exposes loss gradients; tree ensembles do not) | yes for logistic regression / linear SVC; no for trees (surrogate transfer as above) | digest mismatch (the only pickle the loader ever opens, and only for an in-repo asset) |

Consequences the attack catalog (section 12) and explainability (section 13) must respect: a tree ensemble exposes no loss gradients in ART, so gradient attacks (FGSM, PGD) are reported as `not_run: estimator has no loss gradients` for that target **unless** the target's manifest declares a build-time differentiable surrogate, in which case PGD runs by surrogate transfer, is scored on the real model, and is labelled as such in `Measurement.notes` (section 12.2) — a surrogate is never introduced silently; query-based attacks (HopSkipJump) run on every estimator; `TreeExplainer` applies to tree models and `GradientExplainer`/`DeepExplainer` to torch modules. D4(d) is satisfied by the bundled tabular tree ensemble carrying a declared surrogate (PGD by transfer) and being attacked directly by HopSkipJump, with `TreeExplainer` on the real model; which pairs ran is recorded per target in the campaign record, never implied.

Bundled image models are built by `aegis ml build-assets` (S2 §2.1) as a `state_dict` plus an in-tree architecture (gradients native, no conversion) **and** exported to ONNX. The ONNX export is what the demo uploads to exercise the upload path (section 24), which also exercises `onnx2torch` on a known graph. Clean accuracy of every bundled model is recorded in the asset manifest at build time; it is never hard-coded in documentation.

### 9.3 Upload path, step by step

1. `POST /v1/models` (multipart; fields `declared_format`, `architecture_id` when required, `modality`, `dataset_id` for compatibility checks, `license_statement`; section 17). RBAC per section 7 (`MODEL_REGISTER`).
2. The API enforces `Content-Length` and a streaming cap `AEGIS_ML_UPLOAD_MAX_MB` (default 512). Over the cap → HTTP 413. The first 16 bytes are sniffed against the table in 9.2: a pickle opcode, a `.pkl`/`.joblib` name, or a signature that contradicts `declared_format` → HTTP 415 / 422, with an audit row `model.register` `success=false` and the reason in `detail`. No bytes are retained for a refused upload.
3. Accepted bytes stream to the blob store as `BlobStore.put(key=f"{project_id}/models/{target_id}/{safe_filename}", ...)`; the store is content-addressed (`s3://{bucket}/{key}/{sha256}`, `FilesystemBlobStore` for offline), so a re-upload of identical bytes is a no-op and the sha256 is the identity used everywhere afterwards.
4. `authorize("model.register", target=None, ...)` emits the chained audit row (project chain `project:{project_id}`), `detail={target_id, source: "upload", sha256, size_bytes, declared_format, architecture_id, modality, filename}`. `target=None` because the allowlist is a network-scope control and does not apply to an in-boundary artifact; `allowlist_check` records `n/a`. (For the Phase B endpoint kind the URL is passed as `target` and the allowlist applies.)
5. `Target(kind="ml_model_artifact", value=<blob location>)` plus the model manifest (section 5.5: format, sha256, architecture id, input shape, class names, `source=uploaded`, declared licence statement, `status="registered"`) are inserted. If the audit write fails, the blob is deleted best-effort and the request fails 500 — a `Target` row never exists without its audit row.
6. The same admission service creates an `ml.ingest` Run and a `model.validate` Job (section 10.2) and enqueues it; the manifest status becomes `validating`. The response is the `Target` record with that status. No loading has happened in the API. The worker's validation outcome is audited as `model.validate` and moves the status to `available` or `refused` (section 6.6); `attack.run` admission accepts only `available` targets. Every later campaign or verify job re-loads the model through the same sandboxed path and audits the outcome as `model.load`.

Bundled models are registered through `register_bundled_model` (same audit action with `source=bundled`, digest from the asset manifest) and seeded directly as `available`; their blobs are seeded by `aegis ml build-assets` at deploy (section 20).

### 9.4 The sandbox mechanism as it exists, and how the ML vertical uses it

`aegis/scanners/sandbox.py` and `aegis/scanners/sandbox_worker.py` implement the out-of-process boundary for third-party scanner plugins discovered from the `aegis.scanners` entry-point group. What it actually does:

- **Wrap point.** During eager discovery `aegis.scanners.registry._sandbox_wrap` wraps each conformant, signature-approved plugin in `SandboxedScanner`, a structurally conformant `ScannerAdapter` whose `scan()` calls `run_scanner_sandboxed(entry_point, run_state, options, adapter_name, config)`. Built-in adapters registered in code never pass through the wrapper; the sandbox is a plugin-only control today.
- **Launch.** `subprocess.Popen([sys.executable, "-m", "aegis.scanners.sandbox_worker", "--entry-point", ep], stdin/stdout/stderr=PIPE, text=True, env=_child_env(cfg), preexec_fn=_rlimit_preexec(cfg), start_new_session=True)` — list argv, never `shell=True`.
- **Limits** (`SandboxConfig`, from `AEGIS_PLUGIN_SANDBOX_*` env or defaults): `timeout_s=600` (wall clock), `cpu_seconds=300` (`RLIMIT_CPU`), `memory_mb=1024` (`RLIMIT_AS`), `file_size_mb=256` (`RLIMIT_FSIZE`), `open_files=256` (`RLIMIT_NOFILE`), `max_processes=256` (`RLIMIT_NPROC`, best-effort), `RLIMIT_CORE=0`, `allow_network=False`. Soft and hard limits are set equal; individual `setrlimit` failures are swallowed so the child still launches (best-effort hardening).
- **Environment.** Built from an empty dict, copying only `PATH, PYTHONPATH, PYTHONHOME, PYTHONHASHSEED, VIRTUAL_ENV, HOME, TMPDIR, TEMP, TMP, LANG, LC_ALL, LC_CTYPE, TERM, TZ, SYSTEMROOT` when present, pinning `AEGIS_PLUGINS=0`. Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and lower-case forms) are restored only when `AEGIS_PLUGIN_SANDBOX_NETWORK` opts in. The parent's `AEGIS_DB_URL`, `AEGIS_S3_*`, `AEGIS_WORKER_SIGNING_KEY`, `AEGIS_AUTH_PROFILES_KEY`, `PYTHIA_API_KEY`, and any API tokens are never in the child.
- **Timeout.** `proc.communicate(request, timeout=cfg.timeout_s)`; on `TimeoutExpired` the parent SIGKILLs the whole process group (`os.killpg`) so grandchildren die too, reaps, and returns an error envelope.
- **Result channel.** The child `dup`s real stdout to a private fd and points fd 1 (and `sys.stdout`) at stderr, so nothing the plugin prints can corrupt the single JSON line the parent parses. Exit code 0 for any envelope (success or structured error), 2 only when the request itself was unreadable. Any failure — crash, limit hit, timeout, unparseable output — becomes a clean error result rather than taking down the worker.
- **Stated scope.** Per the module docstring and SECURITY.md: process isolation + rlimits + wall-clock kill + minimal env, gated by the plugin allowlist/signature. It is **not** a network namespace or a filesystem jail; a hostile child can still open sockets and touch files the worker UID can reach. Kernel-level isolation is a tracked follow-up. The Helm chart can schedule worker pods under a gVisor `RuntimeClass` (`docs/ops/kubernetes.md`); the ECS Fargate target (section 20) has no equivalent, which is recorded as a risk in section 25.

The ML vertical builds `aegis/ml/sandbox.py` on the same primitives and conventions, with these deliberate differences:

| Aspect | Plugin sandbox (exists) | ML model sandbox (this spec) |
|---|---|---|
| Child entry | `aegis.scanners.sandbox_worker --entry-point module:factory`; imports arbitrary plugin code | `aegis.ml.sandbox_worker --stage validate|attack|explain|verify`; imports only in-tree `aegis.ml` code; the untrusted input is the model file, not code |
| Enable switch | `AEGIS_PLUGINS_SANDBOX` (default on, can be turned off for trusted plugins) | none — there is no in-process path for model bytes; `AEGIS_PLUGINS_SANDBOX=0` has no effect on ML |
| Config env | `AEGIS_PLUGIN_SANDBOX_{NETWORK,CPU_SECONDS,MEMORY_MB,FILESIZE_MB}` | `AEGIS_ML_SANDBOX_TIMEOUT_S` (default 1200), `AEGIS_ML_SANDBOX_CPU_SECONDS` (900), `AEGIS_ML_SANDBOX_MEMORY_MB` (4096), `AEGIS_ML_SANDBOX_FILESIZE_MB` (1024), `AEGIS_ML_SANDBOX_THREADS` (2); network is never enabled (section 20.3). `RLIMIT_AS` caps virtual address space, and CPU torch maps large virtual regions at import, so the default sits well above resident need; the wall-clock and CPU limits are the operative caps. The wall clock must stay below the Celery soft limit (1800 s) and the reaper TTL (`job_max_runtime_seconds`, 3600 s). |
| Child env additions | — | `OMP_NUM_THREADS`/`MKL_NUM_THREADS` = `AEGIS_ML_SANDBOX_THREADS`, `MPLBACKEND=Agg`, `HF_HUB_OFFLINE=1`, `HF_DATASETS_OFFLINE=1`, `PYTHONHASHSEED` fixed for the run |
| Inputs | run dir path + `ScanOptions` JSON | a per-job work directory (`AEGIS_ML_WORK_DIR`, default `$TMPDIR/aegis-ml/<job_id>`, mode 0700) that the **parent** populates: the model file fetched from S3 and digest-checked against the manifest, `slice.npz` (the seeded, stratified evaluation slice sampled by the parent — section 11), and for explain/verify stages the attack-stage `x_adv` artifacts fetched and digest-checked against their `Artifact` rows. The child never reaches S3, Postgres, Redis, or the dataset source. |
| Output | `{"ok": true, "result": <ScanResult dict>}` | `{"ok": true, "result": {measurements[], observations[], findings[] (AegisFinding dicts), artifacts[] ({name, kind, path, sha256, content_type}), provenance{}, not_run[] ({attack, reason}), stage_timings{}}}` or `{"ok": false, "error_class": "<aegis.ml.errors name>", "error": "<operator-safe message>"}`. Large arrays go to files in the work dir; the envelope is capped at 16 MiB. |
| Parent post-processing | rebuild `ScanResult` | validate every list element with its Pydantic model (a malformed envelope fails the job, nothing is trimmed silently); recompute sha256 of each listed file and compare; require `finding.source_run_id == run_id` and `source_tool` prefix `aegis.ml/`; then `run_state.record_artifact(name, bytes, content_type)` (→ blob key `{project_id}/{run_id}/{kind}/{sha256}` and an `Artifact` row unique on `(run_id, kind, sha256)`), `run_state.save_findings(...)`, the campaign/score record write (section 5), and the audit rows (section 10.5); finally the work dir is removed unless `AEGIS_ML_KEEP_WORK_DIR=1` |

The stage internals (`Target` implementations, attack adapters, explainers, defenses, scoring) are plain Python called by `aegis/ml/campaign.py` inside the child. They are unit-tested in-process against `tests/ml/fakes.py::TinyTarget` (section 22); the subprocess boundary is tested separately by launching the real child on `TinyTarget` and on a deliberately malformed file. Bundled models take the identical path on every run, so the demo exercises the boundary rather than bypassing it.

### 9.5 Refusal paths

Every refusal is explicit, typed, audited, and free of model content. Nothing is faked, downgraded, or retried into a different behaviour.

| Condition | Where detected | Outcome | Audit |
|---|---|---|---|
| Upload exceeds `AEGIS_ML_UPLOAD_MAX_MB` | API, while streaming | HTTP 413 `model_too_large`; bytes discarded | `model.register` `success=false`, `detail.reason=size_cap` |
| Pickle opcode / `.pkl` / `.joblib` / unknown signature | API sniff | HTTP 415 `pickle_refused` or `unsupported_model_format` | `model.register` `success=false` |
| Sniffed signature contradicts `declared_format`; `state_dict` without `architecture_id`; unknown `architecture_id` | API | HTTP 422 with the field named (`architecture_required`, `architecture_not_allowlisted`, `unsupported_model_format`) | `model.register` `success=false` |
| Manifest input shape / class count incompatible with the chosen dataset | API at `POST /v1/models` (upload) or `POST /v1/models/{id}/attacks` when both manifests are known | HTTP 422 `dataset_incompatible` | `model.register` / `attack.run` `success=false` |
| Blob digest ≠ manifest sha256 when the worker fetches the model | worker (parent), before spawning | job `failed`, `ArtifactDigestMismatch`; target stays as it was | `model.validate` / `model.load` `success=false` |
| ONNX external data, custom op domain, checker failure, unsupported opset | child (`model.validate`; re-checked at every `model.load`) | `model.validate` job `failed`, target `refused` with `refusal_reason`, blob deleted; `ModelLoadRefused: onnx_<reason>` | `model.validate` `success=false`, `detail.refusal_reason` |
| `torch.load(weights_only=True)` raises; `load_state_dict(strict=True)` mismatch | child | as above; `ModelLoadRefused: pickle_refused` / `architecture_mismatch` | `model.validate` `success=false` |
| ONNX → torch conversion fails | child | target `available` with `gradients=false`; gradient attacks are not offered by the launcher and, if requested through the API, are listed in `not_run` with `unsupported_onnx_op`; black-box attacks run; MRI computed only over attacks that ran and labelled accordingly (section 15) | `model.validate` / `model.load` `success=true`, `detail.gradients=false` |
| Estimator has no loss gradients (tree ensemble without a declared surrogate) and a gradient attack was requested | child | attack listed in `not_run: estimator has no loss gradients`; job succeeds | `attack.execute.<id>` `success=true`, `detail.not_run=true` |
| Wall-clock timeout | parent | process group SIGKILLed; job `failed`, `SandboxTimeout`; files written before the kill are recorded under `ml/partial/…` and the stage is marked `timed_out` in `Run.stage_table`; the campaign record's `completeness` (section 5.6) is `partial` | `job.complete` `success=false` |
| CPU / address-space / file-size rlimit hit | child dies, parent sees non-zero exit or `{"ok": false}` | job `failed`, `SandboxKilled` with the exit status | `job.complete` `success=false` |
| `ml` extra missing on the worker (`CampaignScannerAdapter.health_check()` false) | parent, before spawning | job `failed`, `MlExtraUnavailable` — never a stub result | `job.complete` `success=false` |
| Target kind `ml_model_endpoint` | API | HTTP 501 `not_implemented`, reason string from `endpoint.py` | `attack.run` `success=false` |
| Target not `available` (`registered`, `validating`, `refused`) | API at `POST /v1/models/{id}/attacks` | HTTP 409 `model_load_refused` with the status and `refusal_reason` | `attack.run` `success=false` |
| Dataset revision unavailable in the blob store | parent | job `failed`, `DatasetUnavailable` | `job.complete` `success=false` |

`Job.error` is written by `task_context` as `f"{type(exc).__name__}: {exc}\n{traceback}"`; the exception class name is therefore the machine-readable category the UI maps to a human label (section 18) and is what separates infrastructure and refusal outcomes from model outcomes (S3 run-state contract: "transport failure, skipped cases, unavailable explanations, and incomplete evidence are not model success or model failure").

## 10. Job and worker flow

### 10.1 The two halves, reused

aegis splits every operation into an **admission** half (API process, request-scoped, cheap) and an **execution** half (worker, long-running). `aegis/services/scans.py::create_scan_job`, `services/verify.py::create_verify_job`, and `services/runs.py::cancel_run` are the templates; `aegis/workers/bootstrap.py::task_context` is the execution wrapper; `aegis/workers/job_state.py::set_job_status` is the only writer of `Job.status`. The ML vertical adds admission functions and tasks of the same shape and changes nothing about the contract.

Admission order is load-bearing and identical for every ML route:

1. Authentication (`get_current_user`) and RBAC (`policy.check(user, Action, project_id)`; actions per section 7).
2. Input validation (Pydantic body; target/dataset/attack compatibility from manifests; 4xx on failure, nothing persisted).
3. `safety.authorize(action, target, allowlist=config.target_allowlist, actor=f"user:{user.sub}", writer=resolve_writer(config), project_id=..., run_id=..., detail=...)` — the chained audit row is written to Postgres (`PostgresAuditWriter`, `SELECT … FOR UPDATE` on `audit_chain_heads`) **before** any domain row exists. `detail` is passed through `redact_audit_detail`.
4. `Run` and `Job` rows inserted and flushed (`Run` first — FK precedence).
5. `task.delay(job_id)`. If the broker is unreachable, the exception is logged and the row stays `queued` for a later pickup; the audit row already exists, so a crash here never yields a job without a trail.
6. `JobHandle.to_response()` → `{"run_id", "job_ids", "status_url": "/v1/runs/{run_id}"}`.

Effect class (ADR 0004, `aegis/effects.py`): a campaign against an `ml_model_artifact` operates on a copy of the model inside the sandbox and changes no live system, so it is `read` — it runs on the project role gate alone. A Phase B campaign against an `ml_model_endpoint` queries a live inference service and is `active`: it returns a proposal until re-invoked with `execute=true` by an `approver` (section 7), exactly as agents and active Kali tools were gated.

### 10.2 Tasks

| Celery task | `Job.type` | Queue | Admission | What the worker does | Reads | Writes |
|---|---|---|---|---|---|---|
| `aegis.model_validate` (`workers/tasks/model_validate.py`) | `model.validate` | `scans` | `upload_model_artifact` from `POST /v1/models` (upload), inside an `ml.ingest` Run | fetch the blob, verify sha256 against the manifest; spawn child `--stage validate`: full format parse, architecture instantiation for `state_dict`, ONNX checker and onnxruntime session, optional `onnx2torch` conversion with argmax agreement on a small slice, shape and class-count check against the bound dataset manifest; write `ml.validation_report`; set `targets.detail.status` to `available` (with `gradients`) or `refused` (with `refusal_reason`, blob deleted) | `Target` + manifest, dataset manifest | `targets.detail`, `Artifact` row, audit rows |
| `aegis.attack_run` (`workers/tasks/attack.py`) | `attack.run` (one Job per attack in the set) | `scans` | `create_attack_campaign` from `POST /v1/models/{id}/attacks` | fetch model + the seeded slice into the work dir; spawn child `--stage attack`: load (`model.load`) → if `chain_position == 0`: clean eval (`m.clean`) and the benign noise control at every ε (`m.control.*`) → this attack at each ε in the grid → measurements → Finding by threshold (section 12.6); record artifacts (`ml.adv_slice` per ε, `ml.flip_matrix`, `ml.curve`); save the Finding; write the attack-derived rows into the campaign record; enqueue the next attack job in the chain, or the pre-created `explain.run` when this was the last attack | `Target` + manifest, dataset revision, campaign config from `Job.detail`, the clean/control rows written by the first job | `Finding` rows, `Artifact` rows, campaign record, `Run.stage_table`, audit rows |
| `aegis.explain_run` (`workers/tasks/explain.py`) | `explain.run` | `scans` | pre-created by `create_attack_campaign` (when `explain_k > 0`), or `create_explain_job` from `POST /v1/findings/{id}/explain` | fetch model, slice and the attacks' `x_adv` artifacts (digest-checked); spawn child `--stage explain`: SHAP clean vs adversarial for `explain_k` flipped and `explain_k` unflipped samples per attack at `reference_eps`, `center_mass_ratio` (heuristic), `expl_shift` and its noise floor (section 13); record `Observation`s and artifacts (`ml.input.*`, `ml.perturbation`, `ml.shap.*`); then the **score stage**: `S_expl` and the MRI are written only now, with all five subscores present (D9(ii); `campaign.score` audit row, `ml.score` artifact); enqueue `harden.recommend` | attack-stage artifacts, campaign record | `Observation`s, artifacts, campaign/score record, `Finding.schema_blob` SHAP artifact ids |
| `aegis.harden_recommend` (`workers/tasks/harden.py`) | `harden.recommend` | `default` | pre-created by `create_attack_campaign` (when `auto_recommend`, default true), or `create_harden_job` from `POST /v1/findings/{id}/harden` | `interpret` stage: the interpretation rules of section 14.6; `recommend` stage: the rule layer over measurements + observations (deterministic, each rule cites the ids that fired; section 16.2); optional Pythia writer (10.8); `Interpretation` and `CandidateRecommendation` records with `status=candidate`, `validation=not evaluated`; `report` stage through `services.reports.render_reports` (md/json/html to the blob store as `report.*` artifacts); marks `Run.status=succeeded` when it is the last job of the chain | measurements, observations, score record | interpretation, recommendations, `Artifact` rows for prompt/completion/narrative, `LLMUsage` row, reports |
| `aegis.verify_replay` (`workers/tasks/verify.py`, ML branch) | `verify.replay` | `scans` | existing `create_verify_job` from `POST /v1/findings/{id}/verify`, body extended with `defense` (section 17) | if the finding's `source_tool` starts with `aegis.ml/`: create the `ml.verify` Run with `baseline_run_id`; fetch model + the **same** slice (indices from provenance) + the same attack set, ε grid, seed; spawn child `--stage verify` with the ART preprocessor defense (`defenses.py`) in front of the estimator; re-run clean eval, the **whole in-scope attack set** at every ε, the benign control, and the explanations at `reference_eps` on the defended model; compute the defended subscores and MRI at identical settings → ΔMRI and per-dimension deltas (section 15.6); map the outcome through the existing `_STATE_MAP` to `Finding.validation_state` (section 6.4); `append_remediation_log(finding_id, action=f"ml.verify.{defense_id}", result=<json summary>, success=<bool>)`; attach the `MeasuredDelta` to the recommendation that named this defense (section 16.4). Otherwise the existing DAST/SAST strategies run unchanged; `aegis/verify.py::VerifyStrategy` gains `"ml_replay"`. | baseline campaign record, artifacts | second (defended) score record linked to the baseline, artifacts, `RemediationAttempt`, `Finding.validation_state`/`validated_at`, `Finding.status` per section 6.4 |
| `aegis.report_render` (exists) | `report.render` | `default` | — | unchanged; re-renders reports from findings | | |
| `aegis.reap_stale_jobs` (exists, beat, every 300 s) | — | `default` | — | flips `running` jobs older than `job_max_runtime_seconds` (3600) to `failed` with `error="reaped: exceeded max runtime TTL"` | | |

The defense in `verify.replay` is applied as an ART preprocessor around a copy of the estimator inside the child. The stored artifact is never modified and nothing is deployed; the loop measures a candidate on this model at these settings (D4(a), D9(iv)) and does not "apply a mitigation" in the brief's sense.

### 10.3 Campaign lifecycle

```
POST /v1/models/{id}/attacks     (attacks = [fgsm, pgd])
  │ check(ATTACK_RUN) → validate → authorize("attack.run") → Run(queued, scanner=ml.campaign)
  │ + Job attack.run[fgsm] (chain_position 0) + Job attack.run[pgd] + Job explain.run + Job harden.recommend
  │ → attack_run.delay(job_fgsm) → 202 {run_id, job_ids, status_url}
  ▼
attack_run(job_fgsm)   task_context: queued→running, publish "running"
  │ re-check: Target exists in job.project_id and is `available`; manifest sha256; dataset revision; config re-validated
  │ fetch model + slice → work dir → child --stage attack → model.load, sample, clean_eval, control, attack:fgsm × eps
  │ envelope → verify digests → record_artifact ×N, save_findings, campaign record, stage_table
  │ authorize("attack.execute.fgsm") before the attack; authorize("job.complete") after
  │ attack_run.delay(job_pgd)                        task_context: running→succeeded, publish "succeeded"
  ▼
attack_run(job_pgd)    … reuses slice.npz and the clean/control rows … attack:pgd × eps … explain_run.delay(job_explain)
  ▼
explain_run(job_explain)  … child --stage explain … observations … S_expl → score stage (MRI written, campaign.score) … harden_recommend.delay(job_harden)
  ▼
harden_recommend(job_harden)  interpret → recommend (rules) → Pythia (optional) → report → Run.status=succeeded
```

Rules that govern the chain:

- All campaign `Job` rows are created at admission so each has an audit row before it can run; each task emits its own execute rows and a `job.complete` row on the run chain. Worker rows carry `actor = Job.created_by` (the requesting principal, as `task_context` sets `ctx.actor`) and are correlated with the admission row by `run_id`.
- The attack jobs run as a chain in the declared attack order. The first attack job (`chain_position == 0`) also runs the `sample`, `clean_eval` and `control` stages and writes `slice.npz`, `m.clean` and the `m.control.*` rows; later attack jobs re-fetch `slice.npz` (digest-checked) and reuse those rows, so every row of the campaign is computed on the same indices (section 14.2).
- A task that fails marks the remaining `queued` jobs of the chain `cancelled` (`queued → cancelled` is legal) with `error="upstream job failed: <job_id>"`, sets `Run.status=failed`, `completed_at`, and stops. Nothing downstream runs on partial inputs.
- `explain_k = 0` skips the explain job; then the score stage cannot compute `S_expl`, and the campaign record carries the four available subscores with `S_expl` and MRI marked `not computed: explanation stability not evaluated` (never a renormalized four-dimension number; section 15.4). `auto_recommend=false` skips the harden job; `POST /v1/findings/{id}/harden` creates one later under the same `Run`.
- `Run.stage_table` has the shape fixed in section 6.5; it is the source for the UI stage timeline and for the completeness flag (sections 5.6, 18).
- Stage transitions are published on `run:{run_id}:events` via `publish_job_event(run_id, job_id, status, type="stage", stage=...)` (the helper already accepts extra keys; best-effort, never fails the task).
- `Run.status` moves `queued → running` when the first job starts, `→ succeeded` when the last job of the chain succeeds, `→ failed` on the first terminal task failure, `→ cancelled` via `cancel_run` (section 6.2). The Job vocabulary is `queued | running | succeeded | failed | cancelled` with `running → queued` reserved for the transient-retry requeue; the mapping from William's `completed`/`timed_out`/`cancel_requested` is in section 6.3.

### 10.4 Worker-side re-checks

The worker does not trust admission blindly (the pattern of `scan_start`'s allowlist re-check). Before spawning a child, `attack_run` re-reads the `Target` and asserts it belongs to `Job.project_id` and is `available`; recomputes the sha256 of the fetched model bytes and compares with the manifest; re-validates the campaign configuration with its Pydantic model (`resolve_params` again, so a stale client cannot widen a bound); asserts the dataset id and revision hash match what the audit row recorded; and re-emits `authorize("attack.execute.<attack_id>", target=None, ...)` with `run_id` so the run chain carries the executed configuration. Any mismatch is a terminal failure with a typed error (section 9.5), never a corrected run. The worker's DB session is system-scoped (`app.current_tenants` unset); it touches only rows reachable from its `Job`.

### 10.5 Audit events for D4(c)

Every upload, validation, attack, explanation, hardening pass, and verification appends to the hash-chained log; `aegis audit verify --run <run_id>` proves the campaign trail (S1 §13, §15 step 6). The action vocabulary and `detail` contents are fixed in section 5.11; this subsection fixes the emission order per task. Actions are ≤ 64 characters, `detail` is redacted at write time, and no row carries model bytes, images, dataset rows, prompt text, or secrets — only digests, counts, ids, and blob references (the forensic `tool_detail` convention: digests + refs, not raw bytes).

| Task | Emits, in order |
|---|---|
| API admission (any ML route) | the admission action (`model.register`, `attack.run`, `explain.run`, `harden.recommend`, `verify.replay`, `run.cancel`, `finding.review`, `finding.annotate`, `target.manage`) on the project chain (or the run chain when the run already exists) — **before** any `Run`/`Job` row and before `task.delay` |
| `model.validate` | `model.validate` (from the child's outcome), `job.complete` |
| `attack.run` | `model.load`, `attack.execute.<attack_id>` (before the child runs the attack), `job.complete` |
| `explain.run` | `model.load`, `explain.execute`, `campaign.score` (when the `MRIRecord` is written), `job.complete` |
| `harden.recommend` | `harden.execute` (rules fired, narrative outcome, Pythia settings redacted, prompt/completion digests, token counts), `report.render`, `job.complete` |
| `verify.replay` | `model.load`, `attack.execute.<attack_id>` per attack, `explain.execute`, `campaign.score`, `verify.execute`, `job.complete` |

Offline (`aegis ml attack`, CI): the same `authorize()` calls resolve to `JsonlAuditWriter` at `<run_path>/audit.jsonl` (D4(c): "Postgres-backed, JSONL offline"); `verify_chain` walks either.

### 10.6 Failure, retry, timeout

- **Transient** (`ConnectionError`, `TimeoutError`, SQLAlchemy `OperationalError`/`InterfaceError`) with retries remaining (`max_retries=2`, delay 10 s): `task_context` rolls the body back, resets the row `running → queued`, and `task.retry()`s; the redelivery guard lets the retry run. A stage child that had completed is not re-run: the work dir is keyed by `job_id` and the envelope is re-read if present.
- **Terminal** (any `aegis.ml.errors` class, envelope validation failure, digest mismatch): row `running → failed`, `Job.error` = class name + operator-safe message + traceback, `completed_at` set, `failed` event published, downstream chain jobs cancelled (10.3). A retry from the UI is a **new linked run** (`ml_campaigns.parent_run_id`, section 5.6) with current approvals re-checked; F004 FR-008 — the original is never edited.
- **Timeout.** Sandbox wall clock (`AEGIS_ML_SANDBOX_TIMEOUT_S`, per stage) → `SandboxTimeout`, process group killed, files written so far recorded under `ml/partial/…`, stage `timed_out`, completeness `partial`. Celery soft/hard limits (1800/2100 s) are the outer fence; the reaper (TTL 3600 s, every 300 s) is the backstop for a worker that died without reaching the failure path.
- **Redelivery.** `task_acks_late=True` and `worker_prefetch_multiplier=1`: a job whose worker died is redelivered; `task_context` skips any job not in `queued` (fail-closed), so a crashed, cancelled, or already-terminal job never re-fires an attack.
- **Failure classes are not model outcomes.** `ModelLoadRefused`, `SandboxTimeout`, `SandboxKilled`, `ArtifactDigestMismatch`, `DatasetUnavailable`, `MlExtraUnavailable`, `EnvelopeInvalid`, `ExplainerUnavailable` (SHAP failed for a target; attack measurements stand, `S_expl` not computed) are rendered as run/infrastructure states in the UI and reports, separate from clean/adversarial/control accuracy (section 14, section 18).
- **Request-level idempotency** (F004 US1's duplicate request identity) is Phase B; Phase A relies on the worker redelivery guard and the UI disabling the launch control while a request is in flight (sections 6.3, 17.3).

### 10.7 Cancel semantics

`POST /v1/runs/{id}/cancel` → `check(RUN_CANCEL)` → `cancel_run`: audit `run.cancel` first; `Run.status=cancelled`, `completed_at`; every `queued`/`running` job of the run → `cancelled` through `set_job_status`; best-effort `app.control.revoke(celery_task_id, terminate=True)` when the id is recorded. Two additions make this work for a task whose real work is in a sandbox child:

1. **Cooperative kill.** The ML tasks do not block in `proc.communicate()`. The parent waits on the child in a loop (5 s interval) that re-reads `Job.status` in a fresh session; on `cancelled` it SIGKILLs the child's process group, discards the partial envelope, records already-completed stage files under `ml/partial/…`, writes `stage_table` status `cancelled` for the stage, and returns. Celery's revoke is an accelerator, not the mechanism.
2. **Terminal rows are not overwritten.** `task_context` gains two small changes: it stamps `job.celery_task_id = task.request.id` on pickup when a bound task is supplied (so `cancel_run`'s revoke can reach a running task), and on the success and failure paths it refreshes the row and leaves an already-terminal (`cancelled`) status untouched instead of writing `succeeded`/`failed` over it — the machine in `job_state.py` already forbids `cancelled → *`; this makes the wrapper honour it instead of raising inside its own `except`.

Racing completion (S3 run-state contract): if the worker's `job.complete` row precedes the `run.cancel` row on the chain, the job stands as `succeeded` and the cancel affects only later jobs; otherwise the job is `cancelled` and any evidence persisted before the kill is labelled partial by `stage_table`. The two chained rows are the retained ordering record. A cancelled run is terminal; "retry" creates a new linked run (10.6). A cancel on an already-terminal run returns `409` (section 6.3).

### 10.8 The LLM writer's place in the flow (D5)

`harden.recommend` is the only task that leaves the boundary, and it never touches model bytes (it runs on the `default` pool, whose processes never load a model):

1. `aegis.llm.router.route("ml.harden_narrative", config, project_id=..., org_id=..., budget_checker=DbBudgetChecker())` is the policy layer: `Organization.llm_model_overrides["ml.harden_narrative"]` wins, else `config.task_models["ml.harden_narrative"]` seeded from `AEGIS_ML_LLM_MODEL`; the project daily cap and org monthly cap are enforced (`BudgetExceeded`; with `llm_budget_strict`, an unverifiable budget denies). The resolved id must be a Pythia canonical `<vendor>/<model>` or `pythia/auto`; `AegisConfig.model`'s provider-style default is not used for this task.
2. `aegis.llm.pythia.chat_text(settings, system, user)` is the transport: one non-streaming `POST {PYTHIA_BASE_URL}/v1/chat/completions` with `Authorization: Bearer pk_…`, optional `X-Pythia-Persona`, `temperature=0.2`, `max_tokens=800`, timeout `PYTHIA_TIMEOUT_S` (60 s); `pythia_sdk.PythiaClient` when importable, otherwise the in-repo `httpx` client. No tools, vision, or structured output; no litellm; no provider keys.
3. Input is the rule-layer output, the measurement table with denominators, the scorecard numbers, the limitations and the SHAP text summary (`ml.shap.summary_text`) — text only (section 16.3). `guard_input` (injection detection) and `guard_output`/`filter_output` (secret scrub) from `aegis.llm.guardrails` wrap the call; the prompt and completion are stored as `Artifact` rows (`ml.harden.prompt`, `ml.harden.completion`) and their digests go on the `harden.execute` audit row; a `LLMUsage(task="ml.harden_narrative")` row records tokens and cost (zero with `unpriced_model` noted when the canonical id is not in `aegis/llm/pricing.py`).
4. Any failure — `PythiaUnavailable` (env unset), `AEGIS_DISABLE_LLM=1` (already set on the compose worker pools; section 20 adds `PYTHIA_*` where the writer should run), `BudgetExceeded`, HTTP error, guardrail block, post-check rejection, malformed response — leaves the deterministic rule output in place with `narrative_source="rules"` and the skip reason recorded; it never fails the job and never invents prose. When it succeeds, `narrative_source="llm"` and the UI labels the text "LLM-generated narrative of rule outputs" (section 16, section 18). The writer may not introduce claims absent from the rule outputs, and it never receives images, model data, or dataset rows.

## 11. Datasets and data handling

### 11.1 Rule

Every dataset the tool ships, downloads, or evaluates on is **open, unclassified, publicly available, and carries a license stated on its distribution page** (D3). Nothing else is admitted in Phase A: there is no dataset upload path (uploaded models under D2 are evaluated on the bundled datasets only, after the compatibility check in section 5), no connection to any operational, sensitive, or mission data source, and no synthetic-data generator beyond the test doubles in section 22. The tool evaluates and hardens the robustness of a classifier on these datasets; it never trains, optimizes, or deploys a targeting or weapons model, and it connects to no mission system. D3's choice of military-vehicle imagery knowingly diverges from the non-operational wording of the brief and of constitution Principle II; the divergence, its bounds, and its status as a team decision pending named approval are recorded in the reconciliation table (section 4), the decision register entry D001 (D11), and constitution amendment proposal (a) (D12). Section 21 carries the security consequences.

Two further rules apply to every dataset below:

- **No fixture data is ever presented as results.** CIFAR-10, the committed stratified sample of the malicious-URLs dataset (11.3.3), Spambase-as-fixture, and the `TinyTarget` / `TinyTabularTarget` synthetic doubles exist so that tests and CI run offline and deterministically. They never appear in the demo catalog as evaluated targets, never populate a `Finding`, and never appear on `/runs/[id]` or `/findings/[id]` as evidence (constitution Principle III; William's readiness checklist; sections 14, 18, 22).
- **Dataset identity travels with every run.** The dataset id, the resolved revision (the HuggingFace commit sha for hub datasets; the sha256 of the source file for the Kaggle-sourced tabular dataset), the split, the evaluation-slice indices, and the preprocessing are recorded in the asset manifest at build time and copied into the run's `Provenance` (section 5, section 14). Two campaigns on different datasets — or the same dataset at different revisions — are never compared (D9(i)).

### 11.2 Dataset roles

| Role | Dataset | Modality | Why this one |
|---|---|---|---|
| Demo image dataset (D3, Phase A step 1 of the D8 order) | `leibnitz-lab/military_vehicles`, **coarse 7-class task** | image | Only candidate that is classification-ready, MIT-licensed on its card, academically citable, small enough to bundle, and on-topic. |
| Fallback image dataset (aircraft-type side of D3) | `Illia56/Military-Aircraft-Detection`, `crop/` folder | image | Classification-ready and balanced, but a weaker license chain; used only if the primary cannot be built on the day, and then on an 8–10 class subset. |
| Demo tabular dataset (D4(d), step 4 of the D8 order) | Kaggle `sid321axn/malicious-urls-dataset` (`malicious_phish.csv`) | tabular | Owner decision 2026-09-08: a security-domain task (URL maliciousness), "CC0: Public Domain" as stated by Kaggle, 651,191 rows in one 45.7 MB CSV, four classes; lexical features give an all-continuous perturbable feature set. Needs a Kaggle API token at build time only (11.3.3). |
| Fallback tabular dataset | `lacg030175/UNSW-NB15`, config `standard` | tabular | Demoted from primary on 2026-09-08. Clear license tag, official temporal split, right-sized parquet, reachable without credentials; used only if the Kaggle download cannot be completed on the day (11.3.4). |
| CI tabular fixture (URL pipeline) | `tests/ml/fixtures/malicious_urls_sample.csv` — a committed, seeded, stratified sample of a few hundred rows of the primary | tabular | CC0 permits committing it; tests of the lexical feature extractor, the URL classifier loader and the tabular attack / explain path run offline and never touch Kaggle (11.3.3, section 22). |
| CI tabular fixture (all-continuous features) and second fallback | `mstz/spambase` (UCI Spambase) | tabular | All-continuous features (clean ε semantics), clearest license chain, 1.1 MB (11.3.6). |
| CI / fixture image dataset (D3) | `uoft-cs/cifar10`, test split, pinned 500-image subset | image | Tiny, deterministic, matches ART examples and the `TinyTarget` shapes. Never the demo dataset. |
| Unit-test double | `TinyTarget` (`tests/ml/fakes.py`): random-weight 1-conv net, 8×8×3 inputs, 3 synthetic classes | image | No data download at all; exercises the `Target` and `AttackAdapter` protocols (section 22). |

The bundled models that sit on top of these datasets (a CNN on the coarse vehicle task; the URL maliciousness classifier — a scikit-learn RandomForest or XGBoost tree ensemble on the lexical URL features of 11.3.3, trained by the asset script, with its build-time PGD surrogate; and the CIFAR-10 small CNN kept for CI only) are described in section 9; their clean accuracy, architecture, training recipe, seed, and weight sha256 are **recorded in the asset manifest at build time** and are never written into this document or the UI as constants.

### 11.3 Accepted datasets

All reachability facts were verified on 2026-09-08 from the hackathon network against the HuggingFace hub and, for 11.3.3, the Kaggle dataset metadata API. "Reachable" means an HTTP 200 on the named URL through the corporate proxy.

#### 11.3.1 `leibnitz-lab/military_vehicles` — demo image dataset

| Property | Value |
|---|---|
| Source | HuggingFace Hub, `imagefolder` layout. Companion dataset to Kricheli et al. 2024, arXiv:2407.15192 ("Error Detection and Constraint Recovery in Hierarchical Multi-Label Classification without Prior Knowledge"). `haffnerj/military_vehicles` is a byte-identical re-upload (same 18,915 files, same MIT card); the original is used. |
| License | MIT, declared in the dataset card and the HF license tag. The declaration covers the compilation and the labels; see 11.5 for what it does not cover. |
| Gated | No. |
| Task | Image classification, hierarchical: 7 coarse classes and 24 fine classes. Ground-level photographs of Soviet/Russian-pattern armoured vehicles and air-defence systems. |
| Size | 18,915 files. Coarse: train 7,823 / test 1,621 JPEGs. Fine: train ~7,840 / test 1,621 (same images, relabelled). |
| Coarse classes (7) | Air Defense, BMD, BMP, BTR, MT_LB, Self Propelled Artillery, Tank. |
| Fine classes (24) | 2S19_MSTA, 30N6E, BM-30, BMD, BMP-1, BMP-2, BMP-T15, BRDM, BTR-60, BTR-70, BTR-80, D-30, Iskander, MT_LB, Pantsir-S1, Rs-24, T-14, T-62, T-64, T-72, T-80, T-90, TOS-1, Tornado. |
| Per-class coarse **test** counts (n) | Air Defense 283 · BMD 89 · BMP 176 · BTR 340 · MT_LB 87 · Self Propelled Artillery 333 · Tank 313 (sum 1,621). Fine test counts range from 21 (30N6E) to 161 (BTR-60). |
| Class imbalance | Train: Tank 2,005 vs BMD 322. Every per-family table shows per-class `n` (section 14). |
| Format | JPEG, RGB, variable size at web-thumbnail scale (sampled file 259×194; the bundled provenance sheet lists 250×172 to 600×450). |
| Reachable | Yes. `https://huggingface.co/datasets/leibnitz-lab/military_vehicles/resolve/main/test_coarse/Air%20Defense/0977.jpg` → HTTP 200, 14,449 bytes, `image/jpeg`. |
| Load path (build time, worker or asset CLI only) | `snapshot_download("leibnitz-lab/military_vehicles", repo_type="dataset", revision=<pinned sha>, allow_patterns=["train_coarse/*", "test_coarse/*"])` then `datasets.load_dataset("imagefolder", data_dir=<path>)`. Four top-level split directories exist (`train_coarse/`, `test_coarse/`, `train_fine/`, `test_fine/`), one subdirectory per class; `load_dataset("leibnitz-lab/military_vehicles")` also auto-detects the imagefolder layout. Only the coarse directories are fetched in Phase A. |
| Evaluation split | `test_coarse` (1,621 images). `train_coarse` is used only at build time to train the bundled CNN and is not shipped to the worker image. |
| Preprocessing (fixed at build time, recorded in the manifest) | Resize the shorter side to the manifest resolution and center-crop to a square; convert to float32 in [0, 1], NCHW, no mean/std normalisation outside the model (so ε is a fraction of the [0, 1] pixel range, section 12.3). The demo build targets 128×128 to keep FGSM/PGD sweeps and `GradientExplainer` within CPU budgets; 224×224 is permitted for uploaded models whose manifest declares it. |
| Phase A use | The 7-class coarse task is the bundled classifier's task and the ε-sweep demo. The 24-class fine task is a stretch that needs no new download. |

Caveats that become campaign limitations (section 14) whenever this dataset is used:

1. These are **ground-level photographs, not aerial or overhead imagery**. D3's phrase "aerial-target / military-vehicle" is satisfied on the vehicle side only; the only true overhead candidate found (xView) was rejected (11.4).
2. **Photo copyright is not cleared by the MIT tag.** The bundled `WEO_Data_Sheet.xlsx` (Training sheet, `Source` column) records that images were collected from Roboflow (code 1), armyrecognition.com (code 2), and "another website" (code 0). The dataset authors' MIT declaration covers their compilation and labels. The demo is internal and non-commercial; the images are not redistributed in any public release of this repository or its reports without further review (11.5).
3. The card is a bare citation with no split protocol or de-duplication statement. Train/test are taken as given; near-duplicates across splits are possible and are listed as a limitation.
4. Images may incidentally contain people. The tool performs no person or face recognition, no such labels exist in the data, and none are derived.
5. Subjects are not reliably centred or tightly framed, which weakens the centre-mass heuristic of section 13.4 on this dataset more than on CIFAR-10; the heuristic stays labelled heuristic and carries this note.

#### 11.3.2 `Illia56/Military-Aircraft-Detection` — fallback image dataset

| Property | Value |
|---|---|
| Source | HuggingFace Hub, `imagefolder`. A 4,300-image crop subset (100 crops × 43 types) plus 100 full images and 40 annotated samples, derived from the Kaggle "Military Aircraft Detection Dataset" (uploader `a2015003713`). |
| License | Apache-2.0, declared on the HF card **by the re-uploader**. The upstream HF mirror `a2015003713/military-aircraft-detection-dataset` (50,067 files) declares no license, and the upstream Kaggle license could not be verified from this network. |
| Gated | No. |
| Task | Object detection upstream (PASCAL VOC XML boxes); the `crop/` folder is directly usable as 43-class image classification (one directory per type, 100 crops each). |
| Size | 4,443 files: `crop/` 4,300 (43 × 100), `dataset/` 100 full images, `annotated_samples/` 40, plus README and a "memo" file. |
| Classes (43) | A10, A400M, AG600, AV8B, B1, B2, B52, Be200, C130, C17, C2, C5, E2, E7, EF2000, F117, F14, F15, F16, F18, F22, F35, F4, J20, JAS39, MQ9, Mig31, Mirage2000, P3, RQ4, Rafale, SR71, Su34, Su57, Tornado, Tu160, Tu95, U2, US2, V22, Vulcan, XB70, YF23. |
| Format | JPEG bounding-box crops of variable size from web photographs; resized to a fixed input at build time. Filenames are content hashes with a `_<n>` suffix, not sequential. |
| Reachable | Yes. `https://huggingface.co/datasets/Illia56/Military-Aircraft-Detection/resolve/main/crop/A10/01ed4d81c5d733cbaa266b6ea7821254_0.jpg` → HTTP 200, 32,871 bytes, `image/jpeg`. |
| Load path | `snapshot_download("Illia56/Military-Aircraft-Detection", repo_type="dataset", revision=<pinned sha>, allow_patterns=["crop/*"])` then `load_dataset("imagefolder", data_dir=<path>/crop)`. No train/test split is provided: the build makes a seeded stratified split and records the seed and the resulting indices in the manifest. |
| Phase A use | Fallback only. If used: restrict to an 8–10 class subset (for example fighters / bombers / transports / UAVs), use a pretrained backbone with a linear head rather than training from scratch (100 images per class is thin), and carry the license caveat below. |

Caveats: web-scraped airshow/spotter photographs, not overhead imagery; photographer copyright is not cleared by the Apache-2.0 tag; the README warns of possible wrong labels and duplicate images; the full `a2015003713` mirror is not used (no license). Any campaign on this dataset states the license caveat in its limitations and the data policy (11.5).

#### 11.3.3 Kaggle `sid321axn/malicious-urls-dataset` — demo tabular dataset (D4(d))

| Property | Value |
|---|---|
| Source | Kaggle, `https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset` (owner Manu Siddhartha; title "Malicious URLs dataset"). One file, `malicious_phish.csv`, columns `url`, `type`. Compiled by the uploader from ISCX-URL-2016, PhishTank, the Malware Domain Blacklist, faizann24's phishing-URL set and a Kaggle "URL dataset" (2021); the upstream sources are recorded for provenance and are never re-fetched. |
| License | **"CC0: Public Domain"** — the `licenseName` returned by Kaggle's dataset metadata API (`https://www.kaggle.com/api/v1/datasets/view/sid321axn/malicious-urls-dataset`), which answers unauthenticated; the dataset's HTML page returns 404 to non-browser clients, so the API response is the recorded evidence (verified 2026-09-08, re-confirmed the same day). The declaration is the uploader's statement over the compilation; 11.5 records what it does not settle. |
| Gated | Metadata: no. **Download: yes** — the Kaggle API requires an account token (`KAGGLE_USERNAME` / `KAGGLE_KEY`). No token exists on the build machine as of 2026-09-08; the operator who runs `aegis ml build-assets` supplies one for that run only (section 20.3). |
| Task | Tabular classification of a URL string into four classes: `benign`, `defacement`, `phishing`, `malware` (column `type`). Phase A campaigns use the 4-way task; the per-class table (section 14.2) is where the benign / malicious split is read. |
| Size | 651,191 rows × 2 columns; 45,664,439 bytes (Kaggle `totalBytes`; last updated 2021-07-23). Benign is the majority class (about two thirds); **exact per-class counts are recorded at asset-build time**, not asserted here. |
| Class imbalance | Material (benign ≈ 2/3). The evaluation slice is stratified with equal allocation per class (11.5), and every per-family table shows per-class `n` (section 14). |
| Format | CSV, two string columns. No predefined split: the build de-duplicates exact-duplicate URL strings (count recorded), then makes a seeded stratified train / evaluation split (build default: 20 % held out; seed and resulting indices recorded in the manifest). |
| Reachable | Metadata API: HTTP 200 unauthenticated from the hackathon network (2026-09-08). File download: not exercised from the build machine (no token). The HuggingFace hub holds only **partial** mirrors — `joshtobin/malicious_urls` (< 1K rows) and `JorgeGMM/malicious_urls` (10K–100K rows); neither is the full table, and neither is used unless its license is confirmed, and then only as a fallback fixture, never as the demo dataset (11.4). |
| Load path (build time, asset CLI only) | `aegis ml build-assets` reads `KAGGLE_USERNAME` and `KAGGLE_KEY` from its own environment, performs one authenticated `GET https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset/malicious_phish.csv` (HTTP basic auth; redirects followed; a zip-wrapped response is unpacked) with the `httpx` client already in the `ml` extra, computes the sha256 of `malicious_phish.csv`, stores the file under `ml/assets/kaggle--sid321axn--malicious-urls-dataset/<sha256>/` in the blob store, and records `dataset_id = "kaggle:sid321axn/malicious-urls-dataset"`, `dataset_revision = <file sha256>`, byte count and row count in `MANIFEST.json`. A run refuses to start if the stored file's sha256 differs from the manifest (`DatasetUnavailable`, section 9.5). **CI never touches Kaggle**: `tests/ml/fixtures/malicious_urls_sample.csv` is a committed, seeded, stratified sample of a few hundred rows with a sidecar manifest entry (source id, source-file sha256, row indices, sample sha256). |
| Feature engineering (tabular target) | The bundled **URL maliciousness classifier** is a scikit-learn RandomForest or XGBoost tree ensemble trained by the asset script on lexical features computed from the URL string alone: `url_length`, `digit_ratio`, `letter_ratio`, `count_dot`, `count_hyphen`, `count_at`, `count_question`, `count_percent`, `count_equals`, `subdomain_count`, `path_depth`, `has_ip_host`, `is_shortener`, `is_https`, `suspicious_tld`, `shannon_entropy`. The extractor (`aegis/ml/datasets/url_features.py`) is a pure string function: no DNS, no HTTP, no rendering, no third-party enrichment. Feature names, dtypes, training-split ranges and `perturbable` flags go into `MLModelManifest.features` (section 5.5); the model's clean metrics are recorded in the asset manifest at build time. |
| Evaluation split | The seeded held-out split above, bundled to the blob store; the training split is used only at build time (model, PGD surrogate, per-feature ranges). |
| Phase A use | Bundled URL maliciousness classifier; `TreeExplainer` bar / beeswarm on the lexical features (section 13); PGD by surrogate transfer on the declared continuous features with per-feature-scaled ε and post-attack rounding of integer features; HopSkipJump as the black-box attack (sections 12.2, 12.9). |

Caveats that become campaign limitations (section 14) whenever this dataset is used:

1. **URL strings are data.** The pipeline never fetches, resolves (DNS), or renders any URL from the dataset — not in the worker, the sandbox child, the UI or the reports; only lexical features are computed, and a URL string that is displayed (the clean row in pane 1, section 18.4) is escaped, non-clickable text labelled as dataset content. The sandbox child has no network configuration in any case (section 9.4).
2. **Realizability gap.** Feature-space perturbations (PGD on continuous features with rounding; HopSkipJump) are evidence about the classifier's decision surface. They count as a realizable attack only if the perturbed feature vector maps back to a constructible URL that yields exactly those features; Phase A does not construct URLs and does not check this, so no tabular row is presented as demonstrated URL evasion (section 12.9).
3. **Label noise.** Labels come from several blacklists and feeds merged by the uploader without a documented adjudication step; disagreement between sources cannot be recovered from the file.
4. **Dataset age.** Compiled in 2021; phishing and malware-distribution URL patterns drift, so results describe this snapshot, not current traffic.
5. **Class imbalance** (benign ≈ 2/3): minority-class per-class counts are small at the default `n_samples`; per-class `n` is always shown.
6. **Access.** Download requires a personal Kaggle token, used once by the asset build and never present on the API, web or steady-state worker containers (section 20.3).

#### 11.3.4 `lacg030175/UNSW-NB15` (config `standard`) — fallback tabular dataset

| Property | Value |
|---|---|
| Source | HuggingFace Hub, parquet. Re-packaging of the UNSW Canberra Cyber UNSW-NB15 network-intrusion dataset (Moustafa & Slay, 2015). Config `standard` (also called `temporal`) is the official `UNSW_NB15_training-set.csv` / `UNSW_NB15_testing-set.csv` split; config `random` is a de-duplicated 80/20 split of all 2.28 M records via `Mouwiya/UNSW-NB15` and is **not** used. |
| License | CC-BY-4.0 declared on the HF card (uploader's declaration; upstream UNSW terms are "free for academic research"). Clearer than the GPL-3.0 (`Mireu-Lab`), "other", or untagged mirrors, all of which are rejected. |
| Gated | No. |
| Task | Tabular classification: binary `label` (0 normal / 1 attack) and 10-way `attack_cat`. Phase A campaigns use the binary task; `attack_cat` is reported per class as context. |
| Size | Standard split: train 175,341 rows / test 82,332 rows, 44 features (all official features except `id`). Parquet: `standard/train` 12,773,520 bytes, `standard/test` 6,280,567 bytes (≈19 MB total). |
| Classes | `attack_cat` (10): Normal, Exploits, DoS, Fuzzers, Generic, Reconnaissance, Worms, Shellcode, Backdoor, Analysis. Binary `label`: 0 / 1. The uploader's README reports RF 87.2 % / XGBoost 87.3 % on the standard split — **uploader-reported and illustrative; not a measurement made by this tool**. |
| Format | Parquet. Categorical columns `proto`, `service`, `state` must be encoded before any attack; the fitted encoder (category vocabularies, unknown-category handling) is stored beside the model and recorded in the manifest. The standard-split feature set carries no IP addresses. |
| Reachable | Yes. HTTP 200 on `https://huggingface.co/datasets/lacg030175/UNSW-NB15/resolve/main/standard/train-00000-of-00001.parquet` and `.../standard/test-00000-of-00001.parquet`. |
| Load path | `load_dataset("lacg030175/UNSW-NB15", "standard", revision=<pinned sha>)` → `ds["train"]`, `ds["test"]`. The build bundles the full standard **test** split to the blob store as the evaluation split; the train split is used only at build time (model, surrogate, encoder, per-feature ranges). |
| Phase A use | **Fallback only** (demoted 2026-09-08 in favour of 11.3.3). If the Kaggle download cannot be completed on the day: bundled sklearn RandomForest or XGBoost target, `TreeExplainer` bar/beeswarm, PGD on a declared set of continuous features with per-feature-scaled ε (section 12.9), HopSkipJump as the black-box attack. Campaign settings name the split (`standard`) explicitly and the campaign carries the note that it ran on the fallback dataset. |

Caveats that become campaign limitations if the fallback is used: uploader-declared CC-BY-4.0 over data whose upstream terms are academic-research use (fine for the internal demo; recorded in the data policy); mixed categorical/numeric features make L∞ ε semantics awkward, so perturbation is restricted to declared continuous features with per-feature scaling (section 12.9) and this is stated as a limitation; about 30 % duplicates exist in the full data per the README, which is why the standard split is used; it is not CIC-IDS2017 and no MRI is compared across the two (D9(i)).

#### 11.3.5 `uoft-cs/cifar10` — CI / fixture image dataset

| Property | Value |
|---|---|
| Source | HuggingFace Hub canonical CIFAR-10 mirror, parquet. Original: Krizhevsky, Nair, Hinton, University of Toronto. |
| License | "unknown" on the HF card. CIFAR-10 has no formal license statement and is universally redistributed for research (ART and torchvision test suites included). Acceptable for a test fixture that is never presented as results. |
| Gated | No. |
| Task | Image classification, 10 classes, 32×32 RGB: airplane, automobile, bird, cat, deer, dog, frog, horse, ship, truck. |
| Size | Train 50,000 / test 10,000. Parquet: `plain_text/train-00000-of-00001.parquet` ≈113 MB, `plain_text/test-00000-of-00001.parquet` 23,940,850 bytes. Features: `img` (Image), `label` (ClassLabel). |
| Reachable | HF parquet: yes — `https://huggingface.co/datasets/uoft-cs/cifar10/resolve/main/plain_text/test-00000-of-00001.parquet` → HTTP 200. **torchvision's default download host (`cs.toronto.edu`) is not reachable through the corporate proxy**; torchvision is a fallback for networks where that host is reachable and is never the default path. |
| Load path | `load_dataset("uoft-cs/cifar10", split="test", revision=<pinned sha>)`. For CI the build pins a deterministic subset — 50 images per class chosen by a seeded (seed 0) stratified selection over the test split, 500 images total — and caches it in the repository as `tests/ml/fixtures/cifar10_test_500.npz` (uint8, ≈1.5 MB) with its sha256 and the source indices in `tests/ml/fixtures/MANIFEST.json`, so CI needs no network. |
| Phase A use | CI fixture only (D3). The CIFAR-10 small CNN from the lean design (S2 §2.2) remains the CI target model; it is not listed in the demo catalog. |

#### 11.3.6 `mstz/spambase` — CI tabular fixture and second fallback

| Property | Value |
|---|---|
| Source | HuggingFace Hub, CSV. UCI ML Repository "Spambase" (Hopkins, Reeber, Forman, Suermondt; HP Labs, 1999). |
| License | "cc" on the HF card; the UCI repository lists Spambase under CC BY 4.0 — the clearest license chain of any tabular candidate. |
| Gated | No. |
| Task | Binary tabular classification, `1` = spam / `0` = not spam (column values verified). |
| Size | 4,601 rows × 58 columns (57 continuous features + class). Single file `spambase/train.csv`, 1,125,726 bytes (4,602 lines including header, downloaded and verified). No predefined split: the build makes a seeded stratified split and records the seed. |
| Features | 48 `word_freq_*`, 6 `char_freq_*`, `capital_run_length_average` / `_longest` / `_total`. All continuous, so L∞ / L2 ε semantics need no categorical encoding. |
| Reachable | Yes. `load_dataset("mstz/spambase")["train"]` or `pandas.read_csv("https://huggingface.co/datasets/mstz/spambase/resolve/main/spambase/train.csv")`, HTTP 200. |
| Phase A use | (a) CI tabular fixture for the all-continuous ε semantics: the full CSV is vendored into `tests/ml/fixtures/` with attribution (CC BY 4.0 permits it), so generic tabular attack, explainer, and rule tests run offline beside the committed URL sample of 11.3.3; it is never shown as results. (b) Second fallback for the tabular demo, only if neither 11.3.3 nor 11.3.4 can be built on the day, in which case the campaign carries the note that it ran on a fallback dataset. |

Caveat: 1999-era email features and a less compelling security narrative than URL maliciousness or network intrusion; no official train/test split.

### 11.4 Rejected candidates and Phase B options

| Candidate | Reason rejected | Phase B option |
|---|---|---|
| `HichTala/xview` (DIUx xView 2018 mirror) | No license on the mirror; upstream is CC BY-NC-SA 4.0 with click-through DIUx terms; detection task (60 classes) that would need object chipping to become classification; ≈884 MB. Not reachability-checked because it was rejected first. | The only true overhead-imagery candidate found. Phase B only if licensing is resolved with DIUx. |
| `a2015003713/military-aircraft-detection-dataset` | No license on the HF mirror; web-scraped copyrighted photo dump (50,067 files). | None; use the `Illia56` licensed subset if aircraft imagery is needed. |
| `stableapuppy/MSTAR-Training`, `yixu1/Mix_MSTAR`, `Ca111/WST_DRFSL_MSTAR` | `stableapuppy` is Apache-2.0 but is **not MSTAR SAR data at all** (SynthText / TextCaps / MLT text-recognition zips). `yixu1` and `Ca111` declare no license, are single opaque zips with no card, and have 20–27 downloads. The AFRL SDMS origin is not reachable through the proxy. | MSTAR (canonical 10 classes, 128×128 single-channel SAR chips) would be the best sensor-view fit. Phase B only with the public-release files obtained directly from AFRL SDMS with their terms attached. |
| `Alex5666/Military-Aircraft-Recognition-dataset` | Detection-annotation dump (VOC XML), 304 files, no classification layout. | Superseded by `Illia56` crops. |
| `rdpahalavan/UNSW-NB15` | Packet-level re-extraction; `Network-Flows/UNSW_Flow.parquet` alone is 183,375,358 bytes, packet-level files run to hundreds of MB and 100 M–1 B rows; intended access is via the `nids-datasets` pip package. Apache-2.0, reachable, but far too large to bundle. | None; `lacg030175/UNSW-NB15` standard has the same labels at the right size. |
| `Mireu-Lab` NSL-KDD / UNSW mirrors; CIC-IDS2017 mirrors | GPL-3.0 on data, or "other" / untagged / non-commercial tags. | None. |
| `joshtobin/malicious_urls`, `JorgeGMM/malicious_urls` (HF) | Partial mirrors of the Kaggle malicious-URLs table (< 1K and 10K–100K rows respectively); neither is the full 651,191-row file, and their license fields were not confirmed. | Fallback **fixture** only, never the demo dataset, and only if a license is confirmed; the committed stratified sample of 11.3.3 already covers CI. |

### 11.5 Licensing and data policy

| Dataset | License as declared | What the declaration covers | Policy adopted |
|---|---|---|---|
| `leibnitz-lab/military_vehicles` | MIT (card + tag) | The authors' compilation and labels. Not the photographers' copyright (sources: Roboflow, armyrecognition.com, other sites per `WEO_Data_Sheet.xlsx`). | Internal, non-commercial demo of a robustness tool. Images are stored in the team's blob store and shown in the UI and in run artifacts; they are not committed to the repository and not redistributed in any public release or public report without further review. Reports exported outside the team carry metrics and SHAP renderings only if the reviewer confirms image redistribution is acceptable (export redaction policy is D006, OPEN). |
| `Illia56/Military-Aircraft-Detection` | Apache-2.0 (card, by re-uploader) | The re-uploader's compilation; upstream mirror has no license; photographer copyright not cleared. | Fallback only; same internal-demo handling as above with the license caveat stated in every campaign's limitations. |
| Kaggle `sid321axn/malicious-urls-dataset` | "CC0: Public Domain" (Kaggle metadata API `licenseName`) | The uploader's compilation. The feeds it was compiled from (ISCX-URL-2016, PhishTank, Malware Domain Blacklist, faizann24, a Kaggle "URL dataset") carry their own terms, which this tool does not engage because it never re-fetches them. | Fetched once at build time with the operator's Kaggle token; stored in the blob store with its sha256 as `dataset_revision`; a stratified sample of a few hundred rows is committed to `tests/ml/fixtures/` with attribution (CC0 permits it). URL strings are inert data (11.3.3 caveat 1): never fetched, resolved or rendered as links; reports escape them. |
| `lacg030175/UNSW-NB15` | CC-BY-4.0 (card, by uploader) | Uploader's packaging; upstream UNSW terms are academic-research use. | Fallback only; internal demo; attribution to UNSW Canberra Cyber (Moustafa & Slay 2015) in the manifest and reports. |
| `mstz/spambase` | "cc" (card); CC BY 4.0 at UCI | The dataset. | CI fixture and second fallback; vendored into `tests/ml/fixtures/` with attribution. |
| `uoft-cs/cifar10` | "unknown" (card) | No formal statement exists. | Test fixture only; never presented as results. Pinned 500-image subset vendored for CI. |

Handling rules common to all:

- **Where data lives.** Dataset bytes are fetched once at build time by `aegis ml build-assets` (`aegis/cli/ml.py`, the successor of the lean design's `redsim/setup_assets.py`, D7) — hub datasets with `revision=` pinned, the Kaggle tabular dataset through the authenticated download of 11.3.3 with `KAGGLE_USERNAME` / `KAGGLE_KEY` read for that run only and never written anywhere — written to the blob store (`aegis/storage/blobs.py`; `AEGIS_BLOB_BACKEND=s3` for MinIO/S3) under `ml/assets/<dataset_id>/<revision>/`, and read only by the Celery worker (section 10). The API and web containers never hold dataset bytes (section 8, section 20). The asset seeding step of S1 §12 ("seed sample models and datasets into S3 on first deploy") is this CLI.
- **Manifest contents** (`MANIFEST.json`, written by the build, copied into `Provenance.model_manifest` and `TargetInfo.metadata`): dataset id; resolved revision (HF commit sha, or the source-file sha256 for the Kaggle dataset); license string as declared and the coverage caveat above; split name; total `n` and per-class `n` for the evaluation split; preprocessing (resize/crop rule, resolution, channel order, value range; for tabular: the lexical feature list and extractor version for the URL classifier or the encoder vocabularies for the fallback, declared perturbable features, per-feature min/max on the training split); the split seed for datasets without an official split; the bundled model's architecture, training recipe, seed, weight sha256, and clean accuracy on the full evaluation split; for tabular tree ensembles the build-time surrogate (kind, sha256, agreement with the target on the clean evaluation split); library versions (`torch`, `art`, `shap`, `numpy`, `scikit-learn`/`xgboost`, `onnxruntime` where used).
- **Provenance additions** (section 5.3 fixes storage): `Provenance.dataset` holds the HF dataset id, `Provenance.dataset_split` the split name, and the new field `Provenance.dataset_revision: str | None` holds the resolved HF commit sha, or the sha256 of the source file (`malicious_phish.csv`) for the Kaggle-sourced dataset. The existing fields are unchanged.
- **Evaluation slice.** `Target.sample(n, seed)` returns a seeded, stratified slice of the evaluation split (`CampaignConfig.n_samples`, 10–1000, default 200; `CampaignConfig.seed`): equal allocation per class where the class has enough members, with the remainder redistributed proportionally when a class is exhausted (BMD has 89 and MT_LB 87 coarse test images, so `n_samples` above roughly 600 hits that limit on the vehicle dataset; on the URL dataset the three minority classes together hold about a third of 651,191 rows, so `n_samples` ≤ 1000 never exhausts a class — exact counts are in the manifest). `Sample.indices` records the exact source indices so a rerun with the same `(dataset_revision, split, n, seed)` sees the same rows; the indices are stored with the run and hashed into `Provenance.sample_indices_sha256` (section 5).
- **What reaches the LLM.** No dataset row, URL string, image, adversarial example, SHAP array, or model parameter ever leaves the worker for Pythia; the LLM writer receives metrics and the SHAP text summary of section 13.7 only (D5, section 16, section 21).
- **Standing limitation text is dataset-parameterised.** The first entry of `STANDING_LIMITATIONS` in `aegis/ml/schema.py` currently hard-codes CIFAR-10; it becomes a template filled from the manifest ("`<dataset id>` is an open, unclassified public benchmark of `<ground-level photographs | URL strings | network-flow records | …>`; it is not a proxy for any operational sensor, deployment domain, or mission data"), and the dataset-specific caveats listed in 11.3 are appended to every campaign's `limitations` (section 14.5).
- **URL strings are data (11.3.3).** No component fetches, resolves, or renders a URL from the tabular dataset: the feature extractor is a pure string function, the sandbox child has no network, the UI shows a URL string only as escaped non-clickable text labelled as dataset content, reports escape it, and it never enters the LLM payload. A test asserts the no-network property (section 22.3).
- **Retention.** Dataset slices, adversarial examples, and SHAP artifacts are `Artifact` rows and fall under the retention and export-redaction policy, which is decision D006 and remains OPEN; deleting them is a governed retention operation (constitution Principle VII, section 21), not ordinary editing.

## 12. Attack catalog

### 12.1 Adapter contract and registration

Every attack is an adapter over the Adversarial Robustness Toolbox (ART). S1's interface `run(estimator, data, budget) -> AttackResult` is realised by the protocol already in `aegis/ml/attacks/base.py`:

```python
class AttackAdapter(Protocol):
    id: str
    def info(self) -> AttackInfo: ...                       # id, name, domain, family, description, params_schema, references
    def resolve_params(self, params: dict) -> dict: ...     # fill defaults, coerce, reject out-of-range (ValueError → HTTP 422 at admission)
    def run(self, target: Target, x: np.ndarray, y: np.ndarray, params: dict, seed: int) -> AttackOutput: ...

@dataclass
class AttackOutput:
    x_adv: np.ndarray; linf_norm_mean: float; l2_norm_mean: float; wall_time_s: float
    params: dict; library_versions: dict[str, str]; notes: list[str]
```

- `AttackInfo.family` is the Literal `evasion | control`; `AttackInfo.domain` is `image | tabular | llm`. Phase B rows for text and detection require adding `text` and `detection` to the `Domain` literal in `aegis/ml/schema.py`; that change is not made in Phase A.
- `params_schema` (`ParamSpec`: name, type, default, min, max, description) is the single source of parameter bounds. The UI renders the launcher from it (section 18); admission validates against it (section 10); the worker calls `resolve_params` again before running so a stale client cannot widen a bound.
- Adapters register in the aegis `Registry[T]` (`aegis/registry.py`, duplicate-id detection) under the new capability tags `adversarial_ml` and `explainability` (S1 §4). They are listed by `GET /v1/attacks` (section 17). S1's remark that attacks "list in `/tools`" is superseded: the `/tools` pages and the agent/tool registry were deleted with the pentest vertical (section 2).
- Attack ids are declarative references to registered ART-backed adapters with bounded parameters. The repository stores no attack "recipes", tactical instructions, or executable payloads (constitution Principle II; F003 FR-005).
- White-box attacks need a differentiable estimator. The loader (section 9) provides one directly for bundled torch models and PyTorch `state_dict` uploads (`art.estimators.classification.PyTorchClassifier` via `Target.art_classifier()`), and for ONNX uploads through a worker-side ONNX→torch conversion; when conversion fails the campaign runs black-box attacks only, the white-box rows are recorded as `not run: no differentiable estimator` in the Measurement notes, and the run says so. The launcher offers only the attacks the target's manifest `gradients` flag supports (section 5.5). Nothing is faked.

### 12.2 Catalog

Every row of S1 §6 is kept. Columns added: adapter id, ART class, parameters, and notes. Phase column follows D4 and D8.

| Modality | Attack | Access | Phase | Adapter id | ART class | Parameters (defaults; bounds in `params_schema`) | Notes |
|---|---|---|---|---|---|---|---|
| Image | FGSM | white-box | A | `fgsm` | `art.attacks.evasion.FastGradientMethod` | `eps` from the campaign ε grid (12.3); `norm` = ∞ (Phase A) ; `targeted` = false | One gradient step; the cheapest attack and the first curve on the demo. |
| Image | PGD (L∞, L2) | white-box | A | `pgd` | `art.attacks.evasion.ProjectedGradientDescent` | `eps` from the grid; `eps_step` = `eps / 4`; `max_iter` = 10 (bounds 1–50); `num_random_init` = 0; `norm` ∈ {∞, 2} | S2's fixed `eps_step` 0.007 at ε 0.03 is amended to the ratio rule so the step scales across the sweep (D4(b); at ε 0.03 the step is 0.0075). `num_random_init` > 0 is permitted and adds a recorded nondeterminism source. L2 runs need their own declared grid (12.3); the demo uses L∞. |
| Image | Carlini-Wagner L2 | white-box | B | `cw_l2` | `art.attacks.evasion.CarliniL2Method` | `confidence`, `max_iter`, `binary_search_steps`, `learning_rate` | Minimal-norm attack; reports achieved L2 as `pert`. |
| Image | DeepFool | white-box | B | `deepfool` | `art.attacks.evasion.DeepFool` | `max_iter`, `epsilon` (overshoot), `nb_grads` | Minimal-norm attack. |
| Image | HopSkipJump | black-box | B | `hopskipjump` | `art.attacks.evasion.HopSkipJump` | as the tabular row | Same adapter as tabular, image domain; Phase B because the image demo is white-box. |
| Tabular | PGD | white-box | A | `pgd` | `art.attacks.evasion.ProjectedGradientDescent` on a differentiable **surrogate** | as the image row, ε in per-feature-scaled units (12.9) | Tree ensembles have no gradients. The bundled RandomForest/XGBoost is attacked by **surrogate transfer**: PGD runs against a differentiable surrogate (`art.estimators.classification.ScikitlearnLogisticRegression` or a small torch MLP in `PyTorchClassifier`) fitted at build time on the training split to the bundled model's predicted labels; the resulting rows are scored on the **actual** bundled model, and every metric is measured on it. The surrogate type, sha256, and its agreement rate with the target on the clean evaluation split are recorded in the manifest at build time (`MLModelManifest.surrogate`, section 5.5) and in `Measurement.notes`, and "white-box via surrogate transfer" is a stated limitation. On the bundled URL classifier (11.3.3) the perturbed vector is evidence about the decision surface over lexical features; it is a realizable attack only if it maps back to a constructible URL, which Phase A neither constructs nor checks (12.9), so the row is labelled accordingly and is never presented as URL evasion. |
| Tabular | Boundary / HopSkipJump | black-box | A | `hopskipjump` | `art.attacks.evasion.HopSkipJump` | `norm` ∈ {∞, 2}; `max_iter` = 20 (bounds 1–50); `max_eval` = 1,000 (bounds 100–5,000); `init_eval` = 100; `init_size` = 100 | Implemented as HopSkipJump (D4(d) names it; it is the query-efficient successor of Boundary Attack). `BoundaryAttack` is not registered in Phase A. Runs directly on the bundled tree model's `predict` through ART's `SklearnClassifier` / `XGBoostClassifier` wrapper — no surrogate. Query count is recorded (12.5). Defaults are capped below ART's own (`max_eval` 10,000) for CPU budgets. On the URL classifier this is the more directly meaningful tabular test — it probes the real model's decision boundary with query access and no surrogate — and its output rows carry the same realizability caveat (12.9). |
| Tabular | Zeroth-Order Optimization | black-box | B | `zoo` | `art.attacks.evasion.ZooAttack` | `max_iter`, `binary_search_steps`, `nb_parallel`, `use_resize` = false | Score-based black-box. |
| Text | TextFooler-style word substitution | black/white | B | `textfooler` | not in ART; a TextAttack-backed adapter behind the same protocol | — | Requires the `text` domain literal and a text `Target`. Phase B. |
| Detection | Adversarial patch / DPatch | white-box | B | `adv_patch`, `dpatch` | `art.attacks.evasion.AdversarialPatch`, `art.attacks.evasion.DPatch` | patch size, rotation/scale ranges, `max_iter` | Requires the `detection` domain literal and a detector `Target`. Phase B. |
| **Control** (image and tabular) | Benign random noise at the same ε | none | A | `noise_control` | none (adapter-native; no gradient, no queries) | `eps` and `norm` mirror the attack grid | Family `control` (12.4). Never creates a Finding. |

Phase B rows are registered only when their adapter, estimator support, and tests exist; until then `GET /v1/attacks` does not list them and the UI shows the modality as unavailable with the reason (S2 honesty rule; section 18). LLM-domain red-teaming (garak) is Phase B and, if added, points garak's OpenAI-compatible generator at Pythia (D6); it is not an entry in this catalog.

### 12.3 ε sweep and robustness curve

Every campaign declares a **budget grid** and a **reference budget** as part of its configuration (the F003 "attack-campaign configuration" stored with the `Run` as `CampaignConfig`, sections 5 and 19):

| Setting | Default | Semantics |
|---|---|---|
| `norm` | ∞ | Lp norm of the perturbation. |
| `eps_grid` (L∞, image) | `{0.01, 0.03, 0.1}` (S1 §6) | ε as a fraction of the [0, 1] pixel range, i.e. 2.55, 7.65, and 25.5 grey levels of 255. The grid is sorted ascending; its members are named `eps_small`, `eps_mid`, `eps_large` for the severity rules of section 15.5. Grids with more than three members name the smallest, the reference, and the largest. |
| `eps_grid` (L2, image) | `{0.25, 0.5, 1.0}` | Declared separately; L2 and L∞ results are different test families and never share a curve or an MRI. Not on the demo path. |
| `eps_grid` (tabular) | `{0.01, 0.03, 0.1}` | ε as a fraction of each declared feature's training-split range (12.9). |
| `reference_eps` | `0.03` | The single budget at which S_asr, S_conf, and S_expl are read (section 15) and at which the explained samples are chosen (section 13.3). Must be a member of the grid. It is John's "ε slider at 0.03" in the demo script (section 24). Written ε_ref in formulas. |
| `finding_asr_threshold` | `0.2` | See 12.6 and 15.5. |

Execution:

- One `attack.run` Job per attack in the campaign (section 10). Inside the Job the adapter runs once **per ε in the grid** on the **same** evaluation slice with the **same** seed, producing one `Measurement` row per (attack, ε): `id = "m.evasion.<attack_id>.eps<ε>"`, `family = "evasion"`, `params` including `eps`, `norm`, and every resolved parameter.
- The clean pass (`id = "m.clean"`, `family = "clean"`, the same slice) is computed once per campaign by the first attack job before its attack and shared by all attacks and by the control (section 10.3).
- The **robustness curve** for an attack is the set of points `(ε, acc_adv(a, ε), n)` for ε in the grid, prefixed for display by the clean point `(0, acc_clean, n)`, drawn beside the control curve `(ε, acc_control(ε), n)` at the same ε values. The normalised area under the robust-accuracy-vs-ε curve is the input to `S_eps` (section 15.2); the area is computed by the trapezoid rule over the declared grid points only (the ε = 0 clean point is drawn but excluded from the area) with accuracy divided by `acc_clean`, so a curve that never drops scores 1 and the value is only comparable at an identical grid (D9(i)).
- The curve is stored as an `Artifact` of kind `ml.curve` in two forms: `robustness_curve.json` (`{attack_id, norm, eps_grid, reference_eps, clean: {n, n_correct, accuracy}, points: [{eps, n, n_correct, accuracy, n_clean_correct, n_flipped_from_clean, asr}], control: [{eps, n, n_correct, accuracy}]}`) and a rendered `robustness_curve.png`. Every point carries its denominator; the UI never draws a curve without the `n` (section 14, section 18).
- Minimal-norm attacks (CW, DeepFool, HopSkipJump) do not take ε as an input. For them the grid is used as the **evaluation** grid: an example counts as a success at ε if the attack found an adversarial example within that budget, so the same curve and severity machinery applies, and the achieved norm is reported as `pert` (12.5).

### 12.4 Benign random-noise control

At every ε in the grid — not only at the reference budget — the campaign evaluates the model on the same slice perturbed by **benign random noise of the same magnitude and norm** as the attack (S2 §2.3, brief: "include benign controls"):

- L∞: each input receives `u ~ Uniform(−ε, ε)` per element, added and clipped to the valid range ([0, 1] for images; the feature range for tabular). L2: a random direction scaled to norm ε. The noise uses the run seed (`np.random.default_rng(seed)`), so it is reproducible.
- No gradient, no query, no model access beyond the final prediction. For tabular targets the noise touches only the declared perturbable features (12.9).
- One `Measurement` per ε: `id = "m.control.noise.eps<ε>"`, `family = "control"`, `attack_id = "noise_control"`. Because the control is attack-independent it is computed once per (norm, ε) by the first attack job and shared by every attack in the campaign with that norm.
- The control **never creates a Finding** and never enters the MRI as an attack. Its role is to separate *adversarial* (gradient- or query-aligned) failure from ordinary noise sensitivity:
  - "Control preserves accuracy" is defined as `|acc_control(ε) − acc_clean| ≤ max(0.02, √(acc_clean·(1 − acc_clean)/n))`, i.e. within two percentage points or one binomial standard error of the clean accuracy, whichever is larger. This is the predicate the rule layer's first rule uses (section 16: "random noise did not degrade the model, so the failure is gradient-aligned").
  - If the control alone degrades accuracy by more than `finding_asr_threshold` at some ε, the run records an `Interpretation` (kind `inferred`, basis = the control and clean Measurement ids): "the model is noise-sensitive at ε = …; evasion results at this ε are not attributable to adversarial alignment", and the Finding at that ε is still created from the attack measurement but shows this interpretation beside it (section 14).
- On the explained sample set, the control also gets a SHAP pass so that explanation stability has a benign baseline (section 13.5).

### 12.5 Metrics recorded per attack and ε

S1 §8.1's inputs are recorded as follows. Existing `Measurement` fields are reused; the additions are stated explicitly and belong to `aegis/ml/schema.py` (storage placement is fixed in section 5.3; the scoring definitions in section 15.1 govern).

| S1 input | Definition used here | Where recorded |
|---|---|---|
| `acc_clean` | `n_correct / n` on the clean slice. | `m.clean`: `n`, `n_correct`, `accuracy`, `per_class{class: {n, n_correct}}`. |
| `acc_adv(a, ε)` | `n_correct / n` on `x_adv(a, ε)` over the **whole** slice (not only clean-correct inputs). | `m.evasion.<a>.eps<ε>`: `n`, `n_correct`, `accuracy`, `per_class`. |
| `asr(a, ε)` | Attack success rate = (samples correct on clean **and** incorrect on adv) / (samples correct on clean). Numerator is `n_flipped_from_clean`; the denominator is new. | Existing `n_flipped_from_clean`; **new** `n_clean_correct: int | None` and `attack_success_rate: float | None`. |
| `pert(a)` | Mean perturbation at first success in the attack's norm. For ε-parameterised attacks (FGSM, PGD, noise): for each sample flipped at any grid ε, the measured norm of its adversarial example at the smallest grid ε at which it flips; mean over those samples (computed from the `ml.flip_matrix` artifact). For minimal-norm attacks: the achieved norm of each successful example. | **new** `pert_first_success_mean: float | None` and `pert_first_success_n: int | None` on the attack's `reference_eps` row; the per-ε rows keep `linf_norm_mean` and `l2_norm_mean` of the realised perturbation (both always recorded, whatever the attack norm). |
| `conf_gap(a, ε)` | Per sample `g_i = max(0, max_{j≠y_i} p_j(x_adv_i) − p_{y_i}(x_adv_i))` on the adversarial input, mean over **all** `n` samples, so a robust model scores 0 rather than "undefined" (section 15.1); in [0, 1]. | **new** `conf_gap_mean: float | None`, `conf_gap_n: int | None` (= `n`). Per-sample `confidence_clean` / `confidence_adv` already live on `Observation`. |
| `expl_shift(a, ε)` | Defined in section 13.5; computed in the explain stage, not the attack stage. | Per-sample on `Observation` (new `expl_shift`), aggregate on the attack's `reference_eps` row (new `expl_shift_mean`, `expl_shift_n`) and on the campaign score record (section 5, section 15). |
| `queries(a)` | Black-box attacks only: mean number of model `predict` calls per sample, counted by a wrapping estimator around `Target.art_classifier()` / `predict_proba`. | **new** `queries_mean: float | None`. |

Also recorded on every evasion and control row: `wall_time_s`, `params` (resolved), `notes` (surrogate transfer, frozen features, "not run" reasons, artifact-retention notes), and — through `AttackOutput.library_versions` — the `art`, `torch`, `numpy`, and `scikit-learn`/`xgboost` versions, which are merged into `Provenance` (section 14).

### 12.6 Finding creation

A `Finding` is a derived threshold crossing, not a reviewed judgment (F005/F006 reconciliation; section 6 covers review states).

- **Granularity:** at most one Finding per **attack (test family)** per campaign. The Finding carries the full per-ε table for that attack in its `schema_blob` (section 5.7); it does not split by ε.
- **Trigger:** the attack "succeeds at ε" when `asr(a, ε) ≥ finding_asr_threshold` (default 0.2, campaign-configurable, stored with the Run). A Finding is created when the attack succeeds at **any** ε in the grid (S1 §6: "when success rate crosses a configurable threshold at any budget").
- **Denominator guard:** when `n_clean_correct < 10` at the reference budget, no Finding is created; the Measurement row is kept, `notes` records "denominator too small for a finding", and the run page shows the row with its `n` (section 14: results are never hidden, and zero or tiny denominators never become a percentage headline).
- **Severity** is derived from the grid position of first success and the ASR by the rules of section 15.5 (S1 §8.5: critical / high / medium / low keyed to `eps_small`, `eps_mid`, `eps_large`), written to the existing `Finding.severity` column so the findings table, filters, and audit trail work unchanged. Nothing sets severity by hand.
- **Controls never create Findings** (12.4). Attacks that were not run (no differentiable estimator, cancelled, failed) create no Finding; the reason is in `notes` and the Job state (section 10).
- **Identity:** `Finding.scanner_finding_id = "ml.<attack_id>"`, `source_tool = "aegis.ml/<attack_id>"`, `dedup_key = "ml:<model_sha256[:16]>:<attack_id>:<settings_hash[:16]>"` (section 5.2), so a rerun at identical settings dedups against the earlier Finding and a different grid or dataset does not.
- **Verify link:** `Finding.validation_state` is written by `verify.replay` after a defense is applied and the whole attack set re-run at the same settings (section 16, section 6); the measured ΔMRI is the only sanctioned form of "gain" (D9(iv)).

### 12.7 Determinism, seeds, and provenance

- The run seed feeds `np.random.default_rng(seed)` for the slice and the control noise, `np.random.seed(seed)` for ART's internal RNG, and `torch.manual_seed(seed)` before each attack call.
- With `num_random_init = 0`, FGSM and PGD are deterministic on CPU up to float32 reduction order; HopSkipJump's random initialisation and ZOO's sampling are seeded but recorded as nondeterminism sources.
- `Provenance.nondeterminism` receives, as applicable: `"CPU float32 reductions"`, `"PGD random restarts (num_random_init > 0)"`, `"HopSkipJump random initialisation"`, `"surrogate-transfer PGD: surrogate fitted at build time, seed recorded in manifest"`, plus the explainer entries of section 13.8 (the canonical strings are listed in section 14.4).
- Every Measurement is reproducible from `(model_sha256, dataset_revision, split, indices, attack_id, resolved params, seed)`; that tuple is what a rerun and a ΔMRI comparison must match (D9(i); section 14).

### 12.8 Resource bounds and failure

- Attacks run only in the sandboxed worker (sections 9 and 10): separate process, no network, rlimits. `params_schema` upper bounds (`max_iter` ≤ 50, `max_eval` ≤ 5,000, `n_samples` ≤ 1,000, ≤ 3 grid members by default, more only by explicit configuration) keep a Phase A campaign inside CPU budgets on the demo models.
- The worker enforces a per-Job wall-clock budget (`AEGIS_ML_SANDBOX_TIMEOUT_S`, section 9.4); exceeding it fails the Job (`failed` with `SandboxTimeout`; William's `timed_out` maps onto it, section 6.3). Partial Measurements written before the timeout are kept and labelled partial; no curve point is interpolated.
- Adversarial arrays: the full `x_adv` slice per (attack, ε) is stored as an `Artifact` (`adv_slice.npz`, float32, kind `ml.adv_slice`) when it is at most `AEGIS_ML_MAX_ADV_ARTIFACT_MB` (default 64 MB); otherwise only the explained samples' arrays are stored (section 13.6) and `notes` records that the full slice was not retained. Retention is never load-bearing: `verify.replay` regenerates the attack from configuration and seed rather than replaying stored arrays.

### 12.9 Tabular specifics

- **Perturbable features are declared, not inferred.** The bundled URL maliciousness classifier's manifest (11.3.3) lists the continuous lexical features the attacks may touch (`features[].perturbable`, section 5.5): `url_length`, `digit_ratio`, `letter_ratio`, `count_dot`, `count_hyphen`, `count_at`, `count_question`, `count_percent`, `count_equals`, `subdomain_count`, `path_depth`, `shannon_entropy`; the binary flags `has_ip_host`, `is_shortener`, `is_https`, `suspicious_tld` and the label are frozen in Phase A. On the fallback dataset (11.3.4) the categorical columns `proto`, `service`, `state` and the label are frozen. Frozen features are held at their clean values through the ART attack's `mask` argument where the attack supports it, and re-imposed after every attack step by the adapter where it does not; the method used is in `notes`.
- **ε is per-feature scaled.** For feature `j`, the L∞ budget is `ε · (max_j − min_j)` with the range taken from the training split and recorded in the manifest; the attack operates in min-max-scaled space and the adapter maps back. `linf_norm_mean` / `l2_norm_mean` are reported in scaled units and say so. Adversarial values are clipped to the observed range; integer-valued features are rounded after the attack and the **post-rounding** prediction is what is measured.
- **Two different questions.** Surrogate-transfer PGD measures transfer of gradient-aligned perturbations onto the tree model; HopSkipJump measures direct decision-boundary search with query access. Both are scored on the real bundled model, both are labelled in `notes`, and they remain separate test families in the tables and the curve.
- **Realizability caveat (stated on every tabular row).** Feature-space perturbations — PGD on continuous features with post-attack rounding, and HopSkipJump — are evidence about the classifier's decision surface. A perturbed feature vector counts as a realizable attack only if it maps back to a constructible input: for the URL classifier, a URL string that yields exactly those lexical features while respecting their coupling (`url_length` bounds every count, `digit_ratio + letter_ratio ≤ 1`, `subdomain_count` is bounded by `count_dot`). Phase A does not construct such inputs and does not check constructibility, so every tabular evasion row carries `notes: "feature-space perturbation; realizability not established"`, the tabular standing limitation says so (section 14.5), the UI labels the rows (section 18.4), and no tabular finding, score or narrative claims a demonstrated URL evasion. Within that scope both attacks are meaningful — HopSkipJump as a direct decision-boundary probe of the real model, surrogate-transfer PGD as a transfer measurement — and neither is more than decision-surface evidence.
- **Control** noise is drawn on the same declared features at the same scaled ε.
- **Evidence for pane 1** (section 18) is a per-sample feature diff (feature, clean value, adversarial value, Δ in raw and scaled units) instead of an image pair; for the URL classifier the clean row's URL string is shown as escaped, non-clickable text labelled as dataset content, and there is no adversarial URL to show because the adversarial example is a feature vector (realizability caveat above).
- The awkwardness of L∞ budgets on tabular features (integer counts and coupled ratios on the URL classifier; categorical columns on the fallback dataset) and the realizability gap are standing limitations of every tabular campaign (section 14), and tabular MRIs are never compared with image MRIs (D9(i)).

## 13. Explainability

### 13.1 Stance

SHAP shows *what changed in the model's attribution* between a clean input and its adversarial counterpart. It is **supporting evidence, not causal proof** (brief; constitution Principle III): an attribution map describes the model's sensitivity, not the cause of a failure, and every explanation panel, artifact, and report carries that statement (section 14). The brief's "do not require SHAP for every modality" holds: Phase A supports image and tabular white-box targets; the LLM domain has no SHAP and is shown as `not_implemented` with its reason (Phase B, D6). When an explanation is unsupported or fails, the explain stage records that state and the UI shows an explicit unsupported panel — never a fabricated heatmap (F005 FR-006/SC-002).

### 13.2 Explainer table

Every S1 §7 row is kept; the concrete choice, phase, and artifacts are added.

| Modality | SHAP explainer | Phase | Requirement | Output artifacts |
|---|---|---|---|---|
| Image (white-box) | `shap.GradientExplainer` on `Target.torch_model()` (S2 §2.4). S1's `DeepExplainer` is accepted as an alternative only when the architecture is within its supported layer set; `GradientExplainer` is the default because it works for arbitrary differentiable modules including converted ONNX graphs. | A | Differentiable torch module (bundled, `state_dict` upload, or converted ONNX; section 9). | Pixel saliency overlays, clean vs adversarial, for the explained samples; raw values (13.6). |
| Image (no differentiable module) | `shap.PartitionExplainer` with `shap.maskers.Image` (S1's alternative), model-agnostic over `predict_proba`. | A (fallback path) | Any `Target` with `predict_proba`; slower, so `explain_k` is capped at 8 on this path. | Same overlays; `Provenance` records the explainer used. |
| Tabular (trees) | `shap.TreeExplainer` on the bundled URL maliciousness classifier (RandomForest / XGBoost on the lexical URL features of 11.3.3; D4(d)); `feature_perturbation="tree_path_dependent"`, exact and deterministic. | A | Tree model. Always run on the **real** model, never the PGD surrogate. | Bar plot (global mean \|SHAP\|) and beeswarm over the lexical URL features (for example `url_length`, `count_dot`, `subdomain_count`, `has_ip_host`, `shannon_entropy`), per-sample force plot — each clean vs adversarial. |
| Tabular (non-tree) | `shap.KernelExplainer` over `predict_proba`, background = seeded 100-row sample of the evaluation split. | A (uploaded non-tree sklearn models); otherwise B | `predict_proba`. | Same plots, sampled; nsamples recorded. |
| Text | `shap.PartitionExplainer` with a text masker | B | Text `Target`. | Token attribution highlight. |
| Black-box any | `shap.KernelExplainer` | B | Endpoint target (`ml_model_endpoint`, D2 Phase B). | Same plots, sampled. |

### 13.3 Procedure

The `explain.run` Job (section 10) runs after the attack Jobs of a campaign and reads their outputs; it can also be triggered per Finding (`POST /v1/findings/{id}/explain`, section 17), in which case it explains that Finding's attack.

1. **Explained set.** At the **reference budget** (12.3), for each attack, take in slice order the first `k` samples whose prediction flipped and the first `k` that did not flip (`CampaignConfig.explain_k`, default 8, bounds 0–32; S2 §2.4). If fewer than `k` exist in either group the group is smaller and its size is recorded. The union `E(a)` is the explained set; its size is the denominator of every explanation-derived number.
2. **Background.** Image: 50 images drawn with the run seed from the evaluation slice, excluding `E(a)` when the slice allows (S2). Tabular tree path: none needed. Kernel/Partition paths: as in the table above. Background size is recorded.
3. **Attributions computed per explained sample:** (i) φ_clean — attribution of the **clean-predicted class** on `x_clean`; (ii) φ_adv — attribution of the **same class** on `x_adv(a, reference_eps)` (S2: "attribution for the clean-predicted class"), which is the comparable pair used for `expl_shift`; (iii) for flipped samples only, φ_adv_pred — attribution of the **adversarial predicted class** on `x_adv`, shown as a third, labelled map; (iv) φ_ctrl — attribution of the clean-predicted class on the **control-perturbed** input at the same ε (12.4), used for the noise floor in 13.5.
4. **Sampling parameters.** `GradientExplainer` uses shap's default `nsamples` (200) unless the campaign overrides it; `KernelExplainer`/`PartitionExplainer` sample counts likewise. All are recorded in `Provenance` and in each observation's meta file.
5. **Per-sample record.** One `Observation` per explained sample: `sample_index`, `true_label`, `pred_clean`, `pred_adv`, `flipped`, `confidence_clean`, `confidence_adv`, `artifacts` (name → `Artifact.id`), `artifact_sha256`, `center_mass_ratio_clean` / `center_mass_ratio_adv` (image only; 13.4), `metric_kind = "heuristic"`, `metric_note`, plus the **new** field `expl_shift: float | None` (13.5) and, for tabular, **new** `top_features_clean` / `top_features_adv: list[str]` (feature names ranked by \|SHAP\|). These are additions to `Observation` in `aegis/ml/schema.py` (section 5.3); existing fields are unchanged.
6. **Campaign-level summaries.** Per attack at the reference budget: mean `expl_shift` with its `n`, the control noise floor (13.5), mean centre-mass ratios clean vs adversarial over flipped and non-flipped samples separately (image), and the top-5 features by mean \|SHAP\| clean vs adversarial with rank changes (tabular; on the URL classifier these are lexical features such as `url_length`, `count_dot`, `subdomain_count`, `path_depth`, `shannon_entropy`). These feed section 15 (`S_expl`), section 16 (rules and the text summary), and the scorecard (section 18). They are derived values and render in a derived-summary panel, not among observations (F005 FR-006).

### 13.4 Centre-mass heuristic (image)

`center_mass_ratio` = share of total \|SHAP\| attribution (summed over channels) that falls inside the centred box covering 50 % of the image area (side length 1/√2 of each dimension). It is computed on φ_clean and φ_adv for every explained image sample.

- It is a **proxy** for "attention on the subject", not a segmentation, not object localisation, and not a claim about what the object is. The label is enforced in the contract: `Observation.metric_kind` is the Literal `"heuristic"` and `metric_note` carries the definition (`aegis/ml/schema.py`); the UI badge reads "heuristic" (section 18).
- On the vehicle dataset (11.3.1) subjects are web-thumbnail framed and not reliably centred, so the ratio is weaker evidence there than on CIFAR-10; that caveat is appended to `metric_note` and to the campaign limitations when the dataset's manifest flags `subject_centered: false`.
- It drives exactly one rule (section 16): a mean drop of at least 0.15 on flipped samples, clean vs adversarial, triggers the "investigate reliance on peripheral/background pixels" candidate — itself marked heuristic. The demo narrative "the model relied on background pixels rather than the target" (S1 §7, brief) is therefore an `Interpretation` (kind `inferred`) whose `basis` cites the observation ids, never a measurement.
- Tabular targets have no centre-mass analogue in Phase A; their per-sample heuristic slot is empty (`None`) and the observation shows top-feature rankings instead.

### 13.5 Explanation stability — `expl_shift`

`expl_shift` is the SHAP-native signal S1 §8.2 calls "unique to this tool"; it feeds the MRI dimension `S_expl` (section 15.2). Its definition is fixed here.

**Per sample.** For explained sample *i* under attack *a* at budget ε:

```
v_clean = flatten(φ_clean_i)          # image: SHAP values summed over channels → H×W, then flattened; tabular: the feature vector
v_adv   = flatten(φ_adv_i(a, ε))      # same class (the clean-predicted class), same flattening
cos     = ⟨v_clean, v_adv⟩ / (‖v_clean‖₂ · ‖v_adv‖₂)
expl_shift_i(a, ε) = clamp(1 − cos, 0, 1)
```

- Range: cosine similarity lies in [−1, 1], so `1 − cos` lies in [0, 2]; it is clamped to [0, 1] so that anti-correlated attributions count as a full shift and `S_expl = 1 − mean expl_shift` stays in [0, 1].
- Guard: if either norm is below 1e-12 the pair is undefined; it is excluded and counted in `expl_shift_n_excluded`.
- The same class is explained on both inputs so the comparison is of *where the model looks for the same decision*, not of two different decisions.

**Aggregate.** `expl_shift(a, ε) = mean_i expl_shift_i(a, ε)` over the explained set `E(a)` (13.3), reported with `expl_shift_n = |E(a)| − n_excluded`. It is computed at the **reference budget** in Phase A (the explained set is chosen there; computing it on the full grid is permitted by configuration and multiplies explainer cost). `S_expl` in section 15 is `1 − mean over in-scope attacks of expl_shift(a, reference_eps)`.

**Noise floor.** On the same explained set the run computes `expl_shift_control(ε) = mean_i clamp(1 − cos(v_clean, v_ctrl), 0, 1)` using φ_ctrl from the benign control (13.3 step 3(iv)). It is recorded beside `expl_shift` as `expl_shift_noise_floor` with its `n`. It is **not** part of the MRI; it is context: an attack shift close to the noise floor means the explainer itself moves under any perturbation of that size, and the rule layer and the UI say so (section 16, section 18). `GradientExplainer` sampling noise is additionally listed in `Provenance.nondeterminism`.

**Recording.** Per-sample values go on `Observation.expl_shift`; the aggregate, its `n`, the noise floor, and the explainer settings go on the attack's `reference_eps` Measurement row (`expl_shift_mean`, `expl_shift_n`) and on the per-attack entry of the campaign score record whose storage section 5 fixes. The UI renders `expl_shift` in the derived-summary panel with its denominator and never as an observation (F005 FR-006).

**Dependency on the MRI.** If `explain_k = 0`, the explainer is unsupported for the target, or the explain stage failed, `S_expl` has no input and the MRI is **not computed**; the scorecard shows "not computed: explanation stage absent" with the reason (D9(ii) forbids showing an MRI without all five subscores; section 15).

### 13.6 Artifacts written

`aegis/ml/explain/` writes to the blob store and registers `Artifact` rows (`aegis/db/models.py`: `id`, `run_id`, `project_id`, `org_id`, `kind`, `sha256`, `location`, `content_type`, `size_bytes`; unique on `(run_id, kind, sha256)`) with the kinds fixed in section 5.8. `Observation.artifacts` maps a stable name to the `Artifact.id`; `Observation.artifact_sha256` mirrors `Artifact.sha256`; `GET /v1/artifacts/{id}` streams them with the strict CSP (section 17). S1's "raw SHAP values JSON" is amended: raw arrays are written as `.npz`, with a small JSON meta file beside them, because a 128×128×3 map per class is impractical as JSON.

| Name (per explained sample unless noted) | `Artifact.kind` | Content |
|---|---|---|
| `clean.png` | `ml.input.clean` | The clean input, upscaled nearest-neighbour for display (image). |
| `adv.png` | `ml.input.adv` | The adversarial input at the reference budget (image). |
| `diff.png` | `ml.perturbation` | \|x_adv − x_clean\| per pixel, summed over channels, scaled so that ε maps to full intensity (so maps are comparable across ε); the scale is in the meta file. |
| `shap_clean.png`, `shap_adv.png` | `ml.shap.image` | Attribution overlays for the clean-predicted class on the clean and adversarial inputs. |
| `shap_adv_predclass.png` (flipped only) | `ml.shap.image` | Attribution for the adversarial predicted class on the adversarial input, labelled as such. |
| `shap_values.npz` | `ml.shap.values` | float32 arrays `clean`, `adv`, `adv_predclass` (if any), `control`, plus `indices`. |
| `shap_meta.json` | `ml.shap.meta` | Explainer name and version, class explained, background size, `nsamples`, seed, `center_mass_ratio_*`, `expl_shift`, norms, `diff.png` scale, wall time. |
| `feature_diff.json` (tabular) | `ml.feature_diff` | Per-feature clean / adversarial values, Δ raw and scaled, frozen flags — pane 1 content for tabular. |
| `shap_force_<i>.png` (tabular) | `ml.shap.force` | Per-sample force plot, clean and adversarial. |
| Campaign-level: `shap_bar_clean.png`, `shap_bar_adv.png` (tabular) | `ml.shap.bar` | Mean \|SHAP\| per feature over the explained set; feature order fixed by the clean ranking on both plots so rank changes are visible. |
| Campaign-level: `shap_beeswarm_clean.png`, `shap_beeswarm_adv.png` (tabular) | `ml.shap.beeswarm` | Beeswarm over the explained set, same fixed feature order. |
| Campaign-level: `shap_summary.json` | `ml.shap.summary` | The aggregates of 13.3 step 6 with denominators, per attack. |
| Campaign-level: `shap_summary.txt` | `ml.shap.summary_text` | The **SHAP text summary** — the only explanation-derived content the LLM writer receives (13.7). |

Rendering conventions, so that side-by-side maps are not misleading: a symmetric diverging colormap centred on zero with **one shared colour scale per sample across its clean and adversarial maps**; overlays at fixed alpha over the greyscale input; nearest-neighbour upscaling only; the class explained printed in the image margin. Tabular bar and beeswarm plots share the feature order and the x-axis range between clean and adversarial.

### 13.7 SHAP text summary for the LLM writer

D5 restricts the LLM writer to metrics and a SHAP **text** summary: no images, no arrays, no model or dataset content. The summary is generated **deterministically from templates** in `aegis/ml/explain/summary.py`, per attack at the reference budget, from the aggregates of 13.3 step 6; the writer may rephrase it but may not add claims (section 16). Template (fields in braces are filled from the record; each sentence carries its denominator):

- Image: "For {attack} at ε = {reference_eps} ({norm}), attribution similarity between clean and adversarial inputs fell to a mean expl_shift of {expl_shift} over n = {n} explained samples ({n_flipped} flipped, {n_unflipped} not); the benign-noise control at the same ε gave {expl_shift_noise_floor} over n = {n_ctrl}. The centre-mass heuristic (share of |SHAP| in the central 50 % of the image) moved from {cmr_clean} to {cmr_adv} on flipped samples (n = {n_flipped}); this metric is a heuristic proxy for attention on the subject, not a segmentation."
- Tabular: "For {attack} at ε = {reference_eps} (per-feature scaled), the top features by mean |SHAP| were {top5_clean} on clean rows and {top5_adv} on adversarial rows (n = {n}); {n_rank_changes} of the top 5 changed rank. Mean expl_shift was {expl_shift} (n = {n}); the control at the same ε gave {expl_shift_noise_floor} (n = {n_ctrl})." Feature names are the manifest's feature identifiers (11.3.3); no URL string ever enters the summary.
- Every summary ends with the fixed sentence "SHAP attributions describe the model's sensitivity, not the cause of a failure."

The summary passes through aegis's redaction and guardrails before the Pythia call (section 16, section 21).

### 13.8 Provenance, nondeterminism, and limitations

- `Provenance.shap` records the shap version; the explainer name, background size, `nsamples`, `explain_k`, the class-selection rule, seeds, and wall time are recorded in `shap_meta.json` and in the campaign score record (section 5).
- `Provenance.nondeterminism` receives the `GradientExplainer` / `KernelExplainer` / `PartitionExplainer` sampling entry of section 14.4 whenever a sampled explainer ran; `TreeExplainer` adds the positive statement that it is deterministic.
- Limitations appended to every campaign with an explain stage (section 14): SHAP attributions are not causal; explanations were computed on at most 2·`explain_k` samples per attack at the reference budget only; the centre-mass heuristic assumes a centred subject and is a proxy; `expl_shift` compares attributions of the same class and is sensitive to explainer sampling noise (see the noise floor); for the ONNX fallback path, `PartitionExplainer` masking attributions are not the same quantity as gradient attributions and are not compared across paths.

### 13.9 Where explanations feed

| Consumer | What it takes | Section |
|---|---|---|
| Rule layer | Mean centre-mass drop on flipped samples (heuristic rule); `expl_shift` vs its noise floor; tabular top-feature rank changes. Every triggered rule cites the observation and summary ids. | 16 |
| MRI `S_expl` | `expl_shift(a, reference_eps)` per in-scope attack with `n`; MRI not computed when absent. | 15 |
| LLM writer (Pythia) | `shap_summary.txt` (`ml.shap.summary_text`) only. | 16, 21 |
| Three-pane findings screen, pane 2 | `shap_clean.png` / `shap_adv.png` / `shap_adv_predclass.png` (image) or bar / beeswarm / force (tabular), with the "heuristic" and "not causal" labels and the explainer provenance. | 18 |
| Run page derived-summary panel | `expl_shift`, noise floor, centre-mass means, top features — each with `n`, rendered apart from the measurement table and the observation gallery. | 14, 18 |
| Reports | The same artifacts and summaries by `Artifact.id` and sha256, so every explanation in a report links to a stored file. | 14, 26 |

### 13.10 Cost controls

SHAP on images is the known cost risk (section 25). Controls: `explain_k` ≤ 32 (≤ 8 on the `PartitionExplainer` path); explanations at the reference budget only by default; the demo input resolution fixed at 128×128 by the manifest; batched explainer calls; explanation results cached by `(model_sha256, dataset_revision, sample_index, attack_id, eps, explainer, nsamples, seed)` so `explain.run` and `verify.replay` reuse identical clean attributions; `TreeExplainer` preferred for tabular because it is exact and cheap. A campaign whose explain Job exceeds its wall-clock budget fails that Job with the reason (section 10) and the MRI is not computed (13.5); nothing is interpolated.

## 14. Evidence model and reporting principles

This section fixes what a run is allowed to say and how it says it. It carries the brief's reporting principles, constitution Principles III (evidence before claims) and V (reproducibility with honest limits), and the evidence requirements of F005 (FR-004, FR-005, FR-006, FR-011), F006 (FR-008, FR-010) and F007 (FR-008, FR-009) into the aegis platform as binding constraints. Every later section that produces a number, a picture or a sentence (12, 13, 15, 16, 17, 18, 24) is bound by it. Nothing in S1 conflicts with this section; where S1 was silent (labels, denominators, controls, limitations) S2 applies, and where S2's lean layout differs from aegis persistence, section 5 governs storage while this section governs meaning.

### 14.1 Four kinds of statement, four fields, four panels

A run produces exactly four kinds of statement. They are separate Pydantic types in `aegis/ml/schema.py`, separate sub-objects in every report, and separate panels in the UI (section 18). They are never blended in prose.

| Kind | Type in `aegis/ml/schema.py` | What it is allowed to contain | Label enforced by | UI panel (section 18) |
|---|---|---|---|---|
| Measurement | `Measurement` | Counts and derived rates for one test family at one setting: `n`, `n_correct`, `accuracy`, `n_flipped_from_clean`, `linf_norm_mean`, `l2_norm_mean`, `per_class`, `wall_time_s`, `params`, `notes`, plus the scoring inputs added in 12.5 / 15.1 | The field set itself: there is no free-text claim field, only `notes` for caveats | **Measurements** (table by family, with the eps curve and the MRI scorecard as a derived-summary sub-block, 15.7) |
| Observation | `Observation` | Per-sample evidence: `true_label`, `pred_clean`, `pred_adv`, `flipped`, `confidence_clean`, `confidence_adv`, artifact references and hashes, `center_mass_ratio_clean/adv`, `expl_shift` | `metric_kind: Literal["heuristic"]` with a fixed `metric_note` | **Observations** (gallery: input pair, SHAP pair, labels, heuristic ratios) |
| Interpretation | `Interpretation` | A sentence that infers a cause or pattern, with `basis: list[str]` of measurement/observation ids it rests on | `kind: Literal["inferred"]` | **Interpretation** (each statement shows its basis ids as links) |
| Candidate recommendation | `CandidateRecommendation` | `title`, `rationale`, `triggered_by` ids, `references`, optional `narrative` | `status: Literal["candidate"]`; `validation` (see 16.4 for the one permitted extension); `narrative_source: Literal["rules","llm"]` | **Candidate recommendations** (each labelled "candidate"; validation state shown verbatim) |

Two more blocks always accompany the four: **Provenance** (`Provenance`, 14.4) and **Limitations** (`RunRecord.limitations`, 14.5). A report or page that omits either is malformed.

Rules that hold across all four:

- **Ids are the citation mechanism.** Measurement ids are `m.<family>[.<attack_id>][.eps<ε>]` (`m.clean`, `m.evasion.pgd.eps0.03`, `m.control.noise.eps0.03`); observations are `o.<index:03d>`; interpretations `i.<n>`; recommendations `r.<rule_id>`. `Interpretation.basis` and `CandidateRecommendation.triggered_by` MUST cite ids that exist in the same run. `RunRecord` gains a model validator (M1, section 23) that rejects a record with a dangling citation; `tests/ml/test_schema.py` asserts it.
- **Literal types are the contract.** `Observation.metric_kind`, `Interpretation.kind`, `CandidateRecommendation.status` are single-value `Literal`s. Code cannot construct an observation that calls itself a measurement, an interpretation that calls itself observed, or a recommendation that calls itself validated. The UI renders the literal value as the badge text rather than hard-coding the word, so a schema change is visible immediately.
- **No claim without a basis.** An `Interpretation` with an empty `basis` and a `CandidateRecommendation` with an empty `triggered_by` are rejected at construction (min length 1).
- **Reviewer judgement is a fifth, human, voice.** `RunRecord.reviewer_notes` is free text written only by a person through `PATCH /v1/runs/{id}/reviewer-notes` (section 17); it is displayed under its own "Reviewer notes" heading, never merged into interpretation. The F006 review states that formalise reviewer judgement are mapped in section 6.

### 14.2 Per-family results with denominators and coverage

The brief: "Present results by test family with clear denominators and coverage." F005 FR-005: every metric exposes definition, numerator, denominator, units, exclusions and coverage.

- **Test families.** `MeasurementFamily = Literal["clean", "evasion", "control"]`. `clean` is the baseline on the sampled slice; `evasion` is one attack at one ε; `control` is benign random noise at one ε (14.3). No family is added for hardening: a verify run (16.5) is a new run whose rows use the same three families, measured with the defense in the pipeline, so the defended clean accuracy is a first-class `m.clean` row rather than a footnote.
- **One row per setting.** With the ε sweep of D4(b), a campaign with attack set `{fgsm, pgd}` and grid `{0.01, 0.03, 0.1}` produces 1 clean row, 6 evasion rows and 3 control rows. The robustness curve (section 12) is rendered from these rows; it is not a separate data source.
- **Denominators travel with every number.** `accuracy` is stored alongside `n` and `n_correct`, and the UI prints `n_correct / n (accuracy)`. Attack success rate is printed as `n_flipped_from_clean / n_clean_correct`; its denominator is the clean row's `n_correct`, not `n`, and the UI names that denominator explicitly. Per-class rows print `n_correct / n` per class. A percentage is never printed without its fraction.
- **Zero or unknown denominator.** When `n == 0`, `n_clean_correct == 0`, or a row is absent, the UI and reports show "not computed (denominator 0)" or "no evidence recorded", never `0%` and never `100%` (F005 US2 and edge cases). Section 15.4 says what this does to the score.
- **Coverage.** Every measurements table is headed by the slice description: dataset id and revision (section 11), split, `n_samples`, `seed`, and the sample-selection rule. Rows that were skipped or failed (an attack that raised on a batch, a stage that timed out) appear as rows with `n` = samples actually evaluated and a `notes` entry naming the exclusion; a partial run is labelled `partial` in every place its numbers appear (F007 FR-004).
- **Same slice everywhere.** All rows of one run are computed on the same sample indices (the first attack job samples the slice; later jobs reuse it, section 10.3), so denominators are comparable within the run. A verify run re-uses the baseline run's dataset revision, indices and seed (15.6) so its rows are comparable to the baseline's.

### 14.3 Benign controls

The brief: "Include benign controls and human review of flagged examples."

- **Random-noise control at the same ε.** For every ε in the grid, the pipeline evaluates the model on `x + u`, `u ~ Uniform(-ε, ε)` per element, clipped to the input range, so the control lives inside the same L∞ ball the attack was allowed. Its row is `m.control.noise.eps<ε>` with the same `n`. `tests/ml/test_noise_control.py` asserts the control stays inside the ball.
- **What the control is for.** It separates gradient-aligned fragility (attack degrades, noise does not) from general noise sensitivity (both degrade). Interpretation rule I1 (14.6) and recommendation rules R1/R1b (16.2) read it. Controls are displayed on the robustness curve as a second line and in the table as their own family, and they never enter the MRI (15.2).
- **Human review of flagged examples.** Flagged examples are the samples with `flipped == true`. The observation gallery shows up to `explain_k` flipped and `explain_k` unflipped samples with their inputs and attributions so a person can look; the gallery is evidence for review, not a verdict. `reviewer_notes` and the F006 review workflow (section 6) are where the human records what they concluded.

### 14.4 Provenance and nondeterminism

Constitution V and the brief: record model and dataset versions, test configuration, evaluator configuration, run limitations; disclose nondeterminism; preserve the relationship between reruns and originals.

`Provenance` (already in `aegis/ml/schema.py`) records `aegis_version`, `python`, `torch`, `art`, `shap`, `numpy`, `model_sha256`, `dataset`, `dataset_split`, `model_manifest`, `started_at`, `finished_at`, `hostname`, `device`, `nondeterminism`. This spec adds (M1; the full list is in section 5.3):

| Field | Type | Meaning |
|---|---|---|
| `dataset_revision` | `str \| None` | Content hash or hub revision of the dataset (section 11) |
| `sample_indices_sha256` | `str` | Hash of the evaluated index list, so a rerun can prove it used the same slice |
| `settings_hash` | `str` | The campaign settings hash defined in section 5.6; identical hashes are the precondition for any comparison |
| `baseline_run_id` | `str \| None` | Set on verify runs: the run whose settings and slice this run re-measures (section 5.6 stores it on `ml_campaigns`) |
| `parent_run_id` | `str \| None` | Set on reruns: the run this one was started from with the same configuration |
| `defense` | `dict[str, Any] \| None` | Set on verify runs: ART defense class and resolved parameters (16.5) |
| `llm` | `dict[str, Any] \| None` | Set when a narrative was generated: `PythiaSettings.redacted()` plus `prompt_sha256`, `response_sha256`, token usage (16.3); never the key, never the text |
| `thread_env` | `dict[str, str]` | `OMP_NUM_THREADS`, `MKL_NUM_THREADS`, torch thread count, as observed |
| `onnxruntime`, `sklearn`, `xgboost` | `str \| None` | Library versions when used (section 9) |

`nondeterminism` is a list of strings and MUST be populated from the stages that actually ran. Phase A sources, each appended by the stage that introduces it:

- `"PGD random start (num_random_init > 0, seed=<seed>)"` when the attack uses random initialisation.
- `"HopSkipJump random initial adversarial point and Monte-Carlo gradient estimate (seed=<seed>)"`.
- `"surrogate-transfer PGD: surrogate fitted at build time, seed recorded in manifest"` for tabular tree ensembles (section 12.2).
- `"SHAP GradientExplainer/DeepExplainer background sampling (background_size=<n>, nsamples=<n>)"` for images (or the `KernelExplainer` / `PartitionExplainer` equivalent); `"TreeExplainer is deterministic"` is recorded as a positive statement for tabular.
- `"CPU float32 reductions; results may differ across BLAS builds and thread counts"` always.
- `"Uniform noise control drawn with numpy default_rng(seed)"`.
- `"LLM narrative is nondeterministic (temperature=0.2); prompt and response hashes recorded"` when a narrative was generated.

Reproducibility claim: with the same `settings_hash`, `model_sha256`, `dataset_revision`, `sample_indices_sha256`, library versions and seed, measurements are expected to match to within float tolerance; the spec does not promise bit-for-bit repeatability and the report says so. `report.json` equals `RunRecord.model_dump()` and therefore contains everything needed to rerun (S2 completion criterion 3).

### 14.5 Limitations are always present

`RunRecord.limitations` is non-empty on every succeeded run; the existing validator (`_limitations_required_when_done`) enforces it and `tests/ml/test_schema.py` covers it. `STANDING_LIMITATIONS` is retained with two changes:

1. The CIFAR-10 sentence becomes a template filled from the dataset manifest (section 11.5): `"<dataset name> is an open, unclassified public benchmark; it is not a proxy for any operational domain, sensor, or deployment condition."` CIFAR-10 remains the CI fixture and the sentence is exercised in tests with that name.
2. The single-budget sentence is emitted conditionally: when a sweep ran it reads `"Results come from a single seed; the ε grid was <grid>."`, otherwise the original text.

Every other standing limitation stays verbatim: SHAP attributions describe sensitivity, not cause; the evaluation slice is small and per-class numbers have wide uncertainty; white-box gradient attacks assume full model access and black-box/physical-world attacks were not evaluated (adjusted to name the black-box attack when HopSkipJump ran); recommendations are candidates and none has been validated against this model; passing or failing this suite does not establish safety, robustness in general, or deployment readiness.

Stage-specific limitations are appended by the stage that knows them: the dataset caveats of section 11.3; `explain_k` samples explained out of `n`; explanations computed at the reference budget only (13, 15.1); "white-box via surrogate transfer" for tabular tree ensembles (12.2); the realizability caveat for tabular feature-space perturbations (12.9); the straight-through gradient approximation through a preprocessing defense in verify runs (16.5); a Pythia narrative present or absent and why (16.3); any partial stage.

Limitations render on every run page, every finding page, in every report format, and in the scorecard footer (15.7). The web footer line from S2 stays on every page: "Proof of concept on open, unclassified public data. Results are evidence for human review, not a safety, readiness, or certification determination."

### 14.6 Interpretation rules (Phase A set)

Interpretations are produced by a deterministic rule set in `aegis/ml/recommend/interpret.py`, run as the `interpret` stage of the `harden.recommend` job (section 10.2), so that every inferred sentence has a reproducible basis. The initial set:

| Id | Condition (on measurement ids) | Statement pattern | Basis |
|---|---|---|---|
| I1 | `acc(m.evasion.a.eps_ref) < acc(m.clean) − 0.20` and `|acc(m.control.noise.eps_ref) − acc(m.clean)| ≤ 0.05` | "Random noise at ε=<ε_ref> did not reduce accuracy while <a> did; the degradation is aligned with the loss gradient rather than with general noise sensitivity." | the three rows |
| I2 | `acc(m.control.noise.eps_ref) < acc(m.clean) − 0.10` | "Benign noise at ε=<ε_ref> also reduced accuracy; part of the attack effect is general input sensitivity, not only adversarial structure." | control + clean rows |
| I3 | `acc(m.evasion.pgd.epsε) < acc(m.evasion.fgsm.epsε) − 0.10` for any grid ε | "The iterative attack degraded the model more than the single-step attack at the same ε; single-step results understate the exposure." | both evasion rows |
| I4 | mean `center_mass_ratio_adv` on flipped observations ≤ mean `center_mass_ratio_clean` − 0.15 | "On the flipped samples, attribution moved away from the central region of the image under attack (heuristic centre-mass proxy)." | the observation ids |
| I5 | `expl_shift_mean(ε_ref) ≥ 0.5` | "Attributions changed substantially between clean and adversarial inputs (mean explanation shift <value>); the model's stated reasons are not stable under this perturbation." | the ε_ref evasion row |
| I6 | `conf_gap_mean(ε_ref) ≥ 0.5` | "Wrong predictions under attack were made with high confidence (mean gap <value>); confidence is not a usable signal of attack at this ε." | the ε_ref evasion row |

Thresholds (0.20, 0.05, 0.10, 0.15, 0.5) are defaults in the `scoring` config block (15.3) and are printed next to each statement. Every statement carries `kind: "inferred"`. No statement asserts a cause in the model's training data or architecture; the S1 §7 demo sentence "the model relied on background pixels rather than the target" is permitted only as an I4 statement, labelled inferred and heuristic, never as a caption on a measurement.

### 14.7 Illustrative results, fixtures and unimplemented paths

- **Illustrative is a label, not a tone.** Any number in this spec, in the demo script (section 24), in a screenshot, or in seeded demo content that did not come from a completed run is labelled "illustrative". The demo script's "about 38", "about 71" and "+33" are illustrative (D9(v)).
- **No fixture data presented as results.** The vitest fixture `RunRecord` and the pytest `TinyTarget` (`tests/ml/fakes.py`) exist only under `tests/`. The API never serves a fixture; the web app never renders one outside its test runner; there is no "sample results" mode. The readiness checklist item "Incomplete integration is not concealed by fallback fixtures or fake results" is the gate (section 19).
- **Unimplemented paths fail visibly.** A `TargetInfo` with `status: "not_implemented"` carries a `reason`; launching against it returns HTTP 501 (section 17) and the run page shows the reason and no panels (section 18). An unsupported explainer produces an "unsupported" state and no heatmap (F005 FR-006, SC-002). Never a placeholder image, never a zeroed table.
- **Passing is not readiness.** No page, report, badge or grade uses the words "safe", "certified", "deployment-ready", "hardened" or "fielding" as a status. Section 15.5 rewords the grade readings accordingly; section 16.3 bans them from the LLM narrative.

### 14.8 Reports

Reports (`GET /v1/runs/{id}/report.{md,json,html}`, section 17) contain six sections in this fixed order, and `tests/ml/test_report.py` asserts the order:

1. **Configuration and provenance** (`config`, `provenance`, including `settings_hash`, `baseline_run_id` and `parent_run_id`).
2. **Measurements** (table by family with denominators; per-class table; the robustness curve; the MRI scorecard as a derived-summary sub-block that cannot appear elsewhere, 15.7).
3. **Observations** (gallery with artifact ids and hashes; centre-mass ratios marked heuristic).
4. **Interpretation** (each statement with `inferred` label and basis).
5. **Candidate recommendations** (each with `candidate` label, validation state, triggering ids, references, and the narrative block labelled with its source).
6. **Limitations** (followed by reviewer notes when present).

`report.json` is `RunRecord.model_dump(mode="json")` plus the `MRIRecord`. HTML escapes all user-derived strings (class names, model names, dataset names) and is served with the CSP from section 17. A verify run's report additionally contains the ΔMRI block (15.6) inside section 2 and lists the changed variable (the defense) explicitly (F007 FR-007).

### 14.9 Principle-to-enforcement map

| Principle (source) | Requirement in this spec | Enforced by |
|---|---|---|
| Match evidence to the evaluated system; do not require SHAP everywhere (brief) | Explainer per modality (13); unsupported explainer → "unsupported" state, `S_expl` unavailable, MRI not computed (15.4) | `Target` capability flags; UI state; scoring guard |
| Distinguish observed behaviour from inferred causes (brief; constitution III) | Four types, four panels, `Literal` labels (14.1) | `aegis/ml/schema.py`; `tests/ml/test_schema.py`; vitest label assertions (22) |
| Record versions, configuration, limitations (brief; constitution V) | `Provenance` + `limitations` mandatory (14.4, 14.5) | validator; report section 1 and 6 |
| Results by test family with denominators; avoid a universal score mixing domains (brief; F005 FR-005; F007 FR-008) | Rows per family/setting with `n` (14.2); MRI per campaign, single modality, never aggregated across domains, never shown without its table (15.8) | schema; scorecard component; comparison guard |
| Benign controls and human review (brief) | Noise control per ε (14.3); gallery + reviewer notes + F006 states (6) | pipeline `control` stage; UI |
| Label illustrative results; do not invent runs, improvements or validated fixes (brief; constitution III) | 14.7; ΔMRI is the only gain and only when measured (15.6, 16.4) | spec text; schema validator on `measured` |
| Recommendations are candidates until a separate evaluation (brief; F006 FR-008) | `status: "candidate"` permanently; verify run measures, humans review; nothing is applied to the stored model (16.4, 16.5) | `Literal`; verify job design |
| Passing ≠ safety or readiness (brief; constitution III; F005 FR-011) | Standing limitation; scorecard footer; banned words (14.7, 15.5, 16.3) | text; narrative post-check |
| Evidence integrity (constitution VI; F008) | Artifact `sha256` recorded in `Observation.artifact_sha256` and must equal `Artifact.sha256`; audit events for upload/validate/attack/explain/harden/verify (5, 10) | `Artifact` unique constraint; audit chain |

## 15. Scoring — Model Robustness Index

The Model Robustness Index (MRI) is adopted from S1 §8 (D9) as the per-campaign summary of robustness under the in-scope attacks. It is a 0–100 integer, higher is more robust. It drives the scorecard, the derived Finding severities (15.5) and the ranking of candidate recommendations (16.1). It is deterministic and recomputable from the stored measurements: `aegis.ml.scoring.compute_mri(measurements, observations, settings)` is a pure function, the stored score record carries its inputs, and `tests/ml/test_scoring.py` asserts that recomputation reproduces the stored value.

S1 §8 opened with "the tool reduces every campaign to one number". Under D9 the sentence is replaced: the tool **summarises** a campaign with one number that never travels without the evidence it was computed from (15.8). The brief's principle "avoid a universal score that mixes unrelated domains" is honoured by construction: an MRI is computed for one model × one modality × one declared attack set × one declared ε grid × one reference budget, and nothing in the platform can add, average or rank MRIs across those boundaries. The reconciliation table (section 4) records this as a bounded divergence from the brief's wording (D9(vi)).

### 15.1 Inputs

For each in-scope attack `a` and each ε in the declared grid the engine records the following, all derived from `Measurement` and `Observation` rows of the same run (14.2). The reference budget `reference_eps` is written ε_ref below. Where a quantity needs a field the current schema lacks, the field is named here and in section 12.5 and added in M1 (section 5.3, section 23).

| Input | Definition | Source row / field | Denominator disclosed |
|---|---|---|---|
| `acc_clean` | Accuracy with no attack on the sampled slice | `m.clean.accuracy = n_correct / n` | `n` |
| `acc_adv(a, ε)` | Accuracy on the adversarial examples | `m.evasion.<a>.eps<ε>.accuracy` | `n` |
| `asr(a, ε)` | Attack success rate: fraction of inputs correctly classified on clean data whose adversarial counterpart is misclassified | `m.evasion.<a>.eps<ε>.n_flipped_from_clean / m.clean.n_correct` (stored as `attack_success_rate` with `n_clean_correct`) | `m.clean.n_correct` |
| `pert(a)` | Mean perturbation size at first success, in the attack's Lp norm: for each sample that flips at any grid ε, the measured norm of the adversarial example at the smallest ε at which it flipped; mean over those samples | `Measurement.pert_first_success_mean` on the attack's ε_ref row, computed from the per-sample flip matrix artifact (`Artifact.kind = "ml.flip_matrix"`, section 5.8) | `pert_first_success_n` (number of flipped samples) |
| `conf_gap(a, ε)` | Mean confidence on the wrong label minus the right label. Computation detail fixed by this spec: per sample `g_i = max(0, max_{j≠y_i} p_j(x_adv_i) − p_{y_i}(x_adv_i))`, mean over all `n` samples, so a robust model scores 0 rather than "undefined" | `Measurement.conf_gap_mean` | `n` (`conf_gap_n`) |
| `expl_shift(a, ε)` | `clamp(1 − cos(flatten(φ_clean), flatten(φ_adv)), 0, 1)` where `φ` is the SHAP attribution for the clean-predicted class; per explained sample, then mean (definition fixed in section 13.5) | `Observation.expl_shift`; aggregate in `Measurement.expl_shift_mean` and `Measurement.expl_shift_n` | `expl_shift_n` (≤ 2·`explain_k`) |
| `queries(a)` | Model queries needed to break the model; black-box attacks only, counted by the `Target` wrapper's prediction counter, mean over flipped samples | `Measurement.queries_mean` | number of flipped samples |

Notes fixed by this spec:

- Explanations, and therefore `expl_shift`, are computed at the reference budget ε_ref only in Phase A, to bound SHAP cost (section 25). `Measurement.expl_shift_mean` is `None` on other ε rows.
- For decision-based attacks with no ε knob (HopSkipJump, Boundary), "success at ε" is defined by thresholding the returned adversarial example: a sample counts as flipped at ε when its label differs from the clean prediction and its perturbation norm in the declared norm is ≤ ε. This lets the same grid apply to every attack in the set (section 12.3).
- `pert(a)` and `queries(a)` are recorded and displayed on the Finding (15.5) but do not enter any subscore in Phase A. This matches S1, which lists them as inputs without a weight.
- Control rows (`m.control.*`) are never inputs to the MRI. They are displayed beside the curve and read by interpretation and recommendation rules only.

### 15.2 Dimension subscores

Each subscore is on a 0–100 scale, 100 ideal, and is the unweighted arithmetic mean over the in-scope attacks of the per-attack value. Ratios are clamped to `[0, 1]` before scaling.

| Dimension | Symbol | Definition (S1 §8.2) | Per-attack computation fixed by this spec | Weight |
|---|---|---|---|---|
| Robust accuracy | `S_acc` | Worst-case `acc_adv` across ε, divided by `acc_clean` | `min_ε acc_adv(a, ε) / acc_clean` | 0.35 |
| Evasion resistance | `S_asr` | `1 − mean ASR` at the reference budget | `1 − asr(a, ε_ref)` | 0.25 |
| Budget resilience | `S_eps` | Normalised area under the robust-accuracy vs ε curve | Trapezoidal integral of `acc_adv(a, ε) / acc_clean` over the declared grid points, divided by `(ε_max − ε_min)`. The clean point `ε = 0` is drawn on the curve but not prepended to the integral, so a model that collapses at `ε_min` scores near 0. A one-point grid degenerates to the ratio at that point and the limitation is recorded | 0.20 |
| Confidence calibration | `S_conf` | `1 − clamp(conf_gap)`; a model that is confidently wrong scores low | `1 − conf_gap(a, ε_ref)` | 0.10 |
| Explanation stability | `S_expl` | `1 − mean expl_shift` | `1 − expl_shift(a, ε_ref)` | 0.10 |

Explanation stability is the SHAP-native signal (S1). A model whose attributions move to different features under a small perturbation is brittle even when its accuracy holds; this dimension is what distinguishes the tool from an accuracy-only harness. It is also the dimension most exposed to the brief's caveat that attribution is not causal proof: `S_expl` measures the *stability* of the explanation, not its correctness, and the scorecard says so in its footer.

### 15.3 Aggregate and configuration

```
MRI = round( 0.35·S_acc + 0.25·S_asr + 0.20·S_eps + 0.10·S_conf + 0.10·S_expl )
```

`round` is Python's round-half-to-even on the weighted sum; subscores are stored to one decimal. Weights sum to 1.0 and are validated to do so.

Weights, thresholds and defaults live in the `ml.scoring` config block on `AegisConfig` and are copied into `CampaignConfig.scoring` at admission (section 5.6). S1's "overridable per project" is a Phase B UI; in Phase A the deployment default applies to every project. The block:

| Key | Default | Used by |
|---|---|---|
| `weights` | `{acc: 0.35, asr: 0.25, eps: 0.20, conf: 0.10, expl: 0.10}` | 15.3 |
| `finding_asr_threshold` | 0.2 (ASR at which an attack "succeeds" and creates a Finding; section 12.6) | 15.5 |
| `severity.asr_high` / `severity.asr_mid` | 0.5 / 0.2 | 15.5 |
| `confidence.n_high` / `confidence.n_medium` | 100 / 30 (clean-correct sample counts) | 15.5, section 5.7 |
| `interpretation` thresholds | as printed in 14.6 | 14.6, 16.2 |
| `version` | scoring algorithm version string frozen into every score record | 15.7 |

Whatever the values, they are stored with each score record. A non-default weight vector puts a "non-default weights" badge on the scorecard, and two campaigns with different weight vectors are incomparable (15.6).

### 15.4 When the MRI is not computed

An MRI is computed only when all five subscores are available. Otherwise the scorecard shows the available subscores with their denominators and the text "MRI not computed: <dimension> unavailable (<reason>)". Weights are never renormalised over the available dimensions, because that would make the number incomparable with any other while looking identical. Reasons that make a dimension unavailable:

- `acc_clean == 0` or `m.clean.n_correct == 0`: `S_acc`, `S_asr`, `S_eps` undefined (denominator 0).
- No `m.evasion.<a>.eps<ε_ref>` row for some attack in the set (partial run).
- `explain_k == 0`, or the explainer is unsupported or failed for this target: `S_expl` unavailable.
- Any attack in the declared set has no rows at all (the run is `partial`; the MRI is not computed on partial runs). An attack recorded as `not_run` for a declared reason (no differentiable estimator, section 9.5) is removed from the in-scope set **before** scoring and the removal is stated on the scorecard; the MRI is then computed over the attacks that ran.

### 15.5 Grade bands and derived Finding severity

**Grade bands.** The numeric bands are S1's. The readings are reworded per D9(iii) so that they describe behaviour under the in-scope attacks at the declared settings and nothing else.

| MRI | Grade | Reading (attack-scoped) |
|---|---|---|
| 90–100 | A | Under the in-scope attacks at the declared ε grid, accuracy and attributions were essentially unchanged on this slice. |
| 75–89 | B | Minor degradation under the strongest in-scope attack at the reference budget. |
| 60–74 | C | Substantial degradation under the in-scope iterative attack at the reference budget. |
| 40–59 | D | The cheapest in-scope attack succeeded at the reference budget on a large share of the slice. |
| 0–39 | F | Predictions flipped at the smallest ε in the declared grid on most of the slice. |

The following sentence is printed under every grade, in the UI and in reports: **"A grade describes measured behaviour under the declared attack set, ε grid and slice. It is not a readiness, safety, or certification statement, and it does not describe robustness to attacks that were not run."** S1's readings "Hardened", "Harden before fielding" and "Not deployment-ready" are overridden (D9(iii)) and MUST NOT appear anywhere in the product.

**Finding severity is derived, not hand-set (S1 §8.5).** Each attack in the set whose ASR crosses `finding_asr_threshold` at any grid ε becomes one `Finding` (one per attack family per campaign, not one per sample; section 12.6). With the grid sorted ascending, `ε_small = min`, `ε_large = max`, and `ε_mid = ε_ref` when `ε_ref` is strictly between them, else the median grid point; for the default grid `{0.01, 0.03, 0.1}` with `ε_ref = 0.03` these are exactly S1's three. Severity follows from the budget at first success and the ASR, so it cannot be adjusted by inspection:

- **critical** — succeeds at `ε ≤ ε_small` with `asr ≥ 0.5`.
- **high** — succeeds at `ε ≤ ε_small` with `asr ≥ 0.2`, or at `ε_mid` with `asr ≥ 0.5`.
- **medium** — first success at `ε_mid` (and not high); or first success at `ε_small` with `asr < 0.2`, which can only occur when `finding_asr_threshold` is configured below its 0.2 default.
- **low** — first success only at `ε_large`.

This writes the existing `Finding.severity` column, whose vocabulary `Severity = Literal["critical","high","medium","low"]` (`aegis/schema.py`) matches exactly, so the findings table, filters, dashboard counts and audit trail work unchanged. The other required `AegisFinding` fields are filled deterministically (section 5.7): `title` = `"<attack> flips predictions at ε=<first-success ε> (<norm>; ASR <n_flipped>/<n_correct_clean>)"`; `finding_type` = `adversarial_ml` (the new `FindingType` literal registered in section 5, matching S1's `adversarial_ml` capability tag); `description` = measurement text only; `confidence` = `high` when `m.clean.n_correct ≥ confidence.n_high`, `medium` when `≥ confidence.n_medium`, else `low` (sample-size based, not judgement based); `source_tool` = `aegis.ml/<attack_id>`; `status` = `open`; `evidence` = the measurement ids. The `ml` sub-object of `Finding.schema_blob` (section 5.7) stores the full derivation: attack id and resolved params, grid, per-ε `asr` and `acc_adv` with denominators, first-success ε, `pert`, `conf_gap`, `expl_shift`, `queries`, SHAP artifact ids, and the thresholds used, so severity is recomputable and auditable. Scoring writes `severity` and (via verify, 15.6) `validation_state`; it never writes `Finding.status`, whose transitions are in section 6.

### 15.6 ΔMRI on verify

After the user triggers the verify loop (16.5) a new run is created with `baseline_run_id` set (sections 5.6, 14.4). The tool then reports **ΔMRI = MRI(verify run) − MRI(baseline run)** together with each per-dimension delta and, mandatorily beside it, the change in clean accuracy (`acc_clean(verify) − acc_clean(baseline)`, with both fractions), because a preprocessing defense can buy robustness with clean accuracy.

Preconditions, enforced server-side before a delta is computed or displayed:

- Both runs have a computed MRI (15.4).
- `settings_hash` is equal. The hash is defined in section 5.6: sha256 over the canonical JSON of `CampaignConfig` excluding `defense`, `llm_narrative` and `target_snapshot`, concatenated with the model `sha256`; it therefore covers modality, the attack set with resolved params, `norm`, `eps_grid`, `reference_eps`, dataset id, revision and split, `n_samples`, `seed`, `finding_asr_threshold` and the whole `scoring` block. `Provenance.sample_indices_sha256` must also match.
- Same base model: `model_sha256` equal; the only changed variable is the defense recorded in `Provenance.defense`, and the comparison lists it as the changed variable (F007 FR-007).

If any precondition fails the UI shows "not comparable: <reason>" and no delta is calculated (F007 US comparison scenario). A same-settings comparison of two *different* models is a side-by-side of two full scorecards and their tables, never a single delta; the word ΔMRI is reserved for the verify pairing.

Verify also writes `Finding.validation_state` on each Finding of the baseline run through the worker's `VerifyStatus` and the existing `_STATE_MAP` (`aegis/workers/tasks/verify.py`): `verified` → `poc_passed` when the attack family no longer crosses `finding_asr_threshold` at any grid ε in the verify run, `still_vulnerable` → `poc_failed` when it still does, `inconclusive` → `inconclusive` when the verify run failed or is partial. `Finding.status` follows section 6.4. The UI renders `poc_passed` as "verified: attack no longer crosses threshold at these settings with <defense>", never as "fixed" or "resolved" (section 6).

S1 §8.6 said a recommendation's expected gain is checked against the actual ΔMRI. Under D9(iv) there is no expected gain to check: the measured ΔMRI is the only figure a recommendation ever carries (16.4).

### 15.7 Storage and display

The campaign score record is the `MRIRecord` of section 5.6 (`ml_campaigns.score`, mirrored as the `ml.score` artifact). It MUST contain: `mri: int | None`, `grade: str | None`, `completeness` and `missing` (the not-computed reasons), `subscores` (`S_acc`, `S_asr`, `S_eps`, `S_conf`, `S_expl`, each `float | None`) with their denominators in `inputs`, the `per_attack` breakdown of each subscore, `weights`, `eps_grid`, `reference_eps`, `norm`, `attack_ids`, `finding_asr_threshold`, `settings_hash`, `computed_at`, `scoring_version`, `reading`, and on verify runs `delta` (`baseline_run_id`, `mri_before`, `mri_after`, `delta`, per-dimension deltas, `delta_acc_clean`). The `campaign.score` audit event (section 5.11) records the score record's content hash and `settings_hash` alongside the number, so `aegis audit verify` proves integrity.

The scorecard component (section 18) is the only place the MRI is rendered, and it always renders as one block containing, top to bottom: the number and grade; the five subscore bars with their per-attack values and denominators; the robustness curve (evasion and control lines per attack, section 12); the per-family accuracy table with `n`; the grade sentence from 15.5; the limitations relevant to scoring (`explain_k`, ε_ref-only explanations, slice size). In reports it is a sub-block of section 2 (14.8). The runs list, findings list, dashboard tiles, notifications and audit pages carry no MRI value; the model page's campaign history shows the MRI only as a link into the full scorecard.

### 15.8 Normative constraints (D9)

The following are requirements; a build that violates any of them fails section 26.

- **(i) Scope.** An MRI is computed per campaign, defined as one model × one modality × a declared attack set × a declared ε grid × a reference budget. It MUST NOT be aggregated, averaged, ranked or otherwise combined across modalities, domains, models or campaigns, and MUST NOT be compared with a campaign whose `settings_hash` differs. There is no project-level or model-level "overall" score.
- **(ii) Companions.** The MRI MUST never be shown without, on the same screen or page: its five subscores with denominators, the per-test-family accuracy table with `n`, and the ε curve. Any surface that cannot show all three shows no MRI.
- **(iii) Wording.** Grade readings describe behaviour under the in-scope attacks only, using the table in 15.5. The words "hardened", "harden before fielding", "deployment-ready", "not deployment-ready", "certified", "safe" MUST NOT appear as grade text, badge text or generated narrative. Every grade is accompanied by the statement that no grade is a readiness or certification statement.
- **(iv) Gain.** ΔMRI is a measured delta on this model at these settings and is the only sanctioned form of "gain". A recommendation carries no numeric expected gain, range, or estimate until the verify loop has measured it (16.4). Rule text and narrative may describe direction ("intended to reduce ASR at small ε") but never magnitude.
- **(v) Illustrative numbers.** The numbers in the demo script (section 24: "about 38", "about 71", "+33") and in any screenshot or seeded content that did not come from a completed run are labelled illustrative wherever they appear.
- **(vi) Reconciliation.** Section 4 records the MRI as a divergence from the brief's "avoid a universal score" principle, justified as a per-campaign summary that never mixes domains and always travels with its denominators; the constitution amendment proposal for Principle III (D12(c)) cites constraints (i)–(iv) as the conditions that keep evidence distinguishable.

## 16. Hardening recommendations

`aegis/ml/recommend/` turns measured results into candidate actions in two layers (S1 §9): a deterministic rule layer and an LLM writer layer that rewrites rule output into prose through Pythia (D5). The output is a list of `CandidateRecommendation` objects (14.1). Nothing in this section applies a change to the stored model, the target, or a profile (F006 FR-008; brief: "Autonomous application of proposed mitigations" is out of scope). The only executable path is the user-triggered verify loop (16.5), which measures a preprocessing defense on a worker-side copy of the evaluation pipeline and reports the delta.

### 16.1 Where it runs

- The **rule layer** runs as the `interpret` and `recommend` stages of the `harden.recommend` job (section 10.2), which is pre-created at admission and runs after `explain.run`, so every completed campaign has candidates without a user action. It runs there rather than at the end of `attack.run` because rules R3/R3t read explanation outputs. It needs only the run's own `Measurement`/`Observation` rows.
- The **LLM writer** runs in the same job, only when `CampaignConfig.llm_narrative` is true and Pythia is configured; `POST /v1/findings/{id}/harden` (section 17) creates a follow-on `harden.recommend` job to regenerate. It never blocks or fails the campaign: a narrative failure leaves the rule output standing (16.3).
- Rule outputs are ranked deterministically: by the derived severity of the triggering Finding (15.5), then by the magnitude of the triggering degradation (`acc_clean − acc_adv` at `ε_ref`), then by rule id. The ranking is stored, so the UI, the report and the narrative show the same order.

### 16.2 Rule layer

Each rule cites the measurement or observation ids that triggered it in `triggered_by`, carries its `references`, and emits `status: "candidate"`, `validation: "not evaluated"`. Thresholds are the `scoring` block defaults (15.3) and are printed in the rationale. The Phase A rule set merges S1 §9's four examples with S2 §2.5's five rules; every source row appears below.

| Id | Trigger (measurement ids) | Candidate (title) | Rationale pattern | ART link (16.6) | Source |
|---|---|---|---|---|---|
| R1 | `asr(fgsm, ε_small) ≥ 0.2` and `|acc(m.control.noise.eps_ref) − acc(m.clean)| ≤ 0.05` | Adversarial training (PGD-based) and gradient-masking review | "Single-step FGSM succeeded at the smallest ε (<n_flipped>/<n_correct_clean>) while random noise at ε_ref did not reduce accuracy, so the failure is gradient-aligned; adversarial training targets this directly. Review the model for gradient masking before trusting any defense that only hides gradients." | `AdversarialTrainerMadryPGD` (Phase B apply) | S1 rule 1 + S2 rule 1 |
| R1b | `asr(fgsm, ε_small) ≥ 0.2` and `acc(m.control.noise.eps_ref) < acc(m.clean) − 0.10` | Noise-robust training and input-quality controls | "Both the attack and benign noise degraded accuracy; part of the exposure is general input sensitivity. Augmentation with the same noise family and input-quality checks are candidates alongside adversarial training." | none in ART (training-side) | S2 control principle |
| R2 | `acc(m.evasion.pgd.epsε) < acc(m.evasion.fgsm.epsε) − 0.10` for any grid ε | Evaluate with iterative attacks at multiple ε and iteration counts before relying on results | "PGD degraded the model more than FGSM at ε=<ε>; single-step results understate exposure. Any future evaluation of this model should include iterative attacks across the grid." | none (evaluation practice) | S2 rule 2 |
| R3 | mean `center_mass_ratio_adv` on flipped observations ≤ mean `center_mass_ratio_clean` − 0.15 (image) **or** `expl_shift_mean(ε_ref) ≥ 0.5` (any modality) | Investigate reliance on peripheral or irrelevant features; input preprocessing, feature squeezing, spatial smoothing, cropping/augmentation, retraining with masking | "Attribution moved away from the central region on <k> of <n_flipped> flipped samples (heuristic centre-mass proxy) / attributions shifted by <value> on average. This is consistent with reliance on features a small perturbation can change." Marked heuristic. | `FeatureSqueezing`, `SpatialSmoothing` (Phase A verify) | S1 rule 2 + S2 rule 3 |
| R3t | tabular: the top-3 SHAP features under attack differ from the clean top-3 on ≥ 50 % of flipped samples | Feature range validation and clipping at inference; monotonic constraints where the domain allows | "On <k> of <n_flipped> flipped rows the features driving the prediction changed under attack. Validating and clipping feature ranges at inference bounds what an L∞ perturbation can reach." Marked heuristic. | `FeatureSqueezing` on standardised features; estimator `clip_values` (Phase A verify) | tabular analogue required by D4(d) |
| R4 | `conf_gap_mean(ε_ref) ≥ 0.5` | Confidence calibration and an out-of-distribution reject option | "Wrong predictions under attack carried a mean confidence gap of <value>; the model is confidently wrong. Calibrated confidences and a reject option make attacks detectable at the decision point." | none in ART (calibration is training-side; ART postprocessors alter reported confidences and are not calibration) | S1 rule 3 |
| R5 | a black-box attack (HopSkipJump/Boundary) crosses `finding_asr_threshold` with `queries_mean ≤ query_budget` | Rate limiting and query-pattern monitoring at the inference API | "The decision-based attack succeeded on <n_flipped>/<n_correct_clean> within <queries_mean> queries on average. Limiting and monitoring query volume per client raises the attacker's cost." Applies to the Phase A tabular black-box test and to Phase B endpoint targets. | none (operational control) | S1 rule 4 |
| R6 | any evasion row with `accuracy < acc(m.clean) − 0.05` | Input preprocessing defenses as a cheap first experiment (JPEG compression, spatial smoothing, feature squeezing) | "Accuracy fell from <clean> to <adv> at ε=<ε>. Preprocessing defenses are cheap to test with the verify loop. Caveat: defenses that work by masking gradients are often bypassed by adaptive attacks (Athalye, Carlini, Wagner 2018); a measured ΔMRI here is an upper bound on their benefit." | `JpegCompression` (image), `SpatialSmoothing` (image), `FeatureSqueezing` (image, tabular) (Phase A verify) | S2 rule 4 |
| R7 | always | Rerun with a larger slice and a different seed before drawing conclusions | "This run evaluated <n> samples with seed <seed>. Per-class counts in particular have wide uncertainty." | none | S2 rule 5 |

`tests/ml/test_recommend.py` asserts that each rule fires on a synthetic measurement set and cites the right ids, and that nothing but R7 fires on a flat set. Rule ids are stable so that `r.R3` in one run means the same rule in another.

### 16.3 LLM writer layer via Pythia

The writer rewrites the ranked rule output into a concise plain-language report with prioritised steps. It is a presentation layer over the rules: it may not add claims, numbers or recommendations, and it never carries the "expected robustness gain" that S1 §9 asked for (overridden by D9(iv)).

**Transport (D5).** Every call goes through Pythia, IntelliBridge's OpenAI-compatible agent gateway: `POST {PYTHIA_BASE_URL}/v1/chat/completions`, header `Authorization: Bearer pk_…`, optional `X-Pythia-Persona`, model id in canonical `<vendor>/<model>` form or `pythia/auto`. The implementation is `aegis/llm/pythia.py` (`PythiaSettings`, `chat_text`, `make_backend`, which prefers the official `pythia_sdk` and falls back to `httpx`). aegis holds only the Pythia key; provider keys live in Pythia (section 21). There is no litellm path and no direct provider client. One plain, non-streaming chat completion per narrative (`chat_text`: one system message, one user message, `temperature=0.2`, `max_tokens=800`); no tools, no vision, no structured-output mode.

**Configuration.** `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA` (optional), `PYTHIA_TIMEOUT_S` (default 60) and `AEGIS_ML_LLM_MODEL` (section 20.3). `aegis/llm/pythia.py` currently reads `REDSIM_LLM_MODEL`; renaming it to `AEGIS_ML_LLM_MODEL` is an M0 task (D5, D7; section 23). `CampaignConfig.llm_narrative` defaults to `false`; the launcher (section 18) offers the checkbox only when `/v1/ml/capabilities` reports Pythia as configured, and the demo profile turns it on.

**Policy layer.** The model id is resolved through the existing router: `aegis.llm.router.route(task="ml.harden_narrative", …)` reads `config.task_models["ml.harden_narrative"]` (seeded from `AEGIS_ML_LLM_MODEL`), honours the per-organisation override (`Organization.llm_model_overrides`), and applies the per-project daily and per-organisation monthly budget caps through `DbBudgetChecker`; `enforce_budget_for_run` runs as a fail-closed pre-flight when `llm_budget_strict` is set. The resolved id MUST be a Pythia canonical id; the router rejects anything else for this task. Token usage from Pythia's `usage` block and cost via `aegis.llm.pricing` are written to `LLMUsage` (`task = "ml.harden_narrative"`, section 5.12) exactly as for every other routed call, so the cost page (section 18) shows narrative spend.

**Payload: text only.** The user message is assembled by `aegis/ml/recommend/narrative.py` from exactly:

1. The measurements table as text: family, attack, ε, `n_correct/n`, ASR as `n_flipped/n_correct_clean`, control rows, with the slice header (14.2).
2. The scorecard numbers: MRI, grade, five subscores with denominators, or the "not computed" reason (15.4).
3. The ranked rule outputs: id, title, rationale, triggering ids.
4. The SHAP **text** summary of section 13.7 (`ml.shap.summary_text`): mean `expl_shift` with its `n`; for images the mean centre-mass ratios clean vs adversarial on flipped samples, labelled heuristic; for tabular the top-k feature names by mean |SHAP| clean vs adversarial.
5. The run's limitations list.

It MUST NOT contain: images or image bytes, SHAP arrays, adversarial examples, model weights or architecture, dataset samples, target URLs or credentials, user or organisation identifiers, or reviewer notes. The system prompt states the contract: rewrite the rule outputs into prose for a technical reader; keep every number identical to the input and cite no number not present in it; add no recommendation, cause or claim not present in the rule outputs; do not use the words "validated", "proven", "guaranteed", "hardened", "deployment-ready", "certified", "safe"; describe recommendations as candidates and say that none has been evaluated on this model unless a measured ΔMRI is included in the input.

**Guardrails.** `guard_input` runs on the assembled user message (model, dataset and class names are user-supplied strings and could carry an injection); `guard_output` scrubs the response with the same token signatures the audit chain trusts (`aegis/llm/guardrails.py`, `aegis/audit/redact.py`). Two further post-checks are specific to this writer: a **numeric-consistency check** rejects a narrative containing a number token absent from the payload, and a **banned-word check** rejects a narrative containing any word from the list above. A rejected narrative is discarded, `narrative_source` stays `"rules"`, and the UI shows "LLM narrative: rejected by post-check (<reason>)".

**Failure semantics.** `PythiaSettings.from_env()` returning `None` raises `PythiaUnavailable`; the job records "LLM narrative: not configured" and succeeds. HTTP errors, timeouts, `BudgetExceeded`, `GuardrailViolation` and an unexpected response shape are recorded as "LLM narrative: unavailable (<class>)" and the job succeeds. The narrative is never required for a Finding, a score or a report to exist (section 10.8).

**Audit and provenance.** Each narrative attempt is part of the `harden.execute` audit event (section 5.11) with outcome, `PythiaSettings.redacted()` (gateway, base URL, model, persona; never the key), `prompt_sha256`, `completion_sha256`, token counts and the run/finding ids; the prompt and completion texts are the `ml.harden.prompt` / `ml.harden.completion` artifacts. The same data is written to `Provenance.llm` (14.4). Regenerating a narrative is a new job, a new attempt and a new event; the previous narrative is replaced in the record but the audit chain keeps both hashes.

**Display.** The narrative appears inside the Candidate recommendations panel, below the rule cards, under the heading "LLM-generated narrative of rule outputs (via Pythia, `<model id>`)" (S2), never instead of the rules and never in the Measurements or Interpretation panels.

### 16.4 Candidate status and the measured-ΔMRI rule

This subsection states the rule precisely because it is where S1 §9/§11 ("expected gain") and the brief ("treat recommendations as candidates until supported by a separate evaluation") disagreed. D9(iv) decides.

1. `CandidateRecommendation.status` is `Literal["candidate"]` and stays so for the life of the record. The tool never marks a recommendation "validated", "proven" or "applied". The only stronger word available is a human one: an F006 reviewer confirming a finding revision that cites the recommendation (section 6), which is recorded as a review decision, not as a property of the recommendation.
2. `CandidateRecommendation.validation` is extended from `Literal["not evaluated"]` to `Literal["not evaluated", "measured"]`, and a new optional field `measured: MeasuredDelta | None` is added (M6, sections 5.3, 23). `MeasuredDelta` has `verify_run_id`, `baseline_run_id`, `defense` (class and parameters), `delta_mri: int`, `delta_subscores`, `delta_acc_clean`, `settings_hash`, `measured_at`. A model validator rejects `validation == "measured"` without a `measured` block and `measured` without `validation == "measured"`; `tests/ml/test_schema.py` asserts both.
3. Until a verify run has measured it, a recommendation displays **"Expected gain: not measured — run Verify"**. No number, range, arrow or qualitative magnitude ("large improvement") is shown or generated. Rule rationale and narrative may state the intended direction only.
4. A measured ΔMRI attaches only to the recommendation whose defense the verify run applied (`Provenance.defense` matches the recommendation's ART link), and only when the ΔMRI preconditions of 15.6 hold. Other recommendations in the same run remain `not evaluated`.
5. The displayed measured figure always reads as a delta at settings: **"Measured ΔMRI +<d> (MRI <a> → <b>; clean accuracy <c1> → <c2>; verify run <id>, settings <hash prefix>, defense <class(params)>)"**, with the per-dimension deltas one click away. It is never shortened to a bare "+<d>".
6. A measured delta is evidence about this model, this slice, this defense and this attack set. It is not transferable: the record does not carry it into another campaign, and the UI does not show a recommendation's past measured delta on a different run.

### 16.5 Verify-after-harden loop (D4(a))

"Verify fix" on a recommendation whose ART link is a Phase A preprocessing defense enqueues `verify.replay` (section 10.2) with `baseline_run_id` and the defense configuration. The worker:

1. Loads the same model artifact (same `model_sha256`) in the sandboxed loader (section 9) and the same dataset revision, split, indices and seed as the baseline (`settings_hash` equality, 15.6).
2. Wraps the ART estimator with the chosen preprocessor as `preprocessing_defences` (ART supports this on `PyTorchClassifier`, `SklearnClassifier` and `XGBoostClassifier`), so both prediction and attack go through the defense.
3. Re-runs the identical attack set and ε grid, the noise control, and the explanations at `ε_ref`; writes a full `RunRecord`; computes the MRI and ΔMRI; updates `Finding.validation_state` and `Finding.status` on the baseline's findings (15.6, section 6.4); attaches the `MeasuredDelta` to the recommendation (16.4).
4. Appends the `verify.execute` audit event (section 5.11) and records `Provenance.defense` and the verify-specific limitation below.

Defaults for the Phase A defenses, recorded in provenance and overridable in the verify dialog:

| Defense | ART class | Default parameters | Modalities |
|---|---|---|---|
| Feature squeezing | `art.defences.preprocessor.FeatureSqueezing` | `bit_depth=4`, `clip_values` from the target | image, tabular (standardised features) |
| Spatial smoothing | `art.defences.preprocessor.SpatialSmoothing` | `window_size=3` | image |
| JPEG compression | `art.defences.preprocessor.JpegCompression` | `quality=50`, `clip_values` from the target | image |

Standing limitation appended to every verify run: "The white-box attacks in this run used ART's straight-through gradient estimate through the preprocessing defense. Adaptive attacks that account for the defense may succeed where these did not, so the measured ΔMRI is an upper bound on the defense's benefit against these attacks, not a general robustness gain."

What the loop is not: it does not modify the uploaded or bundled model artifact, does not persist a defended model, does not change the target or any profile, and is never triggered automatically. It is a measurement of a candidate on a worker-side copy, started by an authorised user (section 7), which is what the brief's "separate evaluation" requires and what the constitution's Principle III means by "a separate comparison".

Adversarial training (R1) and defensive distillation are Phase B "apply" steps (S1 Phase B; section 3). Their "Verify fix" button reads "Apply and re-measure: Phase B (not implemented)" and is disabled; no delta is shown or estimated for them.

### 16.6 ART defense linkage

Each recommendation's `references` include the ART class path (or an explicit "no ART implementation") and the paper that motivates the defense, so a reader can find the implementation and the known bypasses. S1's four named defenses all appear; the table also records which are runnable in Phase A.

| Candidate | ART implementation | Phase | Runnable by verify loop | Known bypass to disclose in rationale |
|---|---|---|---|---|
| Adversarial training | `art.defences.trainer.AdversarialTrainer`, `AdversarialTrainerMadryPGD` | B (apply on a bundled model, S1 Phase B) | no | Robustness is specific to the training threat model and ε |
| Feature squeezing | `art.defences.preprocessor.FeatureSqueezing` | A | yes | Gradient-masking defenses are bypassed by adaptive attacks (Athalye, Carlini, Wagner 2018) |
| Spatial smoothing | `art.defences.preprocessor.SpatialSmoothing` | A | yes | Same as above |
| JPEG compression | `art.defences.preprocessor.JpegCompression` | A (image) | yes | Same as above |
| Defensive distillation | `art.defences.transformer.evasion.DefensiveDistillation` | B | no | Broken by the C&W attack (Carlini and Wagner 2017); listed for completeness, ranked last |
| Confidence calibration / reject option | none; temperature scaling is a training-side change. ART postprocessors (`HighConfidence`, `ReverseSigmoid`, `Rounded`) obfuscate reported confidences and are not calibration | B | no | Output obfuscation does not change the decision boundary |
| Feature range validation / clipping (tabular) | estimator `clip_values`; `FeatureSqueezing` on standardised features | A | yes | Bounds only what lies outside the valid range |
| Rate limiting / query monitoring | none (operational control at the inference API) | Phase B endpoint targets; advisory for the Phase A tabular black-box test | no | Does not stop transfer attacks |
| Noise-robust training / augmentation | none in ART (training-side) | B | no | Does not address gradient-aligned perturbations on its own |

## 17. API surface

The ML vertical reuses the `/v1` router, the auth stack and every cross-cutting middleware of the restored aegis API (`aegis/api/app.py`): OIDC bearer verification against the Keycloak JWKS, the `dev:<email>` bearer in `AEGIS_AUTH_MODE=dev` (rejected when `AEGIS_ENV=prod`), the `aegis_api_session` cookie with `X-Aegis-CSRF` double-submit on mutations, the tenant middleware that pins Postgres RLS to the caller's organisations, the per-user / per-project rate limiter on write routes, `X-Aegis-Request-ID` correlation, OTel and the `/metrics` endpoint. New routes are added as new modules under `aegis/api/v1/` (section 8.3) and mounted with the same `prefix="/v1"`.

Three rules apply to every route in this section:

1. **Admission before enqueue.** Every mutating call goes through a service in `aegis/services/` that appends the hash-chained audit event *before* the `Run`/`Job` rows are written and before Celery is touched, exactly as `services.scans.create_scan_job` and `services.verify.create_verify_job` do today (section 10). Audit action names are fixed in section 5.11; the ones emitted at admission are repeated in the tables below.
2. **Role gates are aegis roles.** Minimum roles are the `Action` values enforced by `aegis/api/policy.py` (`scanner` < `remediator` < `approver` < `admin`), as defined once in section 7.4. The mapping of William's Owner / Analyst / Reviewer / Viewer onto these roles is in section 7 and is not repeated here. Read routes require project membership (`ensure_project_access`), and list routes are scoped by `accessible_project_ids`.
3. **Nothing runs in the API process.** Upload handlers perform static checks and stream bytes to the blob store; model loading, attacks, SHAP, hardening and verification happen only on the worker inside the plugin sandbox (sections 9 and 10, D2). A queue or worker outage is a 503, never an in-process fallback (constitution IV).

### 17.1 Routes retained from aegis

| Method | Path | Gate | State in this fork | Use in the ML vertical |
|---|---|---|---|---|
| `GET` | `/health` | none | kept, unchanged | Liveness for ALB / compose health checks. |
| `GET` | `/metrics` | none | kept, unchanged | Prometheus scrape. |
| `GET` | `/v1/runs?project=&limit=` | membership | kept, unchanged | Campaign list. Campaign runs carry `Run.scanner = "ml.campaign"` (verify runs `ml.verify`, ingest runs `ml.ingest`; section 5.2) and `Run.mode = "api"`. |
| `GET` | `/v1/runs/{run_id}` | membership | kept, unchanged | Status, `stage_table`, `completed_at`. The wire shape is deliberately untouched so the existing web tests keep passing; the campaign record is served by a new sibling route (17.2). |
| `POST` | `/v1/runs/{run_id}/cancel` | `RUN_CANCEL` (remediator) | kept; **one new rejection** | Cancels every queued/running `attack.run` / `explain.run` / `harden.recommend` / `verify.replay` job of the campaign through `services.runs.cancel_run` (semantics in section 10.7, states in section 6). Returns `409 run_terminal` when the run is already terminal (section 6.3). |
| `GET` | `/v1/findings?run=&project=&severity=&limit=` | membership (per row) | kept, unchanged | Adversarial findings. `schema_blob` carries the ML block defined in section 5.7. |
| `GET` | `/v1/findings/{finding_id}` | membership | kept, unchanged | One finding, including `validation_state` and `validated_at`. |
| `PATCH` | `/v1/findings/{finding_id}/status` | `FINDING_REVIEW` (approver) + independence check | kept; **ML rule added** | Reviewer dismissal (`false_positive`) with a non-empty `reason` and `expected_status`; `403` when the caller is the campaign creator (section 7.7); `409` on a stale `expected_status`. Audit `finding.review`. Other transitions are worker-only (section 6.4). |
| `POST` | `/v1/findings/{finding_id}/verify` | `VERIFY_REPLAY` (remediator) | kept; **body extended** | Verify-after-harden. Accepts an optional JSON body `{defense, params}` (17.2). Without a body the default defense from section 16.5 is used. |
| `GET` | `/v1/runs/{run_id}/report.{md\|json\|html}` | membership + `REPORT_EXPORT` (scanner) | kept; **one `check()` added** | Campaign report rendered by the worker at run completion (section 14.8). HTML is served under `REPORT_CSP` (`default-src 'none'`), JSON and Markdown as `nosniff` downloads. The added `check()` closes the Viewer export gap (section 7.3). |
| `GET` | `/v1/targets?project=` | membership | kept, unchanged | Generic target list; includes the two new `Target.kind` values. |
| `POST` | `/v1/targets` | `TARGET_MANAGE` (admin) | kept; **one new rejection** | Generic target creation. A body with `kind` in `{ml_model_artifact, ml_model_endpoint}` is rejected with `400 use_models_route` so the upload rules of 17.2 cannot be bypassed. |
| `DELETE` | `/v1/targets/{target_id}` | `TARGET_MANAGE` (admin) | kept, unchanged | Generic delete; ML targets are normally deleted through `DELETE /v1/models/{id}` (same service, same audit event). |
| `GET` | `/v1/targets/{target_id}/verification` | membership | kept; returns `501` | Ownership-verification engine was removed with the pentest domain. Unchanged. |
| `POST` | `/v1/targets/{target_id}/verify` | `TARGET_MANAGE` (admin) | kept; returns `501` | As above. Unchanged. |
| `GET` / `POST` / `DELETE` | `/v1/auth-profiles…` | `AUTH_PROFILE_MANAGE` (admin) for writes | kept, unchanged | Fernet-encrypted credentials for the Phase B black-box endpoint connector (bearer / header). Not used in Phase A. |
| `GET` | `/v1/projects` | authenticated | kept, unchanged | Caller's projects with per-project role; backs `useRoles` in the web app. |
| `GET` | `/v1/projects/{slug}/membership` | membership | kept, unchanged | Roster (read-only). |
| `PUT` | `/v1/projects/{slug}/settings` | admin | kept, unchanged | Daily LLM budget in cents. The cap applies to the Pythia-routed hardening narrative (task `ml.harden_narrative`) exactly as it applied to the old fix writer. |
| `GET` | `/v1/orgs/{org_id}/cost?days=` | org membership | kept, unchanged | LLM spend, now consisting of Pythia calls only (D5). |
| `GET` | `/v1/logs?…` | membership | kept, unchanged | Application log query. |
| `GET` | `/v1/audit/verify?project_id=&run=` | `AUDIT_VERIFY` (admin) | kept, unchanged | Verifies chain `run:<id>` or `project:<id>`; the campaign trail in the demo (section 24). |
| `WS` | `/v1/runs/{run_id}/events` | membership | kept, unchanged | Redis pub/sub relay. Carries the existing `{type:"job", run_id, job_id, status}` frames plus the `{type:"stage", name, status}` frames the ML worker publishes for each entry of `STAGES` (section 10.3). |
| `GET` | `/v1/__settings` | none (non-prod only) | kept, unchanged | Debug view; hidden in prod. |
| `POST` | `/v1/scans` | `SCAN_START` (scanner) | **kept mounted but inert; unmounted at M0** | The 14 scanner adapters were deleted, so `list_scanners()` is empty and every call returns `400 unknown scanner`. The ML vertical does not use it. M0 removes the router and its tests; until then it must not be documented as a working route. |

Housekeeping that belongs to this section: `docs/api/v1.md` still documents routes that no longer exist (tickets, agents, fix, `tools/kali`, `exports/vulnfixer`, GitHub webhooks). M0 prunes those entries and adds the tables of 17.2; the FastAPI-generated OpenAPI document at `/docs` (non-prod) is the executable contract in the meantime. The stale `Action` members that no route uses any more (`AGENT_RUN`, `AGENT_EXECUTE`, `FIX_GENERATE`, `FIX_APPLY`, `TOOL_INVOKE`, `TICKET_SYNC`) are pruned from `aegis/api/policy.py` in the same milestone (section 7.4).

### 17.2 New routes (Phase A)

New `Action` members added to `aegis/api/policy.py` are those of section 7.4: `MODEL_REGISTER` (remediator), `ATTACK_RUN` (scanner), `EXPLAIN_RUN` (scanner), `HARDEN_RECOMMEND` (remediator), `FINDING_REVIEW` (approver), `FINDING_ANNOTATE` (remediator), `REPORT_EXPORT` (scanner). The `StaticPolicyEngine` table, the OPA and the Cedar bundles all gain the same seven rows.

#### Models (F002 catalog, D2/D3)

| Method | Path | Gate | Effect | Audit action | Responses |
|---|---|---|---|---|---|
| `GET` | `/v1/models?project=` | membership | Lists `Target` rows of kind `ml_model_artifact` / `ml_model_endpoint`: `id`, `name`, `source` (`bundled` \| `upload` \| `endpoint`), `modality`, `format` (section 5.5 vocabulary: `onnx` \| `torch_state_dict` \| `safetensors_state_dict` \| `sklearn_joblib` \| `xgboost_json` \| `endpoint`), `sha256`, `manifest` (dataset id + revision, class names, clean accuracy with `n` as recorded at build time, framework versions, `gradients`), `status` (`registered` \| `validating` \| `available` \| `refused`; section 6.6), `refusal_reason`, `last_run_id`. The LLM domain appears as a registry entry with `status: "not_implemented"` and a reason (D6). | — | `200`; `403` |
| `POST` | `/v1/models` (JSON, `source: "bundled"`) | `MODEL_REGISTER` (remediator) | Body `{project_id, bundled_id}`. Creates a `Target` of kind `ml_model_artifact` whose `value` is `bundled:<id>` and whose manifest is copied from the asset manifest (section 11); seeded `available`. | `model.register` (`source=bundled`) | `201` Target; `404 unknown_bundled_model`; `409 already_registered` (same `project_id` + `sha256`) |
| `POST` | `/v1/models` (multipart, `source: "upload"`) | `MODEL_REGISTER` (remediator) | Fields `file`, `project_id`, `name`, `modality` (`image` \| `tabular`), `declared_format` (`onnx` \| `torch_state_dict` \| `safetensors_state_dict`), `architecture_id` (required for state_dict formats; must be one of the architectures in the catalog of section 9), `license_statement` (free text, required), `dataset_id` (bundled dataset the model is evaluated on). The API performs **static checks only** (section 9.3): enforces the size cap while streaming (`AEGIS_ML_UPLOAD_MAX_MB`, default 512), checks the magic bytes and extension for the declared format, rejects anything that looks like a pickle or a ZIP-wrapped pickle (`torch.save` full-model files, `.pkl`, `.joblib`, `.pt` without a declared architecture), computes `sha256`, and writes the bytes to the blob store under `{project_id}/models/{target_id}/{safe_filename}` (content-addressed). The `Target` is created with `status: "registered"`, then the same service creates the `ml.ingest` Run and `model.validate` Job and the status becomes `validating`; deep validation (ONNX checker, shape probe, `onnx2torch` agreement, class-count check) happens on the worker inside the sandbox (section 10.2) and is written back as `available` or `refused` with a reason. | `model.register` (`source=upload`; detail: `sha256`, `size_bytes`, `declared_format`, `architecture_id`, `modality`; never file contents) then `attack.run`-style admission of the ingest job is covered by the same event | `201` Target (`status: "validating"`, with the ingest `run_id`); `413 model_too_large`; `415 unsupported_model_format`; `415 pickle_refused`; `422 architecture_required`; `422 architecture_not_allowlisted`; `422 dataset_incompatible` |
| `POST` | `/v1/models` (`source: "endpoint"`) | `TARGET_MANAGE` (admin) | Black-box connector. Phase B (D2). | — | `501 not_implemented` with `phase: "B"` |
| `GET` | `/v1/models/{id}` | membership | Detail: everything in the list row plus `validation` (the `ml.validation_report` summary: detected format, input shape, class count, `gradients`, `onnx_torch_argmax_agreement`, refusal reason, ingest job id) and the campaign history (`run_id`, attacks, `reference_eps`, `settings_hash`, MRI when scored — as a link into the full scorecard, never as a bare number in a list; section 15.7). | — | `200`; `404` |
| `DELETE` | `/v1/models/{id}` | `TARGET_MANAGE` (admin) | Deletes the blob and the `Target`. `Run`, `Finding`, `Artifact` and audit rows are retained (history is never rewritten; F002 FR-008 spirit). | `target.manage` (`op=delete`) | `200 {deleted}`; `404`; `409 campaign_in_flight` when a run on the model is queued or running |
| `POST` | `/v1/models/{id}/attacks` | `ATTACK_RUN` (scanner) | Starts a campaign. Body is the campaign configuration of section 5.6: `{attack_ids: [attack_id…], attack_params?: {attack_id: {…}}, norm ("linf" \| "l2", default "linf"), eps_grid: [float…], reference_eps, finding_asr_threshold (default 0.2), dataset_id, dataset_revision?, n_samples (10–1000, default 200), seed (default 0), include_control (default true), explain_k (0–32, default 8), auto_recommend (default true), llm_narrative (bool, default false)}`. Scoring weights and thresholds are copied from the deployment `ml.scoring` block (section 15.3) and snapshotted onto the run; they are not a request field in Phase A. Creates one `Run` (`scanner="ml.campaign"`, `target_id`), one `attack.run` `Job` per attack id (chained in the declared order), the campaign-wide `explain.run` (when `explain_k > 0`) and `harden.recommend` (when `auto_recommend`) jobs (section 10.3); the MRI is computed when `explain.run` finishes. When `llm_narrative` is true and Pythia is not configured the campaign still runs; the narrative is skipped and recorded as `narrative_source: "rules"` with the reason (section 16.3). | `attack.run` (detail: config snapshot, model `sha256`, dataset id + revision, `settings_hash`) | `202` JobHandle `{run_id, job_ids, status_url: "/v1/runs/{run_id}"}`; `404`; `409 model_load_refused` (target not `available`: status and `refusal_reason` in the body); `422 unknown_attack`; `422 attack_modality_mismatch`; `422 attack_requires_gradients` (a white-box attack on a target whose manifest `gradients` is false); `422 eps_grid_invalid` (empty, unsorted, outside `(0, 1]`); `422 reference_eps_not_in_grid`; `422 params_out_of_range` (from `AttackAdapter.resolve_params`); `422 dataset_incompatible`; `501 not_implemented` for a Phase B attack or modality; `503 queue_unavailable` |

#### Catalog reads

| Method | Path | Gate | Returns |
|---|---|---|---|
| `GET` | `/v1/attacks?modality=` | authenticated | The attack registry (section 12): `AttackInfo` (`id`, `name`, `domain`, `family`, `description`, `params_schema`, `references`) plus `phase` (`A` \| `B`), `access` (`white-box` \| `black-box`), `requires_gradients` (bool), `status` (`available` \| `not_implemented`) and `reason`. The benign `noise_control` adapter is listed with `family: "control"`. |
| `GET` | `/v1/datasets` | authenticated | Bundled dataset manifest (section 11): `id`, `name`, `license`, `source_url`, `classes`, `size`, `format`, `revision` (content hash), `role` (`demo` \| `ci_fixture`), `reachability` as recorded at build time, `compatible_modalities`. |
| `GET` | `/v1/defenses` | authenticated | ART preprocessing defenses available to `verify.replay` (section 16.5): `id`, `name`, `art_class`, `params_schema`, `modalities`, `phase`, `status`. |
| `GET` | `/v1/ml/capabilities` | authenticated | `{modalities: {image, tabular, llm, text, detection} → {status, reason, phase}, upload_formats: ["onnx", "torch_state_dict", "safetensors_state_dict"], pickle_accepted: false, architectures: [...], explainers: {...}, defenses: [...], llm_narrative: {configured: bool, gateway: "pythia", model: <resolved model for task "ml.harden_narrative"> | null, persona_set: bool}, worker_ml_extra: bool, sandbox_enabled: true}`. Never includes the Pythia key or base URL. The web app reads this once per session to render honest disabled states (section 18.5). |

#### Campaign and evidence reads

| Method | Path | Gate | Returns |
|---|---|---|---|
| `GET` | `/v1/runs/{run_id}/campaign` | membership | The full campaign record assembled per section 5: `config` (`CampaignConfig`), `target` (`TargetInfo`), `attacks` (`AttackInfo[]`), `provenance` (versions, `model_sha256`, dataset id + revision, seed, `sample_indices_sha256`, `settings_hash`, device, `nondeterminism[]`), `measurements[]` (one row per family × attack × ε plus `clean` and `control` rows, each with `n`, `n_correct`, `accuracy`, `n_flipped_from_clean`, `n_clean_correct`, `attack_success_rate`, `linf_norm_mean`, `l2_norm_mean`, `per_class`, `wall_time_s`), `curve` (accuracy vs ε per attack, control and clean baseline, with `n` per point), `observations[]` (artifact ids, labels, confidences, `center_mass_ratio_*`, `expl_shift`, `metric_kind: "heuristic"`), `interpretation[]` (`kind: "inferred"`), `recommendations[]` (`status: "candidate"`, `validation`, `measured`), `limitations[]` (never empty for a finished run), `reviewer_notes`, `completeness` (`complete` \| `partial`, with `missing`), `score` (the `MRIRecord`: MRI, five subscores, `per_attack`, weights, grade, `reading`, `reference_eps`, `eps_grid`, `attack_ids`, `delta` when measured) or `score: null` with `score_status` (`pending` \| `unavailable` + reason). `404`. |
| `GET` | `/v1/runs/{run_id}/artifacts` | membership | `Artifact` rows: `id`, `kind` (section 5.8 vocabulary), `content_type`, `size_bytes`, `sha256`, `created_at`. |
| `GET` | `/v1/artifacts/{artifact_id}` | membership (via `run_id` → project) | Streams the blob. `image/png` is served inline; JSON, `.npz` and text as `Content-Disposition: attachment`; every response carries `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'` and `ETag` = `sha256`. **New route.** S1 §10 listed it as reuse, but the restored API has no artifact route; the `Artifact` table and blob store exist, the endpoint does not. `404` for unknown ids and for rows whose blob is missing (`artifact_blob_missing`). |
| `GET` | `/v1/runs/{run_id}/compare?with={other_run_id}` | membership on both runs | Comparison under D9(i) (F007). Compatibility requires equal `settings_hash` (section 5.6) and equal `sample_indices_sha256`. When the two runs are a verify pairing (same `model_sha256`, one run's `baseline_run_id` is the other) the response carries the ΔMRI: `{compatible: true, mode: "verify_delta", delta_mri, delta_dimensions, delta_acc_clean, delta_families[] (each with both n), changed_variables: ["defense"], unchanged_variables, caveats}`. When the settings match but the model differs, the response is `{compatible: true, mode: "side_by_side", delta: null, scorecards: [two full MRIRecords with their tables], changed_variables: ["model"], …}` — two scorecards, never one delta (section 15.6). `409 incompatible_campaigns` with the list of mismatched variables (`seed`, `n_samples`, `eps_grid`, `dataset_revision`, … are all in the hash and therefore blocking); `409 score_unavailable` when either run has no score; `404`; `403` on either project. |
| `PATCH` | `/v1/runs/{run_id}/reviewer-notes` | `FINDING_ANNOTATE` (remediator) | Body `{reviewer_notes: string}` (≤ 8 KiB). Stored in `ml_campaigns.reviewer_notes` (section 5.6). Audit `finding.annotate` (detail: author, byte length, `sha256` of the text). `200`; `404`; `422` on size. |

#### Finding actions (F005 / F006)

| Method | Path | Gate | Effect | Audit action | Responses |
|---|---|---|---|---|---|
| `POST` | `/v1/findings/{finding_id}/explain` | `EXPLAIN_RUN` (scanner) | Body `{explain_k?, seed?}`. Enqueues `explain.run` scoped to the finding's attack at `reference_eps`: SHAP on the first `explain_k` flipped and `explain_k` unflipped samples (section 13). Used when `explain_k` was 0 or a reviewer wants more samples. | `explain.run` | `202` JobHandle; `404`; `409 campaign_not_terminal`; `409 job_in_flight`; `501 not_implemented` when the modality has no explainer |
| `POST` | `/v1/findings/{finding_id}/harden` | `HARDEN_RECOMMEND` (remediator) | Body `{llm_narrative: bool}`. Enqueues a follow-on `harden.recommend`: the rule layer runs always; the Pythia narrative runs when `llm_narrative` is true and Pythia is configured (section 16.3, D5), otherwise the job records `narrative_source: "rules"` with the reason and succeeds. The result is read back from `GET /v1/findings/{id}` (`schema_blob.ml.recommendations`, section 5.7) and from `/campaign`; the route does not return the report inline because the work is asynchronous. | `harden.recommend`; the worker adds `harden.execute` (model id, prompt `sha256`, token counts, cost cents; never prompt text) | `202` JobHandle; `404`; `409 campaign_not_terminal`; `409 job_in_flight` |
| `POST` | `/v1/findings/{finding_id}/verify` | `VERIFY_REPLAY` (remediator) | Existing route; body `{defense: <id from /v1/defenses>, params?}` (optional; default per section 16.5). Enqueues `verify.replay` with `Job.detail = {finding_id, defense, defense_params, baseline_run_id}` and creates the `ml.verify` Run. The worker applies the ART preprocessor to the estimator and re-runs the campaign's **whole in-scope attack set** at the campaign's ε grid on the same slice (same seed), so ΔMRI is well defined; it writes the `delta` onto the verify run's score record and sets `Finding.validation_state` / `Finding.status` on the triggering finding through the existing `_STATE_MAP` (section 6.4). Other findings of the run receive an informational re-measurement note but keep their state until verified explicitly, because a rerun alone is not resolution (F006 FR-007). | `verify.replay` (existing) | `202` JobHandle; `404`; `409 campaign_not_terminal`; `409 job_in_flight`; `422 unknown_defense`; `422 defense_modality_mismatch`; `422 params_out_of_range` |

### 17.3 Conventions and error codes

- **Error envelope.** Retained routes keep FastAPI's `{"detail": "<string>"}`. New ML routes return `{"detail": {"code": "<snake_case>", "message": "<human text>", "phase"?: "B", "field"?: "<name>", "reasons"?: [...]}}` so the web app can render the refusal without parsing prose.
- **Job handles.** Every enqueue returns `202` with `{run_id, job_ids, status_url}` from `JobHandle.to_response()`, identical to the old scan flow.
- **Idempotency.** Not implemented in Phase A: two identical `POST /v1/models/{id}/attacks` create two campaigns. The UI disables the launcher while a request is in flight (section 18). An `Idempotency-Key` header is Phase B (William F004 US1 duplicate-request scenario; sections 6.3, 10.6).
- **Pagination.** `limit`-based, as on the existing list routes.
- **Uploads.** `Content-Length` is required; the size cap is enforced while streaming, before any byte reaches the blob store.
- **Rate limits.** The existing write-route limiter applies; `429` carries the existing detail.

| Code | HTTP | Raised when |
|---|---|---|
| `use_models_route` | 400 | `POST /v1/targets` with an ML `kind`. |
| `forbidden` (string detail) | 403 | RBAC or membership failure (existing wording from `policy.check`); also the independence check on `finding.review` (section 7.7). |
| `not_found` (string detail) | 404 | Unknown run, finding, model, artifact, bundled model. |
| `already_registered` | 409 | Bundled model already registered in the project. |
| `campaign_in_flight` | 409 | Delete requested while a campaign is queued/running. |
| `model_load_refused` | 409 | Campaign requested on a model whose status is not `available` (`registered`, `validating`, or `refused` with its reason). |
| `campaign_not_terminal` | 409 | Explain / harden / verify requested before the run reached a terminal status. |
| `job_in_flight` | 409 | A job of the same type for the same finding is queued or running. |
| `run_terminal` | 409 | Cancel or status write against a run or finding that is already terminal / stale `expected_status`. |
| `incompatible_campaigns` | 409 | Compare across different settings (D9 i). |
| `score_unavailable` | 409 | Compare when a run has no score. |
| `model_too_large` | 413 | Upload exceeds `AEGIS_ML_UPLOAD_MAX_MB`. |
| `unsupported_model_format` | 415 | Declared or detected format outside the accepted set of section 9.2. |
| `pickle_refused` | 415 | Pickle or full `torch.save` object detected (D2). |
| `architecture_required` | 422 | State_dict format without a declared `architecture_id`. |
| `architecture_not_allowlisted` | 422 | Declared `architecture_id` is not in the section 9 catalog. |
| `dataset_incompatible` | 422 | Dataset shape or class count does not match the model manifest. |
| `unknown_attack` / `unknown_defense` | 422 | Id not in the registry. |
| `attack_modality_mismatch` / `defense_modality_mismatch` | 422 | Attack or defense domain differs from the model modality. |
| `attack_requires_gradients` | 422 | White-box attack requested on a target with `gradients: false` (section 9.5). |
| `eps_grid_invalid` / `reference_eps_not_in_grid` | 422 | Grid rules of section 12.3. |
| `params_out_of_range` | 422 | `AttackAdapter.resolve_params` or defense param validation raised. |
| `rate_limited` (string detail) | 429 | Existing write-route limiter. |
| `not_implemented` | 501 | Endpoint connector, text / detection / LLM modalities, Phase B attacks, garak, explain on an unsupported modality. Always carries `phase`. |
| `queue_unavailable` | 503 | Celery broker unreachable at enqueue. |
| `db_unavailable` (string detail) | 503 | `AEGIS_DB_URL` missing (existing `RuntimeError` mapping). |

### 17.4 Phase B routes (named so the UI can show them honestly)

`POST /v1/models` with `source: "endpoint"` (black-box connector using an `AuthProfile`), text and detection modalities on `/v1/attacks`, KernelSHAP for black-box targets on `/explain`, `Idempotency-Key` on campaign start, finding review transitions beyond dismissal (`POST /v1/findings/{id}/review`, shape per the decision in section 6.4), PDF export on `/report.pdf`, policy-gated export and redaction (F007/F008, blocked while D006 is OPEN), per-project scoring overrides, and a garak run type whose OpenAI-compatible generator points at Pythia (D6). Each of these returns `501 not_implemented` with `phase: "B"` today; none is stubbed with fake output.

**Phase B2 routes (interoperability, section 27).** Named here so the UI and the generated OpenAPI document can show them honestly. Each returns `501 not_implemented` (`phase: "B"`; milestone B2 in section 23) until B2 lands, and none is stubbed with fake output. The first two are S1 §14.1's endpoints; the third is required by S1's consume side and is not named in S1.

| Method | Path | Gate | Effect when built | Audit action | Responses when built |
|---|---|---|---|---|---|
| `POST` | `/v1/runs/{run_id}/dataset` | `DATASET_EXPORT` (remediator; section 27.4) | Enqueues `dataset.export` for a terminal campaign or verify run: builds the Croissant manifest over Parquet from the run's `ml.adv_slice` artifacts (regenerating from configuration and seed inside the sandbox child when the slice was not retained, section 12.8), registers the files as `Artifact` rows and writes them under `datasets/<run-id>/` (section 27.1). Body `{include_card?: bool}`. Imagery exports stay in the artifacts bucket while D006 is open (27.1). | `dataset.export` | `202` JobHandle; `404`; `409 campaign_not_terminal`; `409 job_in_flight`; `409 export_blocked_pending_d006` when an imagery run targets a shared bucket |
| `GET` | `/v1/datasets/{id}` | membership on the source run's project for an export; authenticated for a bundled entry | Returns the Croissant manifest of an exported adversarial dataset, where `{id}` is the run id the export was built from (one export per run, 27.1). For a bundled dataset id of section 11 it returns that manifest entry, the same object `GET /v1/datasets` lists. Run ids and bundled dataset ids (hub paths, `kaggle:` ids) never collide. | — | `200` `application/ld+json`; `404`; `404 dataset_not_exported` when the run exists but has no export |
| `POST` | `/v1/datasets` (multipart) | `DATASET_REGISTER` (remediator; section 27.4) | Consume side: registers another team's evaluation slice as a Croissant manifest plus Parquet, or Parquet alone, with `license_statement`, `modality`, class names and the feature or image schema declared. Static checks in the API (Parquet magic `PAR1`, manifest JSON shape, size cap, sha256), parsing on the worker inside the sandbox child (`dataset.register`), audit event before rows (27.1). The open, unclassified, licensed rule of section 11.1 applies: no license statement, no registration. | `dataset.register` | `201` dataset record (`status: "validating"`); `413 dataset_too_large`; `415 unsupported_dataset_format`; `422 license_required`; `422 remote_reference_refused` (a Croissant `contentUrl` outside the upload); `422 schema_undeclared` |

## 18. Web UI

The web app is `@aegis/web` (D7): the Next.js 14 app router under `web/`, Tailwind, `@aegis/design-system` from `packages/design-system`, the `api()` client in `web/src/lib/api.ts` (cookie or bearer, CSRF header, request id), NextAuth with the Keycloak provider plus the dev-token path (hidden when `NEXT_PUBLIC_AEGIS_ENV=prod`), and the hooks `useRequireAuth`, `useRoles`, `useRunEvents`. `RoleGated` remains UX-only; the API is the authorization boundary (section 7.9). The header brand reads "Adversarial ML Red-Team Simulator". Every page carries the footer line from S2: *"Proof of concept on open, unclassified public data. Results are evidence for human review, not a safety, readiness, or certification determination."*

### 18.1 Navigation and page inventory

Nav order: Dashboard · Runs · Models · Findings · Projects · Audit · Logs · Cost · Auth Profiles. The command palette entries follow the same list.

| Route | State | Purpose | Data | UX gating (section 7.9) |
|---|---|---|---|---|
| `/login` | existing | Keycloak / OIDC sign-in; "Continue as dev admin" in dev mode only. | NextAuth, `/v1/projects` | — |
| `/dashboard` | existing, changed | Recent campaigns: Run, Project, **Model** (replaces Scanner), Attacks, Status, Created; polls every 15 s. Empty state links to `/models`. | `/v1/runs` | — |
| `/models` | **new** | Model list (name, source badge `bundled` / `uploaded` / `endpoint (Phase B)`, modality, format, short `sha256`, clean accuracy with `n` from the manifest, status `registered` / `validating` / `available` / `refused` with reason) and the **Add model** dialog with three tabs: *Bundled sample* (picker), *Upload artifact* (ONNX or `state_dict` / `safetensors` + architecture select, license statement, dataset; the refusal rules are shown before a file is chosen), *Connect endpoint* (rendered disabled with the Phase B reason from `/v1/ml/capabilities`). | `/v1/models`, `/v1/datasets`, `/v1/ml/capabilities` | Add bundled / upload: remediator. Delete: admin. |
| `/models/[id]` | **new** | Model summary (manifest, license, dataset compatibility, validation status with refusal reason and a link to the ingest job), the **campaign launcher** (18.2), and the campaign history table (run, attacks, reference ε, status, and a "scorecard" link — never a bare MRI number in the list, section 15.7). | `/v1/models/{id}`, `/v1/attacks`, `/v1/datasets`, `/v1/defenses` | Launcher: scanner. |
| `/runs` | existing, changed | Columns Run, Model, Attacks, Status (`RunStatusBadge` renders the section 6.2 vocabulary `queued` / `running` / `succeeded` / `failed` / `cancelled`; the component's `partial_success` variant is not written by the ML vertical — completeness is a separate flag), Created. | `/v1/runs` | — |
| `/runs/[id]` | existing, **extended** | The campaign page (18.3). | `/v1/runs/{id}`, `/v1/runs/{id}/campaign`, `/v1/findings?run=`, `/v1/runs/{id}/artifacts`, WS events | Cancel, notes, verify: remediator. |
| `/findings` | existing, changed | Severity filter retained; adds columns Attack, ε at first success, ASR (`k / n`), Validation. Phase B2 adds an **ATLAS technique** column (`schema_blob.ml.atlas_technique`, section 27.2); the column is added when B2 lands, not before, and a finding without a tag shows none. | `/v1/findings` | — |
| `/findings/[id]` | existing, **body replaced** | The three-pane screen (18.4). | `/v1/findings/{id}`, `/v1/runs/{id}/campaign`, artifacts | Explain: scanner. Harden / verify: remediator. Dismiss: approver. |
| `/audit` | existing, changed | Hash-chain verification view; gains a "chain: run:<id>" deep link from the campaign page. Wording is "hash-chained, tamper-evident"; never "tamper-proof" or "certified" (F008 FR-011). | `/v1/audit/verify` | admin |
| `/projects`, `/projects/[slug]/settings` | existing | Roster (read) and the daily LLM budget, which now caps Pythia narrative spend. | `/v1/projects…` | Settings: admin. |
| `/auth-profiles` | existing | Retained for the Phase B endpoint connector; the page header states that no Phase A feature uses a profile. | `/v1/auth-profiles` | admin |
| `/logs`, `/cost` | existing | Unchanged. | `/v1/logs`, `/v1/orgs/{id}/cost` | — |
| `/targets` | changed → redirect | The pentest launcher (scanner select `trivy` / `zap` / `nuclei` and `startScan`) is deleted with its tests; the route redirects to `/models`. | — | — |
| `/agents`, `/tools` | removed | Gone with the CAI agents and Kali tooling. | — | — |

### 18.2 Campaign launcher (`/models/[id]`)

The form is built from `/v1/attacks`, `/v1/datasets`, `/v1/defenses` and `/v1/ml/capabilities`, never from hard-coded lists:

- **Attacks**: checklist grouped by phase. Phase B rows are rendered disabled with their `reason`; they are never hidden and never selectable. White-box attacks are disabled with the reason "target has no differentiable estimator" when the model's manifest `gradients` is false (section 9.5).
- **Perturbation budget**: John's single ε slider is replaced (D4 b) by an **ε grid** multi-select defaulting to `{0.01, 0.03, 0.1}` (L∞, image) and a **reference ε** radio that must be one of the selected values; the grid drives the robustness curve, the reference ε drives `S_asr`, `S_conf` and `S_expl` (section 15).
- **Finding threshold**: `finding_asr_threshold`, default 0.2, shown with the sentence that severities derive from it (section 15.5).
- **Dataset**: bundled dataset picker showing license and revision hash; CIFAR-10 is labelled "CI fixture — not the demo dataset" (D3, section 11).
- **Sample size** 50–500 in the UI (API accepts 10–1000), **seed**, **benign noise control** (default on, with a one-line explanation of why the control exists), **explain_k**, **LLM narrative** (checkbox; enabled only when `/v1/ml/capabilities.llm_narrative.configured` is true, and then showing which Pythia model id would be used; otherwise disabled with "Pythia not configured — rule outputs only").
- **Scoring weights**: displayed read-only from `/v1/ml/capabilities` with the section 15 defaults; per-project editing is Phase B.
- Submit calls `POST /v1/models/{id}/attacks`, disables the button until the response arrives (no idempotency key in Phase A, section 17.3), then routes to `/runs/[id]`.
- The launcher is disabled, with the reason shown inline, when the model is `registered` or `validating` (ingest job pending) or `refused`, when `/v1/ml/capabilities.worker_ml_extra` is false, or when the caller's role is below scanner.

### 18.3 Campaign page (`/runs/[id]`)

The page keeps the existing header (run id, status pill, Cancel dialog gated to remediator, `ReportLinks` for md / json / html) and the existing `StageTimeline` fed by WebSocket frames with the 30 s fallback poll, now keyed by the stage names of section 6.5. Below the header the panels appear in this fixed order; measurements, observations, interpretation and candidate recommendations are **separate panels with distinct visual treatment** (S2, brief, constitution III) and are never interleaved:

1. **Completeness banner** — `complete` or `partial` with the recorded reason (F004 FR-010, F007 FR-004). A partial run is labelled partial here, on the score block and on the report links.
2. **Campaign settings** — attacks, ε grid, reference ε, finding threshold, dataset id + revision, `n`, seed, control on/off, `explain_k`, scoring weights, `settings_hash`, library versions. Always rendered next to the score (D9 i).
3. **MRI scorecard** (section 15.7) — one component, `MriScorecard`, that receives the score, the per-family measurement table and the curve together and renders the number, the grade and the five weighted dimension bars **only when all three are present** (D9 ii). If any is missing it renders "Score unavailable: <reason>" and no number. The grade "Reading" text is the attack-scoped wording of section 15.5; a fixed caption reads "Per-campaign summary under the in-scope attacks at the stated settings. Not a readiness or certification statement." A **ΔMRI** badge appears only when the score record carries a `delta` and is labelled "measured"; the UI has no "expected gain" element anywhere (D9 iv).
4. **Measurements (evidence)** — table by family: `clean`, one `evasion` row per attack × ε, one `control` row per ε; columns `n`, `n_correct`, accuracy, `n_flipped_from_clean / n_clean_correct`, mean L∞, mean L2, wall time; collapsible per-class sub-table. A family with `n = 0` shows "no evidence recorded", never 0 % (F005 edge). The **robustness curve** (accuracy vs ε per attack, control line, clean baseline) sits under the table with denominators in tooltips.
5. **Observations gallery** — per explained sample: clean image, adversarial image, SHAP clean, SHAP adversarial (each an `<img>` from `/v1/artifacts/{id}`), true / predicted labels, confidences, `center_mass_ratio_clean/adv` badged **heuristic** with the `metric_note` as tooltip. Tabular observations show a feature diff table (original, adversarial, delta) and the SHAP bar / beeswarm PNGs. When no explanation was recorded the panel says so with the reason and draws nothing.
6. **Interpretation** — statements badged **inferred**, each listing its `basis` ids as links that scroll to the measurement or observation rows.
7. **Candidate recommendations** — cards badged **candidate · not evaluated**, or **candidate · measured ΔMRI ±x at these settings** once verified; `triggered_by` links; the ART defense link; a **Verify fix** button (remediator) that opens the defense chooser populated from `/v1/defenses`. The narrative block is labelled "LLM-generated narrative of rule outputs (via Pythia, model <id>)" or "Narrative unavailable: <reason>; rule outputs shown".
8. **Limitations** — always rendered: `STANDING_LIMITATIONS` plus run-specific lines (slice size, single seed, ε grid used, dataset name and caveats).
9. **Provenance** — aegis / Python / torch / ART / SHAP / numpy versions, model `sha256`, dataset id + revision, seed, `sample_indices_sha256`, device, hostname, `nondeterminism[]`, and a **Rerun with same config** button that starts a new linked campaign (`parent_run_id`).
10. **Reviewer notes** — textarea bound to `PATCH /v1/runs/{id}/reviewer-notes` (remediator), showing last author and time.
11. **Findings table** — existing table with `SeverityChip`, plus Attack and ε at first success; a **Dismiss** action (approver; disabled with the reason when the viewer is the campaign creator, section 7.7). Phase B2 adds the ATLAS technique column (section 27.2).
12. **Compare** drawer — pick another run of the same model; renders `changed_variables` / `unchanged_variables` and, for a verify pairing, the per-dimension and per-family deltas with both `n`; for a same-settings different-model pair, two scorecards side by side; when the API answers `409 incompatible_campaigns` the drawer lists the mismatched variables and draws no delta.
13. **Audit** — `AuditChainBadge` with the chain id `run:<id>` and a link to `/audit`.

**Phase B2 additions (section 27).** When B2 lands the campaign page gains, below panel 11: (a) a per-campaign **ATLAS coverage** block that lists the techniques exercised by the in-scope attacks that ran, the techniques of declared attacks recorded as `not_run`, and the catalog techniques outside the declared set. It is a description of the declared attack set, not a score: no colour grading, no number, never aggregated across campaigns, and it says nothing about techniques that were not run (27.2). (b) An **Export adversarial dataset** action (remediator) that calls `POST /v1/runs/{id}/dataset` and, once the export exists, shows the manifest sha256, the file list with sizes and a link to `GET /v1/datasets/{id}` (27.1). (c) An **Integrations** line showing the Foundry push status when that integration is configured, and nothing when it is not (27.3). Until B2 lands the coverage block and the export action render disabled with "Phase B2, not implemented" and the Integrations line is absent; no manifest, tag, coverage view or push status is ever fabricated (18.5).

### 18.4 Finding page (`/findings/[id]`) — the three-pane screen

Header: the existing `FindingCard` (title, derived severity, `Finding.status`, `validation_state` chip; the chip's tone map `poc_passed` / `poc_failed` / `inconclusive` / `unvalidated` is retained and the visible label is the ML-facing wording defined in section 6.4, for example "verified: attack no longer crosses threshold at these settings with feature_squeezing"). Three panes side by side on wide screens, stacked on narrow ones:

1. **Input** — original vs adversarial image with a perturbation-magnitude map and the measured L∞ / L2, alongside the noise-control image at the same ε; for tabular, a feature diff table (original, adversarial, delta, unit) optionally rendered with `EvidenceDiff`; for the URL classifier the clean row's URL string appears as escaped, non-clickable text labelled as dataset content, and the pane carries the realizability note of section 12.9 ("feature-space perturbation; realizability not established").
2. **Explanation** — SHAP clean vs adversarial saliency (or bar / beeswarm), centre-mass heuristics badged **heuristic**, the explanation-shift value for this attack shown as a measurement with its `n` and beside its noise floor, and the fixed disclosure "Attribution describes model sensitivity; it is not causal proof" (F005 FR-011). An **Explain** button (scanner) appears when no observation exists for this finding.
3. **Candidates** — the ranked rule outputs for this finding, each **candidate · not evaluated** until a verify record exists; **Verify fix** with the defense chooser; after verification: the measured ΔMRI with per-dimension deltas, the re-measured ASR table for every in-scope attack at the campaign's ε grid (with `n`), the new `validation_state`, and the informational note that other findings of the run were re-measured but not re-stated (section 17.2).

Below the panes: this attack's accuracy-vs-ε row highlighted on the campaign curve, the audit events for this finding (`explain.run`, `harden.recommend`, `harden.execute`, `verify.replay`, `verify.execute`, `finding.review`), and a link back to the campaign.

### 18.5 Honest states

These rules apply to every page and are asserted by tests (section 22).

| Condition | The UI shows | The UI never shows |
|---|---|---|
| Target `status = not_implemented` (LLM; text and detection in Phase B; tabular before M4) | The row, its reason, a disabled Evaluate control | A run, a placeholder result |
| Attack or defense in Phase B | Disabled control labelled "Phase B" with the reason | A hidden option or a fake result |
| Upload refused (`413`, `415`, `422`) | The error `code`, the message and the remedy (export ONNX; declare an architecture; choose a compatible dataset) | A partially created model |
| Worker refused the model (`refused`) or validation pending (`validating`) | Status on the model, the reason, a link to the ingest job and the audit event | A launchable model |
| Pythia not configured, budget exhausted, or narrative rejected by post-check | "Narrative unavailable: <reason>"; rule outputs shown | A fabricated narrative |
| No explanation recorded or modality unsupported | "No explanation recorded (reason)" | A placeholder heatmap |
| Score not computable (attacks incomplete, partial run, missing curve, `explain_k = 0`) | "Score unavailable: <reason>" | A number or a grade |
| Family with `n = 0` | "No evidence recorded" | 0 % |
| Compare incompatible | The mismatched variables | A delta |
| Recommendation before verify | "candidate · not evaluated" | An expected gain |
| Queue or worker unavailable (`503`) | An explicit unavailable state with retry guidance | An in-process run (constitution IV) |
| Fixture data in vitest / Storybook | A visible "FIXTURE — illustrative" ribbon in stories | Fixture data in the deployed app |
| Demo-script numbers (section 24) | "illustrative" labels | Numbers presented as measured |
| Interoperability not built (B2: dataset export, ATLAS tags and coverage view, Foundry / Lattice push; section 27) | Export and coverage controls disabled and labelled "Phase B2, not implemented"; findings without an ATLAS tag show no tag; no Integrations line unless an integration is configured | A fabricated manifest, tag, coverage view or push status |

### 18.6 Components, types and tests

New design-system components (`packages/design-system/src/components/`): `MriScorecard`, `DimensionBars`, `RobustnessCurve` (inline SVG, theme-aware, denominators in tooltips), `MeasurementTable`, `ObservationCard`, `LabelBadge` (variants `candidate`, `inferred`, `heuristic`, `measured`, `illustrative`, `partial`, `phase-b`), `PanelSection`, `CompatibilityList`. Reused unchanged: `RunStatusBadge`, `StageTimeline`, `SeverityChip`, `FindingCard`, `RoleGated` (with `viewer` added to its `ROLES` tuple, section 7.2), `AuditChainBadge`, `EvidenceDiff`, `ToastList` and the primitives (Table, AlertDialog, Tooltip).

`web/src/lib/api.ts` gains the types `ModelTarget`, `AttackInfo`, `DatasetInfo`, `DefenseInfo`, `Capabilities`, `Campaign`, `CampaignConfig`, `Measurement`, `Observation`, `Interpretation`, `CandidateRecommendation`, `MRIRecord`, `ArtifactRow`, `Comparison`, `MlErrorDetail`, and the helpers `startCampaign`, `explainFinding`, `hardenFinding`, `verifyFinding(defense, params)`, `dismissFinding`, `artifactUrl(id)`, `compareRuns`, `patchReviewerNotes`. `isCancellable`, `cancelRun`, `reportUrl` and `deleteTarget` are unchanged. There is no generated client; the FastAPI OpenAPI document is the contract and vitest fixtures are typed against these hand-written types (section 19.4 records this as the replacement for William's `lib/api-client-react` / `lib/api-zod`).

Tests (details in section 22): `runs/[id]/page.test.tsx` renders a fixture campaign and asserts the panel order, that measurements / observations / interpretation / candidates are distinct sections, that the labels `candidate`, `inferred`, `heuristic` are present, that the scorecard does not render a number when the curve is absent, and that limitations are visible; `models/page.test.tsx` asserts the disabled Phase B tab and the rendered refusal codes; `findings/[id]/page.test.tsx` asserts "not evaluated" until a verify record is present and "measured ΔMRI" afterwards; the existing a11y tests (`layout.a11y.test.tsx`, `runs/page.a11y.test.tsx`, `findings/page.a11y.test.tsx`) are kept and extended to `/models`. The Playwright config is kept for an optional end-to-end smoke of the demo path against the compose stack.

## 19. Spec Kit feature mapping

Per D10, William's Spec Kit tree (`.specify/`, `specs/`) stays as the team's process framework and becomes the feature-level layer beneath this product spec. The constitution's principles remain binding constraints, with the three amendment proposals of D12 recorded in `.specify/memory/constitution.md` as *proposed, pending named approval*. Each `specs/00N-*/spec.md` keeps its stories, FR and SC identifiers; each `plan.md`'s "Ownership and proposed paths" table is superseded by the aegis paths in 19.4; each `tasks.md` remains the work breakdown, referenced as `F00N/T00N`. The readiness checklist (`specs/_shared/readiness-checklist.md`) is the approval gate for each feature (19.5). This spec does not flip any feature's "Draft / not approved for implementation" status; the feature owner does that after running the checklist.

### 19.1 Feature map

| Feature | aegis components (code) | John milestone(s) | Delivery slice | Status of William's proposal |
|---|---|---|---|---|
| **F001 Project access** | `aegis/api/auth.py` (Keycloak OIDC via JWKS, `dev:` bearer, session cookie, worker service tokens), `aegis/api/policy.py` + `aegis/policy/` (role rank, OPA / Cedar engines), `aegis/api/middleware/tenant.py` + migration `0006_tenant_rls` / `0009_tenant_org_id_guard` (Postgres RLS by `org_id`), `ProjectMembership` table, `GET /v1/projects…`, web `login`, `useRequireAuth`, `useRoles`, `RoleGated`, NextAuth Keycloak provider, `deploy/keycloak/` | Present in the restored platform (before M0); M7 for Keycloak on Fargate | Slice 1 | **Adopted on aegis; D002 RESOLVED** (Keycloak OIDC + NextAuth, dev-token mode allowed for the demo). Roles map per section 7. US3 invitations, suspend / restore, the last-owner rule (FR-007) and membership editing in the app (FR-005, FR-009) are **not implemented**: memberships are administered in Keycloak and the `project_memberships` table. FR-001 (no custom passwords) and FR-002 (server-side object authorization) hold. The Replit-collaborator exclusion (FR-004) is moot on this stack. |
| **F002 Evaluation catalog** | `Target.kind` `ml_model_artifact` / `ml_model_endpoint` and `targets.detail` (migration `0010_ml_vertical`, M0), `aegis/api/v1/models.py`, `aegis/api/v1/datasets.py`, `aegis/services/ml_models.py`, `aegis/ml/targets/` (bundled targets + manifest: the vehicle-imagery CNN and the **URL maliciousness classifier (sklearn/XGBoost on lexical URL features), trained by the asset script; clean metrics recorded in the asset manifest**), `aegis/ml/datasets/` (bundled dataset manifest including the Kaggle malicious-URLs dataset and the `url_features` extractor, section 11), blob store `{project_id}/models/{target_id}/…`, static upload checks (section 17.2), the sandboxed `model.validate` job (sections 9, 10), web `/models` | M0 (kinds), M1 (bundled CNN), M4 (bundled URL classifier), ONNX upload at M5b in the D8 order; B2 (consume side, section 27.1) | Slice 1 (bundled) and late Slice 3 (upload); B2 for the consume side | **Adopted in part; D001 and D003 RESOLVED with divergence.** Version identity is the content hash (`sha256`) of the model and the revision hash of the dataset, which gives immutability (FR-002, FR-007) without a draft / approved / rejected / archived state machine (FR-005) or independent catalog review (FR-006); those are Phase B. FR-003 provenance fields (source, license statement, public classification, domain, summary, reference) are captured on the `Target` manifest (section 5.5). FR-004's "uploads MUST be rejected pending D003" is superseded by D003's resolution: ONNX / `state_dict` uploads are accepted under the section 9 rules; endpoints stay rejected. Vehicle imagery per D3 diverges from the "benign fixture allowlist" wording and is recorded in the reconciliation table (section 4) and constitution amendment (a). **Phase B2 (section 27.1):** F002 gains the consume side of interoperability: Croissant / Parquet evaluation slices and ONNX models contributed by other teams are registered through the catalog (`POST /v1/datasets`, the existing upload path for ONNX) under the section 11.1 open-data rule and the section 9 loading rules; a consumed slice gets its own dataset id and revision and is never compared with a bundled one (D9(i)). Not built. |
| **F003 Evaluation profiles** | `CampaignConfig` snapshotted onto the `Run` at `POST /v1/models/{id}/attacks` (attack set, ε grid, reference ε, finding threshold, dataset id + revision, `n`, seed, control, `explain_k`, scoring weights, narrative flag) and returned by `/v1/runs/{id}/campaign`; deployment-level `ml.scoring` block; `aegis/ml/schema.py` `CampaignConfig` | M1 (config on the run), M3 (weights), M5a (launcher) | Slice 2 | **Adopted as an immutable per-run snapshot; reusable profiles deferred.** FR-003 (exact input versions), FR-004 (definitions, denominators, benign controls, bounds, explanation support, limitations) and FR-005 (non-operational content) are satisfied by the snapshot. A `Profile` entity with draft / in_review / published / rejected / archived states (FR-006) and author-independent publication (FR-008) is Phase B; in Phase A the approved configuration is the one the product owner recorded in this spec (sections 12 and 15) and the launcher only offers values inside those bounds. |
| **F004 Run management** | `Run` / `Job` tables, `aegis/services/scans.py` pattern → `aegis/services/ml_campaigns.py` (admission: audit event → rows → Celery), `aegis/workers/tasks/{model_validate,attack,explain,harden,verify}.py`, `aegis/workers/bootstrap.py` `task_context`, `aegis/workers/job_state.py` (status machine), `aegis/workers/tasks/reaper.py` (stale jobs → failed), `services.runs.cancel_run`, `aegis/ml/sandbox.py` on the `aegis/scanners/sandbox.py` primitives (D004), Redis pub/sub `events.py`, WS `/v1/runs/{id}/events`, web `/runs`, `/runs/[id]` | M1, M2, M4, M6 | Slice 2 | **Adopted on aegis; D004 RESOLVED** (Celery worker + plugin sandbox; OpenSandbox not used). Run states map onto the `Job` machine and `Run.status` per section 6 (`cancel_requested` and `timed_out` are derived, not stored). FR-005 / FR-006 (approved adapter, explicit failure without web-process fallback) hold: the API never loads a model, and a missing broker is `503 queue_unavailable`. FR-008 retry creates a new linked run (Rerun button, `parent_run_id`). FR-009 idempotent adapter updates are covered by the redelivery guard; the duplicate-request identity of US1 is **not** implemented in Phase A (section 17.3). FR-010 partial evidence is exposed as `completeness`. |
| **F005 Evidence workbench** | Panels 4–6 and 8–9 of `/runs/[id]` (section 18.3), the three-pane `/findings/[id]` (18.4), `GET /v1/runs/{id}/campaign`, `GET /v1/runs/{id}/artifacts`, `GET /v1/artifacts/{id}` (new), `Artifact` rows written by `explain.run` (section 13), `Measurement` / `Observation` models in `aegis/ml/schema.py` | M2 (SHAP artifacts), M5a (UI) | Slice 2 | **Adopted; merged with John's three-pane screen.** FR-002 to FR-006 (read-only browsing by run / family / case, side-by-side originals and adversarials, denominators and coverage, labelled unavailable states, SHAP only when recorded) are the section 18 rules. FR-007 (LLM text evidence) is Phase B with the LLM modality. FR-009 (optional F006 summaries labelled separately) is the candidate panel. FR-011 disclosures are fixed captions. |
| **F006 Findings review** | `Finding` table (`status`, `severity`, `validation_state`, `schema_blob` ML block per section 5.7), derived severity rules (section 15.5, John 8.5), `CandidateRecommendation` (Literal `candidate` / `not evaluated` / `measured`), `harden.recommend` rule layer + Pythia narrative (section 16), `POST /v1/findings/{id}/{explain,harden,verify}`, `PATCH /v1/findings/{id}/status` (dismissal), reviewer notes, `aegis/services/ml_findings.py`, web `/findings`, `/findings/[id]` | M3 (recommendations), M6 (verify) | Slice 3 | **Adopted for candidate recommendations, derived severity, evidence links and reviewer dismissal; the rest of the review workflow per section 6.4.** FR-002 (separate observation / interpretation / candidate fields) is enforced by the schema. FR-008 (recommendations stay candidates, never auto-applied) holds: `verify.replay` applies a preprocessing defense to an evaluation copy and measures; it never changes the registered model. William's review states `draft` / `in_review` / `confirmed` / `dismissed` / `retest_requested` / `resolved` and the author ≠ reviewer rule (FR-005, FR-007) map onto `Finding.status` / `validation_state` as decided in section 6.4: dismissal (independent, audited) ships in Phase A; confirmation, revisions and resolution are Phase B. Revision history (FR-003) is the audit chain, not a revision table. |
| **F007 Reports and comparison** | `aegis/report.py` (md / json / html renderer with XSS-safe markdown), `aegis/workers/tasks/report.py`, `GET /v1/runs/{id}/report.{ext}` under `REPORT_CSP` with the `REPORT_EXPORT` gate, `GET /v1/runs/{id}/compare` (ΔMRI for verify pairings, side-by-side for same-settings model pairs, `changed_variables` / `unchanged_variables`), report files stored as `Artifact` rows with `sha256`, `aegis/audit/redact.py` on LLM inputs | M3 (report), M6 (ΔMRI); B2 (adversarial-dataset export, section 27.1) | Slice 3; B2 for the export | **Adopted with md / json / html and compatible-run comparison; PDF and policy-gated export deferred.** FR-002 / FR-010 immutability: the report is rendered once at completion and its hash is an `Artifact` row. FR-004 partial labels and FR-007 / FR-008 compatibility rules with per-family denominators are sections 17.2 and 18.3. FR-009 separation of observations, judgments, candidates and retest outcomes is the section 14 evidence model. The MRI is a per-campaign summary that travels with its denominators (D9), recorded in section 4 as a divergence from FR-008's "no universal score". PDF (FR-005) and F008-policy-evaluated export and redaction (FR-006) are Phase B; D006 stays OPEN. **Phase B2 (section 27.1):** F007 gains **adversarial-dataset export**: a Croissant manifest over Parquet built from the run's adversarial slices, registered as `Artifact` rows and written to `datasets/<run-id>/`, carrying the run's provenance, limitations and the ATLAS tags of 27.2; imagery exports stay inside the team's bucket while D006 is open. Not built. |
| **F008 Audit and governance** | `aegis/audit/chain.py` (hash-chained append-only writers: Postgres `AuditEvent` + `AuditChainHead`, JSONL offline), migration `0004_audit_append_only`, `aegis audit verify` CLI, `GET /v1/audit/verify`, `aegis/workers/tasks/worm_export.py` + `aegis/storage/worm.py` (S3 Object Lock), `aegis/services/evidence.py` (evidence pack), `aegis/audit/redact.py` + `aegis/llm/guardrails.py`, web `/audit` | Present in the restored platform; every ML action lands on the chain from M1 (D4 c) | Slice 1 foundation; management tools Slice 3 / Phase B | **Foundation adopted and exceeds William's minimal envelope; management tools and retention deferred.** FR-001 envelope fields map onto `AuditEvent` (`actor`, `action`, `target`, `run_id`, `project_id`, `detail`, `created_at`, `seq`, hashes). FR-002 bounded metadata: `detail` carries hashes, counts and ids, never model bytes, inputs or secrets (section 21). FR-003 append-only is enforced by the migration. FR-004 fail-closed: admission writes the event before rows or enqueue. FR-005 / FR-006 Owner-only browsing ↔ `AUDIT_VERIFY` (admin); filtered event browsing is Phase B (the page verifies chains today). FR-007 to FR-010 policy versions, retention and purge markers are blocked while D006 is OPEN. FR-011 wording: the chain is described as hash-chained and tamper-evident, verifiable with `aegis audit verify`; the product never claims tamper-proof or independently certified logging. |

### 19.2 Cross-feature contracts that this spec fixes

- **Roles.** William's Owner / Analyst / Reviewer / Viewer matrix is mapped onto `scanner` / `remediator` / `approver` / `admin` in section 7, including the independent-approval rule and what of it is enforceable in Phase A. Section 17 uses the aegis names.
- **States.** The `Job` status machine (`queued → running → succeeded | failed | cancelled`, with the transient `running → queued` requeue) and `Finding.status` / `validation_state` are canonical in code; William's run states and finding review states are mapped in section 6.
- **Entities.** `Project` / `Membership` → `Project`, `ProjectMembership`, `Organization`; `ModelVersion` / `DatasetVersion` → `Target` (kind `ml_model_*`, manifest in `targets.detail`) + bundled dataset manifest entries keyed by revision hash; `ProfileVersion` → `CampaignConfig` on the `Run` (`ml_campaigns.config`); `Run` → `Run` + `Job` + `ml_campaigns`; `Evidence` → `Measurement` / `Observation` in the campaign record plus `Artifact` rows; `Finding` / `Recommendation` / `Review` → `Finding` (`schema_blob` ML block) + audit events; `ReportSnapshot` → report `Artifact` rows; `AuditEvent` → `AuditEvent`. Field placement is section 5.
- **Event envelope.** F008's "agreed event envelope" is the existing `AuditWriter.append(action, actor, target, allowlist_check, override, success, detail)` signature; ML action names are in section 5.11.
- **Fixtures.** The rule in `specs/_shared/architecture.md` ("Fixtures used before live execution must be visibly labeled as fixtures. The final demonstration must use genuine evidence") is binding: `TinyTarget` (`tests/ml/fakes.py`) and vitest fixtures exist only under `tests/` and `*.test.tsx`; the deployed app has no fixture path, and Storybook stories carry the illustrative ribbon (section 18.5).

### 19.3 Delivery slices, milestones and the D8 order

| William slice | Slice demo | John milestones | Position in the D8 demo-critical order | Exit evidence |
|---|---|---|---|---|
| Gate 0 — agree product and boundaries | Reviewed scope and interfaces | This spec; D001–D005 resolved in `specs/_shared/decisions.md`; constitution amendments proposed | Before everything | This document approved by the product owner; reconciliation table (section 4) complete |
| Slice 1 — team access and approved catalog (F001 + F002 + F008 foundation) | Authorised members register and select bundled models and datasets; unauthorised users cannot read or mutate; every mutation is on the chain | Restored platform (auth, RBAC, RLS, chain) + M0 (kinds, job types, `ml` extra) + M1's bundled CNN registration | Step 1 (image path) begins here; the **ONNX upload** part of F002 is deliberately step 5, after verify-after-harden | `tests/test_list_endpoint_scoping.py`-style membership tests pass for `/v1/models`; `GET /v1/audit/verify` verifies `model.register` events; upload refusals return the section 17.3 codes |
| Slice 2 — one genuine evaluation and its evidence (F003 + F004 + F005) | Configure a campaign, run it, inspect real evidence, distinguish partial from complete | M1 (FGSM / PGD, ε sweep, findings), M2 (SHAP artifacts), M3 (scoring), M5a (UI), then M4 (tabular) | Steps 1–2 (image path end to end, MRI scorecard) and step 4 (tabular) | A real campaign on the bundled vehicle-imagery model shows measurements with `n`, curve, observations, limitations; a cancelled run shows `partial`; no fixture data anywhere in the deployed UI |
| Slice 3 — human review and accountable reporting (F006 + F007 + F008 tools) | Candidate recommendations, dismissal, verify, report, compare, audit trail | M3 (rules + Pythia writer), M6 (verify-after-harden, ΔMRI), M5b (upload dialog), M7 (Fargate) | Steps 3 (verify-after-harden), 5 (ONNX upload), 6 (Fargate) | Verify produces a measured ΔMRI and a `validation_state` change on the chain; md / json / html reports carry limitations and provenance; compare blocks incompatible runs; `aegis audit verify` passes on the campaign chain |

Section 3.4 states plainly that Phase A as decided exceeds a one-to-two-day build; the D8 order above is the order in which slices are allowed to be cut if time runs out, and the feature statuses in 19.1 are updated to match what actually landed, never the reverse.

### 19.4 Replaced implementation locations

William's plans proposed Replit monorepo paths. D10 replaces them with aegis paths. Feature `plan.md` files keep their FR and verification content; their path tables are read through this mapping.

| William's proposed path | Replacement in this repository |
|---|---|
| `lib/api-spec/openapi.yaml` | FastAPI-generated OpenAPI (`/docs`, non-prod) plus `docs/api/v1.md`; per-feature `specs/00N-*/contracts/*.openapi.yaml` may quote excerpts but the generated document is authoritative |
| `lib/api-client-react/`, `lib/api-zod/` | `web/src/lib/api.ts` hand-written types and helpers (no code generation); vitest fixtures typed against them |
| `lib/db/src/schema/*.ts` | `aegis/db/models.py` and Alembic revisions under `aegis/db/migrations/versions/` (`0010_ml_vertical`, after `0009_tenant_org_id_guard`, adds `targets.detail`, `ml_campaigns` and the section 5 vocabularies) |
| `artifacts/api-server/src/routes/assurance/*.ts` | `aegis/api/v1/{models,datasets,attacks,defenses,ml_capabilities,artifacts,compare,ml_findings}.py` (new) and the existing `runs.py`, `runs_cancel.py`, `findings.py`, `verify.py`, `reports.py`, `audit.py`, `projects.py`, `auth_profiles.py` |
| `artifacts/api-server/src/services/assurance/*.ts` | `aegis/services/{ml_models,ml_campaigns,ml_findings}.py` (new), `aegis/services/{runs,verify,targets,reports,evidence}.py` (existing), and the domain code in `aegis/ml/{schema,targets,attacks,explain,recommend,scoring,datasets,defenses,sandbox}` |
| "No worker runtime selected" (F004) | `aegis/workers/celery_app.py`, `aegis/workers/tasks/{model_validate,attack,explain,harden,verify}.py`, `aegis/workers/bootstrap.py`, `aegis/ml/sandbox.py` (on the `aegis/scanners/sandbox.py` primitives) |
| `artifacts/ai-assurance/src/features/*` | `web/src/app/{models,runs,findings,audit,projects}/…` and `packages/design-system/src/components/*` |
| `artifacts/api-server/src/tests/assurance/*.test.ts` | `tests/ml/*` (marker `ml`, `TinyTarget`), `tests/test_api_*.py`, `tests/test_admission_audit_before_enqueue.py` pattern for the new admission services |
| `artifacts/ai-assurance/src/tests/*.test.tsx` | `web/src/app/**/page.test.tsx`, `*.a11y.test.tsx`, `web/tests/` (Playwright) |
| `specs/008-audit-governance/contracts/audit-event.yaml` | `aegis/audit/chain.py` record shape (`to_record`) and `docs/architecture/audit-chain.md` |

### 19.5 Readiness checklist as the approval gate

The checklist in `specs/_shared/readiness-checklist.md` is applied per feature before its tasks are worked, and its "Done is a separate gate" clause is the reason section 26 exists.

- **Specify.** Stories, FR ids and Given / When / Then scenarios stay in each `spec.md`. Where this spec narrows or defers a story (19.1), the feature owner records the narrowing in the spec's "Unresolved decisions and gates" block, citing the decision id (D1–D13), instead of deleting the story.
- **Clarify.** D001–D005 are RESOLVED in `specs/_shared/decisions.md` with approver "product owner (hackathon), 2026-09-08" (D11). D006 (retention, export redaction, licensing) and D007 (named owners and independent reviewers) remain OPEN; no feature may claim them resolved, no owner name is invented, and every F007 / F008 capability gated on D006 stays blocked.
- **Plan.** Paths are the 19.4 replacements; dependencies follow the slice order in 19.3; access enforcement, data minimisation and execution boundaries are sections 7, 9, 10 and 21.
- **Tasks and analysis.** `F00N/T00N` ids are kept; tasks whose target is a replaced path are re-pointed, not renumbered. The "Incomplete integration is not concealed by fallback fixtures or fake results" box is the 19.2 fixture rule and section 18.5.
- **Approval record.** Product owner / date: the hackathon product owner, 2026-09-08, for scope. Engineering reviewer and security / data reviewer: unassigned until D007 is resolved; their boxes stay open. Decision per feature stays "Draft" until the feature owner runs the checklist after the relevant slice lands.
- **Done.** Acceptance evidence (test output, screenshots of real campaigns, `aegis audit verify` output) is stored next to the feature under `specs/00N-*/evidence/` and referenced from section 26. Specification approval alone is not completion; a story is done only with its visible behaviour, server-side checks, failure states and evidence (constitution VI).

## 20. Deployment

Two deployment shapes are in scope: the docker-compose developer stack (used for every milestone through M6 and for the demo rehearsal) and the ECS Fargate target from S1 §12 (M7). Both run the same three application images plus the same data plane; only the operator surface differs. Nothing in this section exists yet for the ML vertical: the compose file and Dockerfiles listed here are the restored aegis ones, and the changes below are what M0/M7 must make to them.

### 20.1 Developer stack (`deploy/docker-compose.yml`)

The restored compose file already brings up the full platform the product reuses (D1). The table lists every service as it exists today and the change, if any, the ML vertical needs.

| Service | Image / command | Host port | Role for this product | Change required |
|---|---|---|---|---|
| `postgres` | `aegis-postgres:dev` (postgres:16 + pgaudit, `deploy/Dockerfile.postgres`) | 5432 | Runs, Jobs, Findings, Artifacts, campaign/score records (`ml_campaigns`, section 5), RLS-protected tenant tables, Postgres audit chain | None. The Alembic migration `0010_ml_vertical` (section 5.3) runs through the API image's existing `alembic upgrade head` entrypoint. |
| `redis` | `redis:7-alpine` | 6379 | Celery broker (`/0`) and result backend (`/1`) | None |
| `keycloak` | `quay.io/keycloak/keycloak:24.0 start-dev --import-realm` | 8080 | OIDC issuer for the `aegis` realm (`deploy/keycloak/realm-export.json`) | Add the `viewer` realm role (section 7.2). `AEGIS_AUTH_MODE=dev` (dev tokens, `make token-for`) is permitted for the demo per D11 (D002). |
| `minio` | `quay.io/minio/minio` | 9100 (S3), 9101 (console) | Blob store for uploaded models, bundled assets, adversarial examples, SHAP PNG/npz, robustness-curve artifacts; container-internal `http://minio:9000` | Create a second bucket with Object Lock enabled when exercising WORM export locally (`AEGIS_WORM_BUCKET`, default `aegis-worm`). |
| `aegis-api` | `aegis-api:dev` (`deploy/Dockerfile.api`, `pip install -e ".[api,worker]"`) | 8000 | `/v1` routes incl. the new `/v1/models`, attack/explain/harden/verify endpoints (section 17); admission (audit event → Run/Job rows → enqueue) | None to the image. The `ml` extra is **never** installed here; a test asserts the API process does not import `torch`, `art`, `shap`, or `onnxruntime` (section 22). |
| `aegis-worker` | `aegis-worker:dev` (`deploy/Dockerfile.worker`), `celery … worker -Q scans` | — | Runs `model.validate`, `attack.run`, `explain.run`, `verify.replay` (section 10) on the long-running `scans` queue; the only process that loads a model, and only inside the sandboxed loader subprocess (section 9) | Install `.[worker,ml]`; drop the `project_repos/` `COPY` and editable installs (the submodules were deleted, so the current `COPY project_repos/` line fails the build); mount a named volume for the dataset cache (`AEGIS_ML_DATASET_CACHE`) so section 11's dataset fetch happens once. |
| `aegis-worker-default` | same image, `-Q default` | — | `harden.recommend` (rules + the Pythia writer; section 8.3 routes it here so the LLM call never shares a pool with model loading), report rendering, stale-job reaper, WORM export, tenant-integrity checks | Add the Pythia env (20.3) and unset `AEGIS_DISABLE_LLM` on this service when the narrative should run; it never loads a model. |
| `aegis-beat` | same image, `celery … beat` | — | Fires `aegis.reap_stale_jobs` (turns a crashed `running` job into `failed`, section 6) and `aegis.export_chains_to_worm` | None |
| `aegis-web` | `aegis-web:dev` (`deploy/Dockerfile.web`, pnpm workspace `@aegis/web` + `@aegis/design-system`) | 3300 → 3000 | Pages in section 18 | None to the image; new pages are ordinary Next.js routes. |
| `aegis-log-ingest` | `aegis-log-ingest:dev` | 4319 | Postgres mirror of application logs (`application_logs`), queryable by `run_id` | None |
| `opa` (profile `policy`) | `openpolicyagent/opa:0.66.0` | 8181 | Optional external policy engine for the role gate (section 7) | Add the seven new `Action` rows (section 7.4) to the bundle if the profile is used; the static engine is the default and is sufficient for Phase A. |
| `otel-collector`, `loki`, `jaeger` (profile `obs`) | as shipped | 4317/4320, 3100, 16686/4318 | Optional traces/logs | None |
| `elasticsearch`, `kibana` (profile `obs-search`) | as shipped | 9200, 5601 | Optional log search | None |

Operator flow for a fresh checkout (`make` targets forward from the repo root to `deploy/Makefile`):

1. `make up` — builds and starts the default profile. The worker build now pulls the `ml` extra (torch CPU wheel, ART, SHAP, onnxruntime, scikit-learn, matplotlib, pillow, pyarrow, onnx2torch, safetensors); expect this image to be the slowest to build and pin versions early (section 25).
2. `make seed` — creates `default-org`, project `default`, and user `admin` with the `admin` role (existing target).
3. `aegis ml build-assets` (new CLI, M0/M1; `aegis/cli/ml.py`) — runs on the worker image (`docker compose run --rm aegis-worker aegis ml build-assets`): fetches the datasets of section 11 by dataset id and pinned revision (the Kaggle malicious-URLs dataset through its authenticated download, which needs `KAGGLE_USERNAME` / `KAGGLE_KEY` in the environment of this one-off run only; section 11.3.3), trains or exports the bundled models with a fixed seed (and, for the tabular tree ensemble, fits and records the PGD surrogate of section 12.2), writes each model, its `MANIFEST.json` (dataset id, revision hash, split, architecture, epochs, seed, clean accuracy on the evaluation split, library versions, weights sha256) and the dataset slice to the blob store under `ml/assets/` and `bundled/` prefixes, and registers one `Target` row of kind `ml_model_artifact` per bundled model in project `default` (`available`, `source=bundled`). Clean-accuracy figures are recorded here and only here; no document hard-codes them.
4. Optionally export `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `AEGIS_ML_LLM_MODEL` (and `PYTHIA_PERSONA`) and unset `AEGIS_DISABLE_LLM` for `aegis-worker-default` before `make up`; otherwise the LLM writer is off and recommendations render from the rule layer alone with `narrative_source = "rules"` (section 16).
5. Open `http://localhost:3300`, sign in (Keycloak realm user, or dev token), and follow section 24.

### 20.2 Images and dependency groups

`pyproject.toml` already defines the `ml` optional-dependency group (`numpy`, `torch`, `torchvision`, `onnx`, `onnxruntime`, `scikit-learn`, `adversarial-robustness-toolbox`, `shap`, `matplotlib`, `pillow`, `pyarrow`, `httpx`), an `llm` group (the private `pythia-sdk`, optional — `aegis/llm/pythia.py` falls back to its in-repo `httpx` client with the same wire contract), and a `garak` group (Phase B only, D6; not installed in any Phase A image). Section 8.4 adds `onnx2torch` and `safetensors` to the `ml` group at M0.

| Image | Extras installed | Contains model-loading code path | Notes |
|---|---|---|---|
| `aegis-api` | `api`, `worker` | No | Unchanged. Multipart upload streams to the blob store and records the sha256; the file is never opened as a model here (section 9). |
| `aegis-worker` | `worker`, `ml` (+ `llm` only when a build-time token for the private Pythia repo is available; the build must succeed without it) | Yes, in the sandboxed subprocess only | Add `xgboost` to the `ml` group only if the bundled tabular model (section 11, D4d) is an XGBoost booster; otherwise a scikit-learn tree ensemble supported by `shap.TreeExplainer` is used and the group stays as is. The choice is recorded in the asset manifest. |
| `aegis-web` | pnpm workspace | No | Unchanged. |

The three application images are the only ones the team maintains; Postgres, Redis, Keycloak, MinIO, and the observability images are upstream.

### 20.3 Environment variables added by this vertical

All existing `AEGIS_*` variables keep their meaning (`AEGIS_DB_URL`, `AEGIS_BROKER_URL`, `AEGIS_RESULT_BACKEND`, `AEGIS_BLOB_BACKEND=s3`, `AEGIS_S3_ENDPOINT/BUCKET/REGION/ACCESS_KEY_ID/SECRET_ACCESS_KEY`, `AEGIS_AUTH_MODE`, `AEGIS_OIDC_ISSUER`, `AEGIS_OIDC_JWKS_URL`, `AEGIS_CORS_ORIGINS`, `AEGIS_WORKER_SIGNING_KEY`, `AEGIS_AUTH_PROFILES_KEY`, `AEGIS_PLUGINS_SANDBOX`, `AEGIS_PLUGIN_SANDBOX_CPU_SECONDS/MEMORY_MB/FILESIZE_MB`, `AEGIS_PLUGIN_SANDBOX_NETWORK`, `AEGIS_WORM_EXPORT`, `AEGIS_WORM_BUCKET`, `AEGIS_WORM_RETENTION_DAYS`, `AEGIS_DISABLE_LLM`, `AEGIS_LLM_BUDGET_STRICT`, `AEGIS_LLM_GUARDRAILS`).

| Variable | Where | Meaning |
|---|---|---|
| `PYTHIA_BASE_URL` | worker (`default` pool) | Pythia gateway base URL; the client posts to `{PYTHIA_BASE_URL}/v1/chat/completions` (D5). |
| `PYTHIA_API_KEY` | worker (secret) | `pk_…` gateway key, sent as `Authorization: Bearer`. The only LLM credential in the deployment. |
| `PYTHIA_PERSONA` | worker, optional | Sent as `X-Pythia-Persona`. |
| `PYTHIA_TIMEOUT_S` | worker, optional | Request timeout (default 60). |
| `AEGIS_ML_LLM_MODEL` | worker | Canonical model id (`<vendor>/<model>` or `pythia/auto`) for the hardening narrative. This **renames** the scaffold's `REDSIM_LLM_MODEL` (read today in `aegis/llm/pythia.py`, referenced in `aegis/ml/schema.py` and `tests/test_llm_pythia.py`); the rename is an M0 task and the test changes with it (section 22). aegis's per-task router (`aegis.llm.router.route`, task `ml.harden_narrative`) and budget checker still decide whether and at what budget the call is made; Pythia is the transport. |
| `AEGIS_ML_UPLOAD_MAX_MB` | api | Hard cap on uploaded model size (default 512); exceeding it returns `413 model_too_large` (section 17.3). |
| `AEGIS_ML_DATASET_CACHE` | worker | Directory (volume) for the dataset cache used by `build-assets` and the loaders in section 11. |
| `AEGIS_ML_WORK_DIR` | worker | Root of the per-job work directories the sandbox parent populates (default `$TMPDIR/aegis-ml/<job_id>`, mode 0700; section 9.4). |
| `AEGIS_ML_KEEP_WORK_DIR` | worker, optional | `1` keeps work directories after a job for debugging; default removes them. |
| `AEGIS_ML_SANDBOX_TIMEOUT_S`, `AEGIS_ML_SANDBOX_CPU_SECONDS`, `AEGIS_ML_SANDBOX_MEMORY_MB`, `AEGIS_ML_SANDBOX_FILESIZE_MB`, `AEGIS_ML_SANDBOX_THREADS` | worker | Resource ceilings of the ML sandbox child (defaults 1200 s, 900 s, 4096 MB, 1024 MB, 2 threads; section 9.4). There is no network switch: the ML child never gets network configuration. |
| `AEGIS_ML_MAX_ADV_ARTIFACT_MB` | worker | Size above which the full adversarial slice is not retained as an artifact (default 64; section 12.8). |
| `KAGGLE_USERNAME`, `KAGGLE_KEY` | `aegis ml build-assets` one-off run only (worker image) | Kaggle API credentials used solely to download `malicious_phish.csv` (section 11.3.3). Never set on the API, web, steady-state worker or beat services, never in the sandbox child environment (section 9.4), never logged or written to a manifest; CI does not need them because the committed sample is used. |

If any of the required Pythia variables (`PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `AEGIS_ML_LLM_MODEL`) is missing the narrative is skipped, not faked: `PythiaSettings.from_env()` returns `None`, the recommendation keeps `narrative = None`, `narrative_source = "rules"`, and the UI says so (section 18.5).

### 20.4 AWS target (ECS Fargate) — S1 §12, updated

Target: ECS Fargate + RDS PostgreSQL 16 + S3 + ElastiCache Redis. No GPU (S1 §3 non-goal); every bundled model is small enough for CPU inference and attack.

| Component | AWS service | Notes |
|---|---|---|
| API (`aegis-api`) | ECS Fargate service behind an ALB | Reuse `deploy/Dockerfile.api`. Run `alembic upgrade head` as a one-off ECS task before each rollout rather than from every API task's entrypoint, so concurrent tasks never race the migration. |
| Worker (`aegis-worker`) | ECS Fargate service | Reuse `deploy/Dockerfile.worker` with the `ml` extra (20.2). The default image CMD consumes `scans,default`, so one service suffices for the demo; split into two services (`-Q scans` / `-Q default`) when long attacks starve bookkeeping, mirroring compose. Size the task for torch + ART + SHAP on CPU and raise Fargate ephemeral storage above the 20 GiB default if the dataset cache and uploaded models require it. The sandboxed loader's rlimits (section 9.4) must fit inside the task's memory limit. |
| Beat (`aegis-beat`) | ECS Fargate service, one task | Reaper and WORM export schedule. Exactly one task; `celery beat` is not safe to scale. |
| Web (`aegis-web`) | ECS Fargate service behind the ALB, or Amplify | Reuse `deploy/Dockerfile.web`. |
| Log ingest (`aegis-log-ingest`) | ECS Fargate service, optional | Postgres log mirror; skip for the demo if time is short. |
| Postgres | RDS PostgreSQL 16 | RLS is enabled by the existing migrations (`FORCE ROW LEVEL SECURITY` on tenant tables, including `ml_campaigns`). Enable `pgaudit` through the parameter group to match what `deploy/Dockerfile.postgres` adds locally. |
| Redis | ElastiCache (Redis) | Celery broker + result backend. |
| Object store | S3 bucket (artifacts) + a second S3 bucket created with Object Lock (WORM audit export) | Models, adversarial examples, SHAP outputs, robustness curves, reports in the first; `aegis.export_chains_to_worm` writes chains to the second with `COMPLIANCE` retention (`AEGIS_WORM_RETENTION_DAYS`, default 2555). Object Lock must be set at bucket creation. |
| Secrets | AWS Secrets Manager → task-definition secrets | `PYTHIA_API_KEY`, `AEGIS_WORKER_SIGNING_KEY`, `AEGIS_AUTH_PROFILES_KEY` (Fernet), `NEXTAUTH_SECRET`, DB password. **No model-provider keys exist anywhere in the deployment** (D5); Pythia holds them. Prefer an IAM task role over static `AEGIS_S3_*` keys. |
| Auth | Keycloak on Fargate (realm import from `deploy/keycloak/`), or Cognito via OIDC (`AEGIS_OIDC_ISSUER`, `AEGIS_OIDC_JWKS_URL`) | Dev-token mode (`AEGIS_AUTH_MODE=dev`) is acceptable for the hackathon demo (D11/D002) only when the ALB is restricted to the team's addresses; it is never acceptable on an open listener, and it is refused when `AEGIS_ENV=prod`. |
| LLM gateway | Pythia (external, IntelliBridge-operated) | Egress only, from the worker security group to `PYTHIA_BASE_URL` over HTTPS. The API and web tasks have no route to it. |

Network posture: worker egress is limited to RDS, ElastiCache, S3 (gateway endpoint), ECR/Secrets Manager (interface endpoints), the dataset hosts of section 11 (the HuggingFace hub and, for the tabular dataset, the Kaggle API) during `build-assets` only, and Pythia. The sandboxed loader subprocess receives no proxy environment and is expected to make no network calls (section 9.4); that expectation is a defense-in-depth measure, not a network namespace — see section 21.

Build steps (S1 §12, revised):

1. The `ml` optional-dependency group already exists in `pyproject.toml`; install it only in the worker image (`pip install -e ".[worker,ml]"`) to keep the API and web images small. Pin `torch` (CPU wheel index), `adversarial-robustness-toolbox`, `shap`, `onnxruntime`, `onnx2torch` and `safetensors` to exact versions before M1 and record them in `Provenance` (section 14.4).
2. Write a Terraform or AWS Copilot definition for the Fargate services, RDS, ElastiCache, the two S3 buckets, the ALB, and the one-off migration task. Reuse the Helm chart's environment variable names (`deploy/helm/aegis/values.yaml` → `configmap.yaml` / `secret.yaml`) as task-definition environment so compose, Helm, and Fargate agree.
3. Set `AEGIS_BLOB_BACKEND=s3` and point `AEGIS_DB_URL`, `AEGIS_BROKER_URL`, `AEGIS_RESULT_BACKEND` at the managed endpoints; set `AEGIS_WORM_EXPORT=1` and `AEGIS_WORM_BUCKET` to the Object Lock bucket.
4. Run `aegis ml build-assets` once as a one-off ECS task on the worker image to seed the three bundled models (the image CNN trained on the vehicle-imagery dataset of section 11, the URL maliciousness classifier on the malicious-URLs dataset of section 11.3.3 with its surrogate, and the ONNX export of the image CNN that exercises the ONNX loader) and the two evaluation datasets into S3, each with its `MANIFEST.json`. The manifests are the only source of clean-accuracy numbers.
5. Smoke-test in order: `/health`, sign-in, `GET /v1/models` lists the bundled targets as `available`, one FGSM campaign on the bundled image model completes, `aegis audit verify --all` passes.

## 21. Security and trust

This section carries S1 §13 forward and binds it to D2, D3, and D5. Every statement about isolation below describes what the code does today or what a numbered milestone must add; nothing here claims the ML paths are implemented.

### 21.1 Model files are untrusted input (S1 §13, D2)

- **Accepted formats.** ONNX (preferred: a protobuf graph, no code executed on load) and PyTorch `state_dict` files — zip-archived `.pt`/`.pth` loaded with `weights_only=True`, or `.safetensors` — accompanied by an explicit architecture declaration from the in-tree architecture catalog (section 9.2). TensorFlow SavedModel, listed as acceptable in S1 §5, is not accepted in Phase A because no Phase A model uses it; it is a Phase B format decision.
- **Refused by default.** Full pickled models (`torch.save(model)` of an `nn.Module`, `pickle`/`joblib` dumps) are refused at upload time with `415 pickle_refused` (section 17.3), and refused again at validation time on the worker if a file that passed the signature check turns out to contain arbitrary pickle globals (`torch.load(..., weights_only=True)` for `state_dict`; ONNX parsed with `onnx.load` + `onnx.checker`). S1's "I trust this file" override is **not** in Phase A. If it is added in Phase B it is admin-only, still sandboxed, and written to the audit chain as an explicit override (`AuditEvent.override = true`).
- **Where loading happens.** Never in the API process. The API stores the bytes in the blob store, computes and records the sha256 (`Provenance.model_sha256`), checks size and magic bytes, and writes the `model.register` audit event. Only the worker, only inside the ML sandbox built on the plugin-sandbox pattern of `aegis/scanners/sandbox.py` (separate child process launched with a list argv, POSIX rlimits on CPU seconds, address space, file size, open files, processes, core dumps; a wall-clock kill of the whole process group; an allowlisted minimal environment that omits every `AEGIS_*` secret, S3 credential, and the Pythia key; proxy variables stripped so the child has no configured egress), deserializes and runs the model — first in the `model.validate` job, then in every campaign (section 9).
- **What the sandbox is not.** The module's own docstring is the contract: process isolation + rlimits + timeout + minimal environment, **not** a network namespace or a filesystem jail. A hostile file that also defeated the format checks could still open sockets or read files the worker UID can reach. Mitigations in scope: the format allowlist above (the primary control — ONNX and `weights_only` state_dicts do not execute code), least-privilege worker credentials (IAM task role scoped to the artifact bucket prefix; no DB credential in the child environment), the Helm chart's gVisor `RuntimeClass` when deployed on Kubernetes, and security-group egress limits on Fargate (section 20.4). Kernel-level isolation per load remains the follow-up already tracked in aegis's ADRs. OpenSandbox is not used (D11/D004).
- **Resource ceilings** come from `AEGIS_ML_SANDBOX_*` (section 9.4, section 20.3) and are recorded in the Job detail so a timed-out load (`SandboxTimeout`) is distinguishable from a refused one (`ModelLoadRefused`) (section 10.6).

### 21.2 Attacks stay in-boundary (S1 §13, D5)

- No model, dataset sample, adversarial example, SHAP array, or image ever leaves the deployment. The only external call the vertical makes is the hardening narrative, and it goes through Pythia exclusively: `POST {PYTHIA_BASE_URL}/v1/chat/completions`, `Authorization: Bearer pk_…`, optional `X-Pythia-Persona`, canonical `<vendor>/<model>` or `pythia/auto` (D5). There is no litellm, no direct provider SDK, and no provider key in any image, secret store, or environment.
- The writer receives **only** the metrics table, the scorecard numbers, the rule outputs, the limitations and a plain-text SHAP summary (section 16.3). It never receives image bytes, feature vectors, model paths, dataset rows, or user identifiers. One non-streaming chat completion; no tools, no vision content blocks, no structured-output mode.
- Input passes through `aegis.llm.guardrails.guard_input` (secret scrubbing via `scrub_secrets`, prompt-injection detection) and output through `guard_output`/`filter_output` plus the writer's numeric-consistency and banned-word post-checks; `redact_audit_detail` scrubs any detail written to the chain. The `PythiaSettings.redacted()` view is what lands in `Provenance`; the key never does.
- aegis's per-task routing and budget caps remain the policy layer: the narrative call asks `aegis.llm.router.route` for its model under task `ml.harden_narrative`, is gated by the project and organization budgets (`enforce_budget_for_run`), and appears in the `/cost` dashboard. `AEGIS_DISABLE_LLM=1` (the compose default for workers) or missing Pythia settings disable the call; the rule layer still produces every recommendation.

### 21.3 Multi-tenancy

Model targets, runs, jobs, findings, artifacts, and the campaign/score record (`ml_campaigns`, section 5) inherit the existing `org_id` row-level security (`FORCE ROW LEVEL SECURITY` on tenant tables, exercised by `tests/test_tenant_rls.py` against Postgres). Blob keys are prefixed by project and run; `GET /v1/artifacts/{id}` resolves through the RLS-protected `Artifact` row, never from a client-supplied path. One tenant never sees another's model, results, or scorecard. Roles and the independent-approval rule are in section 7.

### 21.4 Audit (S1 §13, D4c)

Every mutating call — model registration (and refused upload), campaign start, explain, harden, verify, report render, reviewer note, finding dismissal — appends to the hash-chained log **before** the Celery task is enqueued, exactly as `aegis.services.scans.create_scan_job` does today (`tests/test_admission_audit_before_enqueue.py` is the pattern to extend). Chains are per project and per run; the Postgres writer (`PostgresAuditWriter`) is used by the platform and the JSONL writer (`JsonlAuditWriter`) by the offline CLI path. `aegis audit verify --all` proves a campaign's trail; `aegis.export_chains_to_worm` copies chains to the Object Lock bucket on the beat schedule. Event detail carries ids, hashes, and counts — never model bytes, sample data, or secrets (constitution VII; William's F008 event contract). The action names are defined in section 5.11.

### 21.5 Data (S1 §13, D3)

- Only open, unclassified, public datasets with a clear license are shipped or fetched (section 11). The dataset id, pinned revision hash, and license are recorded in `Provenance` and shown on the model page and in every report.
- The demo imagery is military-vehicle imagery from such a dataset (D3; section 11.3.1 records that it is ground-level, not overhead). The team recorded this as a knowing divergence from the brief's and constitution's non-operational language, with these bounds, which the UI states on the model page and in the report limitations: open/unclassified data only; the tool evaluates and hardens the robustness of a classifier and never trains, optimizes, or deploys targeting or weapons models; no connection to any mission system; results are evidence for human review, not a readiness or certification statement (sections 4, 14, 15).
- CIFAR-10 is the CI/fixture dataset only (D3); fixture data is never presented as a result (section 14, section 22).
- Uploaded models and datasets are retained under the same lifecycle as other aegis artifacts; deletion is an explicit, audited operation, and the retention/redaction policy remains open in the decision register (D006, section 19).

### 21.6 Web and API hygiene (inherited)

CSRF double-submit on cookie sessions, the WebSocket Origin gate, strict CSP on served HTML reports and artifacts (`default-src 'none'`), `X-Content-Type-Options: nosniff`, per-route RBAC checked server-side (the web `<RoleGated>` is cosmetic), rate limiting, and JWKS caching are all restored aegis behavior and apply to the new routes without change. Upload endpoints add: a size cap (`AEGIS_ML_UPLOAD_MAX_MB`), content sniffing by magic bytes rather than by extension or client `Content-Type`, and a filename that is never used as a storage key.

### 21.7 Phase B connector (not built)

The black-box endpoint connector (D2 Phase B) will reuse `AuthProfile` (Fernet-encrypted bearer/header credentials, key rotation via `AEGIS_AUTH_PROFILES_KEY_PREVIOUS`) and must add an egress allowlist and private-address blocking before any request leaves the worker; aegis's existing target-ownership verification (DNS TXT) gates `verified` targets. Until then `POST /v1/models` with `source: "endpoint"` returns `501 not_implemented` (section 17) and the UI shows the reason.

### 21.8 Interoperability (Phase B2, not built)

- **Exports contain adversarial tensors and labels only.** An adversarial dataset (section 27.1) holds clean and adversarial inputs, true labels, clean and adversarial predictions with confidences, the per-sample attack id and ε, slice indices, and a provenance manifest. It never contains model weights or model files, secrets, Pythia settings, credentials, user or organisation identifiers, reviewer notes, or raw URL strings from the tabular dataset (feature vectors only, section 11.3.3). The export job fails rather than write a manifest whose rows disagree with the run record.
- **Foundry and Lattice hold only their configured connection.** Each integration is off by default. When enabled it holds exactly the connection it was configured with: a base URL and a token or IAM role scoped to the target dataset or entity, read by the `default` worker pool from the environment or the section 20.4 secret store. No standing credential exists anywhere else, nothing is cached in `Job.detail`, artifacts, audit rows or exports, and neither the API process nor the sandbox child ever sees these settings. Pushes are HTTPS calls to the platforms' REST APIs, not LLM calls (D5 unaffected).
- **Consumed data is untrusted input.** Croissant manifests and Parquet files from other teams are stored and hashed by the API and parsed only on the worker inside the sandbox child with `pyarrow`; a manifest that references anything outside the registered upload is refused; the open, unclassified, licensed rule of section 11.1 applies to every registered slice; ONNX models from other teams take the section 9 path unchanged.
- **Egress.** B2 adds to the worker's `default` pool exactly the export bucket, the configured Foundry API host and, only if a decision ever enables it, the Lattice endpoint; the security-group posture of section 20.4 is extended to those hosts and no others. The D3 bound "no mission-system connections" blocks the Lattice integration until an explicit decision resolves the conflict (section 27.3).
- **Redistribution.** Imagery exports stay inside the team's artifacts bucket while D006 (export redaction) is open (sections 11.5, 27.1).

## 22. Testing plan

The plan keeps aegis's existing suite green, adds an offline `ml` tier that needs no dataset download and no network, and asserts the reporting principles as code. Commands: `pytest -q` (default; `addopts` excludes `docker`, `e2e`, `slow`, `auth_required`), `pytest -m ml`, `pytest -m integration`, `make check` (ruff → mypy → pytest), `pnpm --filter @aegis/web test` (vitest), `pnpm --filter @aegis/web typecheck`.

### 22.1 Tiers and markers (`pyproject.toml`)

| Marker | Exists | Environment | What runs |
|---|---|---|---|
| `unit` (default) | yes | `pip install -e ".[test,dev]"`, no services, no `ml` extra | Pure-Python tests. ML tests that import torch/ART/SHAP use `pytest.importorskip` and are stamped `ml`, so this tier skips them instead of failing. |
| `integration` | yes | sqlite harness from `tests/conftest.py` (auto-stamped when a test requests `db_session` / `sqlite_session_factory`); Postgres + Redis in the CI integration job | DB-backed admission, RLS (Postgres only), audit chain, job state, ML routes with `TestClient`. |
| `ml` | yes ("needs the ml extra (torch/ART/SHAP); skipped when absent") | `pip install -e ".[test,dev,ml]"`, CPU, offline | Attacks, control, sweep, SHAP, scoring, loader, verify loop, Celery task bodies in eager mode — all on the `TinyTarget` fake. A new CI job installs the `ml` extra and runs `pytest -m ml`. |
| `slow` | yes | opt-in | Anything that touches the CIFAR-10 fixture slice end to end or trains a model. |
| `e2e` | yes | live compose stack, `AEGIS_E2E` set | One browser campaign against the bundled image model (Playwright, `web/tests/`). |

Budget: the default `pytest -q` stays under a minute with no services and no LLM (the aegis "offline path stays sacred" rule); the `ml` tier targets a few minutes on a laptop CPU because every test uses 8×8×3 inputs.

### 22.2 Shared doubles and fixtures

- `tests/conftest.py` — `make_sqlite_session_factory` / `sqlite_session_factory` / `db_session` (JSONB compiled to TEXT, `StaticPool` so route handlers see the seeded rows). ML DB tests reuse these; nothing new is hand-rolled.
- `tests/ml/fakes.py::TinyTarget` (exists) — satisfies the `Target` protocol with a random-weight one-conv net on 8×8×3 inputs, 3 classes (`circle`, `square`, `triangle`), seeded `sample(n, seed)`, `art_classifier()` returning an ART `PyTorchClassifier` with `clip_values=(0, 1)`, `torch_model()`, and a `manifest()` with a weights sha256. Every attack/explain/score/verify test runs against it.
- `tests/ml/fakes.py::TinyTabularTarget` (to add, M4) — a scikit-learn tree ensemble on a seeded 12-feature, 3-class synthetic table with a declared linear surrogate; exposes the same protocol with `art_classifier()` returning the matching ART estimator and `torch_model()` raising `NotImplementedError`.
- `tests/ml/fixtures/cifar10_test_500.npz` + `tests/ml/fixtures/MANIFEST.json` (to add, M1) — the pinned 500-image CIFAR-10 test-split slice of section 11.3.5 written by `aegis ml build-assets --fixture`, with its source dataset id, revision hash, indices, and sha256 in the sidecar manifest. It is the CI/fixture dataset (D3); it is never registered as a demo target and no code path serves it as a result.
- `tests/ml/fixtures/malicious_urls_sample.csv` + a `MANIFEST.json` entry (to add, M4) — a seeded, stratified sample of a few hundred rows of the Kaggle malicious-URLs dataset (section 11.3.3; CC0) with the source-file sha256, row indices and sample sha256 recorded. It is the CI fixture for the lexical feature extractor and the tabular attack / explain path; the vendored Spambase CSV (11.3.6) remains the all-continuous fixture. Neither is ever registered as a demo target or served as a result, and no test contacts Kaggle.
- `tests/ml/fixtures/run_record.json` (to add, M5a) — one `RunRecord` produced by the `ml` tier from `TinyTarget`, used by vitest page tests. Its `target.name` is "Tiny random CNN (test double)" so a fixture can never masquerade as a real model in a screenshot.
- Pythia: `httpx.MockTransport` handlers (pattern in `tests/test_llm_pythia.py`); no test ever contacts a gateway.

### 22.3 Backend tests

| File | Tier | Asserts |
|---|---|---|
| `tests/ml/test_schema.py` | unit | `RunRecord` round-trips through `model_dump`/`model_validate`; `Observation.metric_kind` accepts only `"heuristic"`, `Interpretation.kind` only `"inferred"`, `CandidateRecommendation.status` only `"candidate"` and `.validation` only `"not evaluated"` or `"measured"` (a `ValidationError` on any other value; `"measured"` without a `measured` block and a `measured` block without `"measured"` are both rejected, section 16.4); a `succeeded` record with empty `limitations` is rejected; a dangling `basis` / `triggered_by` citation is rejected (section 14.1); `STANDING_LIMITATIONS` contains the "not causal proof", "candidates", and "does not establish safety or readiness" statements and the dataset template renders with `CIFAR-10`; `Measurement.n_correct <= n`, `accuracy == n_correct / n`, and `per_class` counts sum to `n`. |
| `tests/ml/test_attacks.py` | ml | FGSM and PGD on `TinyTarget` over 16 samples: output shape equals input shape; `max|x_adv − x|∞ ≤ eps + 1e-6`; values stay in `[0, 1]`; identical outputs under the same seed; `resolve_params` rejects out-of-range `eps`/`max_iter` with `ValueError`; `AttackOutput.library_versions` carries `art` and `torch`. |
| `tests/ml/test_noise_control.py` | ml | The benign control at the same `eps` stays inside the L∞ ball, is gradient-free (the ART classifier's gradient method is never called — asserted via a spy), and produces a `Measurement` with `family="control"` and the same `n` as the evasion row. |
| `tests/ml/test_eps_sweep.py` | ml | A sweep over `{0.01, 0.03, 0.1}` yields one `Measurement` per `(attack, eps)` with equal `n`; the `ml.curve` JSON artifact has exactly one point per eps with `n` on each point; the reference budget is present in the grid. |
| `tests/ml/test_explain.py` | ml | `shap.GradientExplainer` on `TinyTarget` produces clean and adversarial attribution arrays of image shape; `center_mass_ratio_*` lies in `[0, 1]` and the `Observation` carries `metric_kind="heuristic"`; `expl_shift = clamp(1 − cosine(clean, adv), 0, 1)` lies in `[0, 1]` and the noise floor is recorded beside it; PNG and `.npz` artifacts are written with sha256s that match `Observation.artifact_sha256`; the tabular path (`TreeExplainer` on `TinyTabularTarget`) writes bar and beeswarm PNGs plus raw values. |
| `tests/ml/test_url_features.py` | unit | The lexical feature extractor of 11.3.3 (`aegis/ml/datasets/url_features.py`) is a pure function of the string: identical output for identical input; defined output for empty, malformed and non-ASCII strings; feature values inside the manifest's declared ranges on the committed sample `tests/ml/fixtures/malicious_urls_sample.csv`; with `socket.socket` patched to raise, extraction over the whole sample and the tabular target's `predict_proba` on it make no network call (the "URLs are data" rule); the report renderer emits no anchor element for a URL string (`aegis/report.py` escaping). |
| `tests/ml/test_recommend.py` | unit | Each rule in section 16.2 and each interpretation rule in section 14.6 fires on a synthetic measurement set and cites the triggering measurement ids in `triggered_by` / `basis`; on a flat set nothing fires except R7; every emitted recommendation has `status="candidate"`, `validation="not evaluated"`, and **no numeric expected gain field** (D9 iv); the ART defense reference is present. |
| `tests/ml/test_narrative.py` | unit | With Pythia configured (mock transport) the request goes to `/v1/chat/completions` with `Authorization: Bearer pk_…` and the persona header, one `system` + one `user` message, no `tools`, no image content blocks; the user prompt contains only the metrics table, scorecard numbers, rule outputs, limitations and SHAP text summary (asserted: no base64, no `.onnx`/`.pt` paths, no dataset rows); every number in the returned narrative appears in the payload (numeric-consistency check) and no banned word passes; `guard_input`/`guard_output` are invoked; with settings missing the recommendation has `narrative=None` and `narrative_source="rules"`; a 4xx/5xx from the gateway degrades to rules, never fails the job. `tests/test_llm_pythia.py::test_from_env_requires_all_three` changes `REDSIM_LLM_MODEL` → `AEGIS_ML_LLM_MODEL` (D5). |
| `tests/ml/test_scoring.py` | unit | MRI from a stored measurement set is deterministic; the five subscores each lie in `[0, 100]`; weights are `0.35/0.25/0.20/0.10/0.10` and sum to 1; `MRI == round(Σ w·S)`; the score record refuses to compute across measurements from more than one modality (D9 i); serialization of a score without its subscores, per-family table with denominators, and eps grid is impossible (the record type requires them, D9 ii); grade-band readings contain none of `Hardened`, `fielding`, `deployment-ready`, `certif` (regex, D9 iii); severity derivation reproduces section 15.5's thresholds for `eps_small`/`eps_mid`/`eps_large` × ASR; ΔMRI is computed only when `settings_hash` and `sample_indices_sha256` match, otherwise the comparison raises the incompatibility error surfaced as `409 incompatible_campaigns` (D9 iv). |
| `tests/ml/test_loader_refusals.py` | ml | A pickled `nn.Module` is refused (format check) before any deserialization; a `state_dict` without a registered architecture id is refused; a `state_dict` containing non-tensor globals is refused by `weights_only=True`; an ONNX file that fails `onnx.checker` is refused; an oversize file is refused at the API; each refusal produces the error code of section 17.3 and a `model.register` / `model.validate` audit event; a valid ONNX and a valid `state_dict` load and predict on 8×8×3 inputs; the target status moves `registered → validating → available | refused`. |
| `tests/ml/test_sandbox_loader.py` | ml | The loader is invoked through the sandbox seam (list argv, `start_new_session=True`, `preexec_fn` present on POSIX); the child environment contains no `AEGIS_*` secret, `PYTHIA_API_KEY`, or proxy variable; a loader that sleeps past the timeout is killed as a process group and the Job records `SandboxTimeout`, distinct from `ModelLoadRefused`; loader stdout is a single JSON line. |
| `tests/test_api_process_has_no_ml.py` | unit | Importing `aegis.api.app` and building the app leaves `torch`, `art`, `shap`, `onnxruntime` absent from `sys.modules`. |
| `tests/ml/test_admission.py` | integration | For `upload_model_artifact`, `create_attack_campaign`, `create_explain_job`, `create_harden_job`, `create_verify_job` (section 10): the audit row is written first, then Run/Job rows, then the enqueue (order asserted with the `InMemoryAuditWriter` and a patched `apply_async`, the pattern of `tests/test_admission_audit_before_enqueue.py`); the `Target.kind` values `ml_model_artifact`/`ml_model_endpoint` and the new `Job.type` values pass schema validation; an endpoint target returns `501 not_implemented` and still writes the refused audit event; a campaign on a `validating` or `refused` target returns `409 model_load_refused`. |
| `tests/ml/test_tasks.py` | ml + integration | Celery task bodies run eagerly against the sqlite harness with `TinyTarget`: `model.validate` sets `available` with `gradients=true`; the `attack.run` chain writes one `Finding` per attack family that crosses `finding_asr_threshold`, with `schema_blob` fields per section 5.7 and derived `severity`, and the second attack job reuses the first job's `m.clean` / `m.control.*` rows; `explain.run` writes `Artifact` rows and the score record only when all five subscores exist; `harden.recommend` writes interpretation and candidates; `verify.replay` applies the configured ART preprocessing defense, re-runs the same attack set/eps grid/seed, stores baseline and defended score records and ΔMRI (sign not asserted — a defense may not help), moves `Finding.validation_state` through `_STATE_MAP` and `Finding.status` per section 6.4; job status transitions obey `aegis.workers.job_state.ALLOWED`; a raised exception lands the job in `failed` with the error, cancels the downstream chain jobs, and preserves partial measurements marked `partial` (section 10). |
| `tests/ml/test_audit_campaign.py` | integration | A full campaign against the JSONL writer yields `model.register`, `model.validate`, `attack.run`, `model.load`, `attack.execute.*`, `explain.*`, `campaign.score`, `harden.*`, `verify.*`, `job.complete` events on the project and `run:<id>` chains; `verify_chain` passes; mutating any event breaks it; detail payloads contain no secret keys per `redact_audit_detail`. |
| `tests/ml/test_report.py` | unit | Markdown report contains, in order: configuration and provenance, measurements by family with `n` (with the MRI scorecard sub-block including subscores and eps curve), observations, interpretation (labelled inferred), candidate recommendations (labelled candidate / not evaluated), limitations (section 14.8); HTML escapes a `<script>` in a class name (reusing `aegis/report.py`'s escaping and CSP); JSON equals `RunRecord.model_dump()` plus the score record; a report of a run without a sweep says so in limitations. |
| `tests/ml/test_routes.py` | integration | `TestClient`: `GET /v1/models` lists bundled targets and, for the LLM domain, `status="not_implemented"` with a reason; `POST /v1/models` multipart happy path (`201`, `status="validating"`) and each refusal code; `POST /v1/models/{id}/attacks` validates the campaign configuration (attack ids, eps grid, reference budget in grid, threshold, `n_samples` bounds, seed) and returns 202 with `run_id`; `GET /v1/artifacts/{id}` returns 404 for unknown ids and never accepts a path; `GET /v1/runs/{id}/compare` returns `409 incompatible_campaigns` on a seed mismatch; list endpoints are scoped to the caller's project memberships; `PATCH /v1/findings/{id}/status` returns `403` for the campaign creator. |
| `tests/test_tenant_rls.py` (extend) | integration (Postgres) | `ml_campaigns` and `targets.detail` are covered by `FORCE ROW LEVEL SECURITY`; a cross-org read of a score record returns nothing. |

### 22.4 Frontend tests (vitest, `web/src/**/*.test.tsx`)

| File | Asserts |
|---|---|
| `app/models/page.test.tsx` | Bundled models render with dataset name, license, revision hash, and clean accuracy read from the manifest; the "Connect endpoint" tab shows the Phase B not-implemented reason and no launch button; the upload dialog states accepted formats and shows the refusal message returned by the API; a `refused` model shows its reason and no launcher. |
| `app/models/[id]/page.test.tsx` | The launcher renders attacks from `/v1/attacks` with `params_schema`, the eps grid, reference budget, finding threshold, `n_samples`, seed, and the control toggle; white-box attacks are disabled when `gradients` is false; submitting posts the `CampaignConfig` body of section 17.2 (F003). |
| `app/runs/[id]/page.test.tsx` (extend) | The MRI scorecard never renders without the five dimension bars, the per-family accuracy table with `k / n` denominators, and the eps curve (a fixture missing any of them renders the "Score unavailable" state instead); the grade reading text is attack-scoped; the `StageTimeline` shows section 6.5's stages; a `failed` or partial run shows the completeness banner rather than a score; the panel order of section 18.3 holds. |
| `app/findings/[id]/page.test.tsx` (extend) | Three panes are present and separately labelled: input pair (clean, adversarial, and the noise control at the same eps), SHAP clean vs adversarial with "heuristic" on the center-mass metric, and recommendations each labelled "candidate · not evaluated" with **no expected-gain number**; the interpretation list is labelled "inferred" with its basis ids; limitations are visible; "Verify fix" is role-gated; after a verify the ΔMRI block appears with the before/after settings shown equal and the `validation_state` chip reads the section 6.4 wording. |
| `app/findings/[id]/page.a11y.test.tsx`, `app/runs/[id]/page.a11y.test.tsx` | axe passes on the new panels (existing a11y test pattern). |
| `components/*.test.tsx` | `MriScorecard`, `RobustnessCurve`, `MeasurementTable` refuse to render a bare number: props are typed to require subscores and denominators. |

Every page test uses `tests/ml/fixtures/run_record.json` (a test double, section 22.2); the footer line "Proof of concept on open, unclassified public data. Results are evidence for human review, not a safety, readiness, or certification determination." is asserted on every page.

### 22.5 End-to-end and CI

- `web/tests/ml_campaign.spec.ts` (Playwright, `e2e`): sign in with a dev token, pick the bundled image model, launch FGSM + PGD with the default grid, wait for `succeeded`, open the finding, run "Verify fix", open `/audit`. Gated by `AEGIS_E2E`; not part of the merge gate.
- CI jobs: **unit** (minimal env, default markers), **integration** (Postgres + Redis, `-m integration`), **ml** (`.[test,dev,ml]`, `-m ml`, offline), **web** (`pnpm typecheck && pnpm test`), plus the existing `ruff`/`mypy` gates. The `ml` job caches the torch wheel.
- The concurrent platform fix-up must leave the restored suite import-clean before the ML tier is added; the ML tier is not merged while the default tier is red.

## 23. Milestones

S1 §14's milestones and ids are kept. Two things change: the demo-critical order inside Phase A (D8) is made explicit, and each milestone is mapped to the Spec Kit slice and features it delivers (D10, section 19) with an exit check that can be verified rather than asserted.

**Timeline statement.** The product owner's original estimate was 1–2 days. Phase A as decided — image and tabular paths, ONNX/state_dict upload with sandboxed loading, eps sweep, verify-after-harden, MRI, full audit coverage, on the full aegis platform — exceeds a 1–2 day build. S1 §16's risk stands: freeze Phase A first, execute it in the D8 order below, and do not start any Phase B item until the image path runs end to end in the browser. If time runs out, the milestones after the cut line are reported as not implemented in the UI and README (section 26), never simulated.

| # | Milestone | Deliverable (S1 §14, updated) | D8 order | Spec Kit slice / features | Exit check |
|---|---|---|---|---|---|
| M0 | Scaffold | `aegis/ml/` package (schema, target/attack protocols, and Pythia client already exist as contracts); Alembic migration `0010_ml_vertical` adding `targets.detail`, `ml_campaigns`, and the `Target.kind` / `Job.type` / `Run.scanner` values of section 5; `aegis/ml/schema.py` additions of section 5.3 (`CampaignConfig`, `MRIRecord`, `MLFindingDetail`, `MLModelManifest`, new `Measurement`/`Observation`/`Provenance` fields, `score` stage); the seven `Action` members and `viewer` rank (section 7); `ml` dep group (exists) plus `onnx2torch`/`safetensors` installed in `Dockerfile.worker` with the `project_repos` lines removed; `REDSIM_LLM_MODEL` → `AEGIS_ML_LLM_MODEL`; `/v1/scans` unmounted and stale `Action` members pruned; `aegis ml build-assets` CLI skeleton; decision register rows D001–D005 recorded (D11); constitution amendment proposals appended (D12). | 1 | Gate 0 + Slice 1 (F001 and F008 event foundation are already aegis; F002 schema) | `alembic upgrade head` on a fresh DB; `pytest -q` green; API process imports no ML library. |
| M1 | Load + attack (image) | Bundled CNN trained on the vehicle-imagery dataset of section 11 by `build-assets` with `MANIFEST.json`; `model.validate` job and the ML sandbox child for bundled torch weights and ONNX (section 9); FGSM + PGD adapters; **eps sweep** over `{0.01, 0.03, 0.1}` with the `ml.curve` artifact (D4b); **benign noise control** at each eps; `Measurement` rows with `n`, per-class counts, norms; `Finding`s with derived severity; the `attack.run` chain; audit events for register/validate/attack (D4c). | 2 | Slice 2 (F002 bundled catalog, F003 campaign configuration, F004 run) | `pytest -m ml` attack/control/sweep tests green; one campaign completes on the compose stack with chain verified. |
| M2 | SHAP (image) | `explain.run` produces clean vs adversarial saliency PNG + `.npz` `Artifact`s, `center_mass_ratio` labelled heuristic, `expl_shift` and its noise floor per attack at `reference_eps` for `S_expl`; explain audit event. | 3 | Slice 2 (F005 evidence) | Artifacts stream under CSP; observations carry sha256s. |
| M3 | Recommendations + scoring | Score stage in `explain.run`: **MRI** subscores, aggregate, grade bands with attack-scoped readings, severity derivation, refusal to mix modalities or compare incompatible campaigns (D9), `campaign.score` audit event; `harden.recommend` job with the interpretation rules (14.6), the rule layer citing triggering measurement ids (16.2), the LLM writer through Pythia with guardrails and post-checks, text-only, off by default (D5); md/json/html report render; harden audit event. | 4 | Slice 2 → 3 (F006 candidates, F007 score record and report) | Scoring tests green; narrative degrades to rules when Pythia is absent. |
| M5a | UI — image slice | `/models` (bundled picker, endpoint tab as not-implemented), `/models/[id]` launcher, `/runs/[id]` with stage timeline, MRI scorecard (never without subscores, denominators, eps curve), findings table with dismissal; `/findings/[id]` three panes with separate measurement / observation / interpretation / candidate panels and labels; limitations and footer everywhere. | 5 | Slice 2 (F005) + Slice 3 (F006 view, dismissal) | vitest page tests green; image path demonstrable end to end in the browser. **Cut line for a demo.** |
| M6 | Verify loop | `verify.replay` for ML: apply an ART preprocessing defense (feature squeezing or spatial smoothing), re-run the whole attack set/eps grid/seed, store baseline and defended score records, report **measured ΔMRI** and per-dimension deltas, attach `MeasuredDelta` to the recommendation, update `Finding.validation_state` and `Finding.status` (D4a); "Verify fix" button; compare route; verify audit events. | 6 | Slice 3 (F007 comparison, F006 retest) | ΔMRI shown only for compatible settings; a non-positive delta is displayed as measured. |
| M4 | Tabular path | Bundled **URL maliciousness classifier** (sklearn/XGBoost on lexical URL features) trained by `build-assets` on the Kaggle malicious-URLs dataset (`sid321axn/malicious-urls-dataset`, CC0; section 11.3.3) with its build-time surrogate, clean metrics in the asset manifest and the committed CI sample; the `url_features` extractor with its no-network test; PGD by surrogate transfer + HopSkipJump with the realizability caveat on every row (12.9); `TreeExplainer` bar/beeswarm on the lexical features; same measurement, scoring, and UI contracts with a feature-diff table in pane 1 (D4d). UNSW-NB15 (11.3.4) is the fallback if the Kaggle download cannot be completed. | 7 | Slice 2 second adapter (F002–F005) | Tabular campaign completes; MRI computed per campaign, never across modalities; `pytest -m ml` runs the tabular tests on the committed sample without a Kaggle token. |
| M5b | UI — upload path | Upload dialog (ONNX, `state_dict` / `safetensors` + architecture id), `validating` / `refused` states with the section 17.3 error codes, model page showing sha256, license, revision; `/audit` view of a campaign. | 8 | Slice 1 completion (F002 upload rules), Slice 3 (F008 UI) | Refusal tests green; pickled upload is refused end to end. |
| M7 | Deploy | Fargate services + RDS + ElastiCache + two S3 buckets + Secrets Manager; one-off migration and `build-assets` tasks; Pythia egress from the worker only; demo run end to end with `aegis audit verify --all`. | 9 | Slice 3 (F008 WORM export) | Section 20.4 smoke test passes; README records the measured clone-to-first-run time (section 26). |
| B1+ | Stretch (Phase B) | Black-box endpoint connector over `AuthProfile` with egress allowlist; Carlini-Wagner, DeepFool, HopSkipJump (image), ZOO; text and detection modalities; KernelSHAP for black-box; adversarial-training defense; garak LLM-domain probes pointed at Pythia (D6); pickle override (admin-only, sandboxed, audited); finding review states beyond dismissal (section 6.4); per-project scoring overrides; `Idempotency-Key`; PDF export. | after Phase A | Deferred extensions (specs/README.md) | Each item appears in the UI as not implemented with a reason until it lands. |
| B2 | Interop | Croissant adversarial-dataset export + ONNX ingest; MITRE ATLAS tagging; Foundry push (Lattice exploratory). | after B1+ | Deferred extensions; F002 consume side and F007 export (section 19); section 27 | An exported manifest validates as Croissant, its sha256 matches the registered `Artifact` rows, and a consumer re-reads the Parquet payload with the recorded labels and per-sample ε; ATLAS tags appear on new findings, in the report and in the manifest; the Foundry push succeeds against a configured instance and is audited on the run chain; Lattice stays text-only until the D3 conflict is decided (section 27.3); every control shows not implemented until then. |

Milestone reviews use the readiness checklist (section 19.5): specification approval and "done" are separate gates, and a milestone is done only with passing checks, acceptance evidence next to the feature, and a behavior-to-spec comparison.

## 24. Demo script

Target demo, following S1 §15 with the D3 dataset. **Every number in this script is illustrative** (brief: "Label any illustrative results as illustrative. Do not invent completed runs, measured improvements, or validated fixes."). The real values come from the run that is executed live; if the live values differ, the live values are what is shown and said.

Preconditions: the compose stack (or the Fargate deployment) is up; `aegis ml build-assets` has seeded the bundled models; the presenter is signed in with a role that permits `attack.run`, `harden.recommend` and `verify.replay` (`remediator` or above, section 7), and a second identity with `approver` is available if the dismissal step is shown (section 7.7); Pythia settings are present on the `default` worker or the presenter states up front that the narrative is off and recommendations are rule text.

1. **Models.** Open `/models`. The list shows the three bundled targets as `available`. Pick the bundled vehicle-imagery CNN. Its page shows the dataset name, license, and pinned revision from section 11, the model's sha256, and the clean accuracy read from `MANIFEST.json` (the presenter reads the figure from the screen; it is not in this script). Point out the bounds banner: open/unclassified data; robustness evaluation only; no targeting, weapons, or mission-system use (D3).
2. **Run attack.** Click **Run attack**. Select FGSM and PGD, eps grid `{0.01, 0.03, 0.1}` with reference budget `0.03`, the default finding threshold, sample size and seed, benign noise control on, `explain_k` at its default, LLM narrative on if Pythia is configured. Start. The admission writes the audit event before the jobs are queued (section 10); show the run id.
3. **Campaign.** Watch `/runs/[id]`. The stage timeline advances through load, sample, clean evaluation, attack (three eps values × two attacks), control, explain, score, interpret, recommend, report. When it completes the MRI scorecard appears **together with** its five dimension bars, the per-family accuracy table with denominators (`clean k/n`, `fgsm@eps k/n`, `pgd@eps k/n`, `control@eps k/n`), and the robustness curve. *Illustrative:* the score lands near 38, grade F, and a finding with derived severity `critical` appears because PGD crossed its threshold at the smallest eps with ASR ≥ 0.5 (section 15.5). Say aloud that the grade describes robustness under FGSM and PGD at this grid on this slice and is not a readiness statement.
4. **Finding.** Open the finding. Left pane: a vehicle image from the demo dataset's class list (section 11), clean vs adversarial, near-identical to the eye, alongside the noise-control image at the same eps that did **not** flip the prediction. Middle pane: SHAP clean vs adversarial; the center-mass ratio, labelled heuristic, dropped, and the interpretation statement, labelled inferred, says the attribution moved from the vehicle toward the background. Right pane: candidate recommendations — adversarial training, input preprocessing (feature squeezing / spatial smoothing), confidence calibration — each labelled candidate / not evaluated, each citing the measurement that triggered it, **with no expected-gain number** (D9 iv). If Pythia is configured, the narrative is labelled "LLM-generated narrative of rule outputs"; if not, the rule text stands.
5. **Verify fix.** Click **Verify fix** and choose feature squeezing. The worker applies the ART preprocessor, re-runs the same attack set, eps grid, and seed, and writes a second score record. *Illustrative:* the MRI climbs to about 71 (grade C) and a ΔMRI of about +33 shows on the scorecard with per-dimension deltas and the clean-accuracy change; the finding's `validation_state` records the verify outcome (section 6.4). Say that ΔMRI is a measured delta on this model at these settings and the only sanctioned form of "gain". If the live delta is small, zero, or negative, show it as measured — that outcome is also a result.
6. **Tabular (D4d).** Open the bundled **URL maliciousness classifier** (lexical features of the Kaggle malicious-URLs dataset, section 11.3.3; its page shows the "CC0: Public Domain" license statement, the source-file sha256 and the clean metrics read from `MANIFEST.json`). Launch PGD (surrogate transfer) + HopSkipJump with the default tabular grid and open its run: the same scorecard shape, a feature-diff table in pane 1 (the clean row's URL shown as inert text, never a link), and `TreeExplainer` bar and beeswarm plots in pane 2 over features such as `url_length`, `count_dot`, `subdomain_count`, `shannon_entropy`. *Illustrative:* HopSkipJump flips roughly a third of the clean-correct rows within the reference budget while the noise control leaves accuracy essentially unchanged, and two of the top-five SHAP features change rank between clean and adversarial rows; the PGD rows are labelled "white-box via surrogate transfer". Say aloud that these are feature-space perturbations — decision-surface evidence carrying the realizability caveat of section 12.9, not demonstrated URL evasion — and that this campaign's MRI is its own number and is never combined with the image campaign's (D9 i).
7. **Honest edges.** On `/models`, show the "Connect endpoint" tab marked not implemented with its reason (Phase B), and on the launcher the Phase B attacks listed as unavailable. Optionally, with the second identity, dismiss a finding with a reason and show that the campaign creator cannot. Nothing is faked.
8. **Audit.** Open `/audit` for the campaign: register/validate, attack, explain, score, harden, verify, and report events in one hash chain. Run `aegis audit verify --all` in a terminal and show the result.
9. **Report.** Download the Markdown or HTML report: configuration and provenance (dataset id and revision, model sha256, library versions, seed, nondeterminism sources), measurements by family with denominators, observations, interpretation, candidates, the score with subscores and eps curve, and the standing limitations.

## 25. Open risks

S1 §16's four risks remain and are joined by the risks the decisions of 2026-09-08 introduce.

| Risk | Consequence if ignored | Mitigation / owner action |
|---|---|---|
| **Timeline (D8).** Phase A as decided exceeds a 1–2 day build. | Half-built paths get demoed as if finished. | Execute in the D8 order (section 23); cut line after M5a; everything past the line is shown as not implemented, never simulated. Product owner decides the cut on demo-day morning. |
| **ART + SHAP + torch image size (S1).** | Slow builds, failed Fargate pulls. | `ml` extra in the worker image only; CPU torch wheel from the CPU index; pin versions at M1; cache the wheel in CI. |
| **SHAP on images is slow (S1).** | Explain stage dominates run time. | Small models; `explain_k ≤ 32` with a default of 8; 50-image background; cache explanations per `(model sha256, dataset revision, sample index, attack, eps, explainer, nsamples, seed)`; `GradientExplainer`/`DeepExplainer` for white-box, `PartitionExplainer` only when gradients are unavailable (section 13.10). |
| **Pickle safety (S1, D2).** | Code execution on load. | ONNX preferred; `state_dict` with `weights_only=True` and an explicit architecture; pickles refused by default; loading only in the sandboxed worker subprocess; override not in Phase A. |
| **Scope creep across modalities (S1).** | Image + tabular never finish. | Freeze Phase A; no text/detection/endpoint work before M5a runs end to end. |
| **ONNX uploads and white-box attacks.** ART has no gradient-capable ONNX estimator; `onnxruntime` is inference-only, so FGSM/PGD cannot run natively on an ONNX upload. | The preferred upload format silently downgrades the attack set, or an ONNX campaign fails at attack time. | `model.validate` records `gradients` per target from the `onnx2torch` conversion outcome; targets without gradients get the black-box attack set (HopSkipJump) and `PartitionExplainer`, and the launcher shows which attacks are available and why (sections 9.5, 18.2); the bundled ONNX export exists precisely to exercise this path (section 20.4). The conversion-library choice is recorded in the register at M1. |
| **Dataset licensing and provenance (D3, section 11).** Community-hosted imagery datasets can carry unclear or incompatible licenses or scraped provenance (section 11.3.1 records that photo copyright is not cleared by the MIT tag). | The demo ships data the team may not redistribute, or the divergence from the brief's language is compounded by a licensing problem. | Section 11 selects only datasets with an explicit license field verified on the dataset card; dataset id, revision hash, and license are recorded in `Provenance` and shown in the UI; images are not redistributed outside the team (section 11.5); the security/data reviewer signs the readiness checklist for F002 before the demo; if the selected dataset fails review, fall back to the section 11.3.2 dataset or another open dataset meeting section 11's criteria — CIFAR-10 stays the CI fixture only. |
| **Dataset reachability at build time.** The Hugging Face hub was reachable from the team network; the University of Toronto CIFAR mirror was not. | `build-assets` fails on a fresh machine. | Load paths in section 11 use the hub with the pinned revision first and torchvision only as a fallback; the fixture slice is committed so CI never downloads. |
| **MRI misuse (D9, brief).** A single number invites comparison across models, domains, and settings, and reads as a readiness grade. | The tool becomes the "universal score" the brief warns against. | Score is per campaign and refuses cross-modality aggregation and incompatible comparisons in code; never rendered without subscores, denominators, and the eps curve; attack-scoped grade readings; the only "gain" is a measured ΔMRI; the divergence is recorded in the reconciliation table (section 4) and constitution amendment proposal (D12). |
| **Divergence from the brief's non-operational language (D3).** | Reviewers read military-vehicle imagery as operational targeting work. | Bounds stated in the UI, reports, decision register, and constitution amendment proposal; open/unclassified data only; no training, optimization, or deployment of targeting models; no mission-system connections. Ratification of the amendment is not claimed. |
| **Pythia availability and latency during the demo.** | Recommendation pane stalls or errors. | Narrative is optional and degrades to rule text with `narrative_source="rules"`; 60 s timeout; the demo script covers both states. No provider fallback is permitted (D5). |
| **LLM narrative introducing claims.** | Prose contradicts or embellishes the measurements. | Text-only input of metrics + SHAP summary; guardrails on input and output; the numeric-consistency and banned-word post-checks (section 16.3) and their tests in section 22; UI label "LLM-generated narrative of rule outputs". |
| **Sandbox limits (section 21).** The plugin sandbox has no network or filesystem namespace. | A malicious file that also passed the format checks could reach the network or worker files. | Format allowlist is the primary control; minimal child environment with no secrets; least-privilege worker role; gVisor RuntimeClass on Kubernetes; egress security groups on Fargate; kernel isolation remains a tracked follow-up. |
| **Tabular attack semantics and the realizability gap (D4d).** PGD on tabular features ignores the coupling between lexical features and their ranges; a perturbed feature vector may map to no constructible URL; surrogate transfer measures transfer, not direct white-box exposure; HopSkipJump query counts grow quickly. | Adversarial feature vectors read as demonstrated URL evasion when they are only decision-surface evidence; long runs; over-reading of the PGD rows. | Clip to per-feature min/max from the dataset and round integer features; attack only declared continuous features; every tabular row carries the realizability caveat and the standing limitation (section 12.9) and the UI shows it (section 18.4); label PGD rows "white-box via surrogate transfer" with the surrogate agreement rate; cap HopSkipJump iterations and record `queries(a)`; constructing realizable URLs from perturbed features is out of scope for Phase A and is stated as such. |
| **Malicious-URLs dataset (D4d, section 11.3.3).** Labels merged from several feeds without a documented adjudication step (label noise); compiled in 2021 (age); benign ≈ 2/3 (class imbalance); download needs a personal Kaggle token that CI and fresh machines do not have. | Noisy or stale labels inflate or mask the measured ASR; minority-class `n` is small; `build-assets` fails without a token, or a token gets pasted into CI or a container environment. | Per-class `n` on every table and the stratified slice (11.5); label noise, age and imbalance are recorded campaign limitations (11.3.3 caveats); CI uses the committed stratified sample and never touches Kaggle; the token is supplied only to the one-off `build-assets` run and is never set on a service (section 20.3); UNSW-NB15 (11.3.4) is the recorded fallback if the download cannot be completed on the day. |
| **Eps sweep multiplies cost.** Three eps × two attacks × n samples × explain. | Runs exceed the reaper's `job_max_runtime_seconds` (3600 default) or the sandbox wall clock. | Default slice size chosen so an image campaign completes on a laptop CPU; one job per attack with per-stage progress; `AEGIS_ML_SANDBOX_TIMEOUT_S` below the Celery soft limit; raise the ceilings for the worker if measured runtimes require it. |
| **Platform restore in flight.** The restored aegis code is being made import-clean concurrently; `deploy/Dockerfile.worker` still copies the deleted `project_repos/`. | M0 cannot start until the suite is green. | The ML tier is not merged while the default tier is red (section 22.5); the Dockerfile change is an M0 task. |
| **Keycloak in the demo.** Realm import or browser auth misbehaves on demo hardware. | Sign-in blocks the demo. | Dev-token mode is permitted (D11/D002) on a listener restricted to the team; rehearse both paths. |
| **Independent review (constitution, D007 open).** No named independent reviewer exists. | Findings and approvals are self-confirmed. | D007 stays open in the register without invented owners; the readiness checklist approval record is left unchecked until a named reviewer signs; the service-layer dismissal check enforces the "not the author" rule (section 7.7) regardless. |
| **Role-check denials are not chained (section 7.8).** | An F008 reviewer expects every denied action on the chain. | Denials are logged to `application_logs` with `request_id`; chaining them is a Phase B change to `policy.check`. Recorded here so it is not mistaken for an oversight. |
| **Retention and export policy (D006 open).** | Deletion or export of stored evidence without an approved policy. | No purge operation ships in Phase A; exports carry the standing redaction; D006 remains open. |
| **Lattice SDK access (B2, section 27.3).** The Lattice integration is gated on SDK access the team does not have, and it conflicts with the D3 bound "no mission-system connections". | Time spent on an integration that cannot be enabled, or an attestation posted to an operating picture in breach of D3. | Marked exploratory and text-only; requires SDK access, an explicit product-owner decision and a constitution amendment proposal before any code; never on by default. |
| **Foundry API access (B2, section 27.3).** No Foundry instance, token or ontology object type is available to the team, and the REST surface differs between Foundry deployments. | The primary integration is built against assumptions and fails on first contact, or a connection token is pasted into a service environment. | Env-selected and off by default; connection settings read only by the `default` worker pool; the push is a plain REST call audited on the run chain; the section 23 exit check requires a real push against a configured instance, not a mocked one. |
| **Export size (B2, section 27.1).** A full adversarial slice is `n_samples` × grid size × attack count tensors; at 128×128×3 float32 with the default grid and two attacks that is hundreds of megabytes per campaign. | Slow exports, bucket cost, consumers who cannot download. | Clean inputs as `uint8`, adversarial tensors as `float32` (quantising a perturbation of a few grey levels would change the measured result); one Parquet file per (attack, ε) so consumers pick shards; content-addressed shards so an unchanged shard is never rewritten; slices above `AEGIS_ML_MAX_ADV_ARTIFACT_MB` (section 12.8) are regenerated at export time rather than stored twice; the manifest records every file's size. |
| **ATLAS mapping drift (B2, section 27.2).** Technique ids and names change between ATLAS releases, and a single-technique tag can misdescribe an attack. | Stored findings carry stale or wrong tags; two teams read different techniques for the same attack. | The mapping lives in the attack registry with the ATLAS version it was checked against; findings store id and name as written at creation; a mapping change is a registry change with a test and never a rewrite of stored findings; the coverage view labels itself a description of the declared attack set, not a score. |

## 26. Completion criteria

One merged list. Each criterion is observable; the source it comes from is tagged: **[S2]** the lean design's completion criteria, **[Brief]** the project brief's completion criteria and reporting principles, **[S3]** William's readiness checklist and feature success criteria, **[Const.]** the constitution, **[Dn]** a decision of 2026-09-08. Phase A is complete when every item holds on the deployed stack; anything that does not hold is listed in the README as not implemented.

### 26.1 Workflow and reproducibility

1. A teammate can follow `README.md` from clone to a finished bundled-image-model FGSM + PGD campaign visible in the browser, on a laptop CPU with Docker, in one sitting; the measured clone-to-first-run time is recorded in the README at M7 (S2's 15-minute target applied to the lean stack; the full aegis stack targets 30 minutes including image builds). [S2, Brief]
2. `report.json` and the run record contain everything needed to rerun: campaign configuration (attack set, eps grid, reference budget, finding threshold, sample size, seed, control on/off, `explain_k`), dataset id + revision hash + split + indices, model sha256 and manifest, library versions, device, hostname, and the list of nondeterminism sources. [S2, Brief, Const. V]
3. A rerun with the same configuration is linked to the original run (`parent_run_id`); a retry or rerun never mutates a terminal run (section 6). [S3 F004 SC-002]
4. Every stage of a run is visible in the stage timeline, and an interrupted or failed run is distinguishable from a completed evaluation; partial measurements are shown with explicit completeness and never as a complete evaluation. [S3, Const. IV]

### 26.2 Evidence integrity

5. Every measurement, observation, and recommendation shown in the UI links to a stored `Artifact` or record reachable through the API (no orphaned numbers). [S2, Brief]
6. Measurements, observations, interpretation, and candidate recommendations are separate fields in the record and separate panels in the UI; the labels `candidate` / `not evaluated` (or `measured`), `inferred`, and `heuristic` are enforced by `Literal` types and asserted by tests. [S2, Brief, Const. III]
7. Results are presented by test family (clean, evasion per attack and eps, control) with denominators (`k / n`) and per-class counts; the benign random-noise control runs at the same eps as each evasion measurement. [S2, Brief]
8. SHAP output is presented as supporting evidence with the "not causal proof" limitation; the center-mass metric is labelled heuristic wherever it appears. [S2, Brief, Const. III]
9. Limitations are non-empty on every succeeded run, visible on every run page, and included in every report; they always include the standing limitations of `aegis/ml/schema.py`, the dataset caveats of section 11, and the D3 bounds statement. [S2]
10. No fixture data is ever served as a result: the CIFAR-10 fixture slice and `TinyTarget` exist only in tests, and a test asserts the API has no code path to fixture files. [S3, Const. VI]
11. Illustrative numbers (demo script, documentation) are labelled illustrative; no document or screen claims a completed run, measured improvement, or validated fix that did not happen. [Brief, Const. III]

### 26.3 Scoring (D9)

12. The MRI is computed per campaign (one model × one modality × declared attack set × declared eps grid × reference budget) and the code refuses to aggregate across modalities or to compare campaigns with different `settings_hash`. [D9 i]
13. The MRI is never rendered or exported without its five subscores, the per-family accuracy table with denominators, and the eps curve. [D9 ii, Brief]
14. Grade-band readings are attack-scoped and no reading or label contains readiness, fielding, deployment, or certification language; every scorecard states that no grade is a readiness or certification statement. [D9 iii, Brief, Const. III]
15. A recommendation carries no numeric expected gain; ΔMRI appears only after the verify loop measures it on the same model at the same settings, as a `MeasuredDelta` on that recommendation. [D9 iv, Brief]
16. Finding severity is derived from the budget at first success and ASR per section 15.5 and cannot be set by hand. [S1 §8.5]

### 26.4 Boundaries and security

17. Uploaded models are validated and loaded only on the worker inside the sandboxed subprocess; the API process never imports an ML library (test-enforced); pickled models are refused by default with an explicit error and an audit event; `state_dict` uploads require a registered architecture; a target is launchable only when `available`. [D2, Const. IV, Brief]
18. Data handling and execution boundaries for uploads received the security/data reviewer's sign-off on the F002 and F004 readiness checklists before the upload path was enabled; if no named reviewer exists, the upload dialog stays disabled and says why. [Brief, S3]
19. Only open, unclassified, public datasets with a recorded license are present; dataset id, revision, and license are shown on the model page and in reports; the D3 bounds are displayed. [D3, Const. II as amended-proposal]
20. Every LLM call goes through Pythia, with only metrics, rule outputs, limitations and a SHAP text summary as input, under aegis routing and budgets; no provider key exists anywhere in the repository, images, or deployment. [D5]
21. Cross-organization isolation holds for every new table and blob prefix (RLS test on Postgres); server-side RBAC gates every mutating route; finding dismissal cannot be performed by the campaign's author. [S3 F001/F006 SC-001, Const. IV]

### 26.5 Audit and governance

22. Registration (and refused upload), validation, attack, explain, score, harden, verify, dismissal and report events are on the hash chain, with every admission event written before the corresponding job is enqueued; `aegis audit verify --all` passes on a completed campaign; event detail contains no secrets, raw payloads, or model bytes. [D4c, S3 F008 SC-001, Const. VII]
23. WORM export runs on the beat schedule when enabled and the exported chain re-verifies. [S1 §12]
24. Unsupported paths (endpoint connector, Phase B attacks and modalities, review states beyond dismissal) are visible as not implemented with a reason and return the not-implemented error; nothing is silently bypassed or faked. [S2, Brief, Const. IV]

### 26.6 Process gates (S3)

25. Each feature F001–F008 has a readiness checklist copied into its `checklists/` directory with the Specify, Clarify, Plan, and Tasks sections reviewed; boxes are checked only by the named reviewers, not by document generation. [S3]
26. The approval record for each feature names the product owner, an engineering reviewer, and (where relevant) a security or data reviewer with dates; remaining non-blocking limitations are listed; the decision is Draft / Changes requested / Approved for implementation. D006 and D007 remain open in the register and are not assigned invented owners. [S3, D11]
27. "Done" is recorded separately from approval: passing checks (the unit, integration, ml, and web CI jobs), actual acceptance evidence stored next to the feature, accessibility and error-state checks for the new pages, and a reviewed behavior-to-spec comparison. Specification approval alone does not complete a feature. [S3, Const. VI]
28. The decision register carries RESOLVED rows D001–D005 in its own format with approver "product owner (hackathon), 2026-09-08"; the constitution carries the "Amendment proposals (2026-09-08)" section with status "proposed, pending named approval"; ratification is not claimed anywhere. [D11, D12]
29. `docs/project-brief.md` is the single brief (D13); every reference to `docs/brief.md` under `docs/`, `specs/`, and `.specify/` is updated, and references remaining in code or `README.md` are reported. [D13]

## 27. Interoperability (Phase B2)

Source: S1 §14, which John Sasser added on 2026-09-08 (commit `4acdb85`) after the first consolidation pass had read S1. S2 and S3 have no counterpart, and section 4 row 57 records the adoption. The hackathon scores the tool on interoperability: it should contribute datasets that other teams consume and consume datasets that other teams contribute. This section carries S1 §14.1 to §14.3 into the consolidated vocabulary (`Run`, `Finding`, `Artifact`, `MRIRecord`) as one Phase B2 milestone (section 23), behind every Phase A item and behind B1+ (section 3.4).

Four rules bind the whole section:

1. **Opt-in, off by default.** Every capability here is selected by environment configuration and is absent until an operator turns it on. Nothing exports, tags for export, or pushes on its own, and no campaign changes behaviour because an integration exists.
2. **Data and REST integrations, not LLM calls.** Nothing in this section sends anything to Pythia or to any model provider, so D5 is untouched. The Foundry and Lattice connections are HTTPS calls to their REST APIs made from the worker's `default` pool, the pool that makes the Pythia call today (section 10.8), so neither the API process nor the sandbox child gains egress.
3. **No standing credentials.** Each integration holds exactly the connection it is configured with (a base URL plus a token or IAM role scoped to the target dataset or entity), read from the worker environment or the section 20.4 secret store, never written to `Job.detail`, artifacts, audit rows or exports (section 21.8).
4. **Nothing here is implemented.** As of this spec every route below returns `501 not_implemented` (section 17.4), every control is disabled with its reason (section 18.5), and no manifest, tag, coverage view or push status is ever fabricated.

### 27.1 Contribute an adversarial dataset

Every campaign (a `Run` with `scanner = ml.campaign` or `ml.verify`) generates perturbed inputs with their true and predicted labels. B2 publishes them, on request, as a versioned **adversarial dataset** that other teams consume: a defense team adversarially trains on it, a model team adds it to a regression suite.

| Aspect | Specification |
|---|---|
| Format | **Croissant** (the MLCommons JSON-LD dataset-metadata standard) manifest over a **Parquet** payload. A Hugging Face `datasets` bundle is the same payload with a generated dataset card; the card text is rendered from the manifest and the run's limitations by a template and is never written by the LLM writer. |
| Contents | Per sample: the clean input and the adversarial input as tensors (images with shape, dtype and value range declared; tabular campaigns export **feature vectors** only and never the source URL string, section 11.3.3 caveat 1), the true label, the clean prediction and the adversarial prediction with confidences, the attack id, the norm and the ε at which the sample was generated, the `flipped` flag, and the source-slice index (`Sample.indices`, section 11.5) with the dataset id, revision and split so a consumer can reproduce the slice. Control-noise samples are exported as their own family so a consumer has the same benign baseline the campaign had (section 12.4). |
| Manifest | Content-addressed: `croissant.json` lists every Parquet file with its sha256 and byte size, and the manifest's own sha256 is the dataset version. It carries model provenance (`model_sha256`, `manifest_sha256`, `settings_hash`), the `Provenance` block of section 14.4 (library versions, seed, nondeterminism sources), the campaign configuration (attack set with resolved parameters, ε grid, reference ε, `n_samples`), the source dataset's id, revision, license string and the section 11.5 coverage caveat, the run's `limitations` verbatim, and the ATLAS technique per attack (27.2). It never carries model weights, model files, dataset bytes beyond the exported slice, Pythia settings, credentials, user identifiers or reviewer notes. |
| Derivation | A worker job (`dataset.export`, `scans` queue, 27.4) reads the run's `ml.adv_slice` artifacts and `slice.npz`. When the full slice was not retained (section 12.8) the job regenerates it from configuration and seed inside the sandbox child and the manifest records `regenerated: true` with the nondeterminism sources that apply. The export is a projection of the run record, never a second computation: exported labels and predictions must equal the run's `Observation` rows and `ml.flip_matrix` artifact, and the job fails rather than export on any mismatch. |
| Location | `datasets/<run-id>/croissant.json` and `datasets/<run-id>/data/*.parquet` in the bucket configured for exports (the artifacts bucket of section 20.4 by default; a shared cross-team bucket is an operator setting introduced with B2). Each file is also an `Artifact` row on the run (`ml.dataset.manifest`, `ml.dataset.parquet`, 27.4), so the membership and RLS gates of section 7 govern the API routes while other teams read the S3 prefix with their own bucket permissions and verify integrity from the manifest. |
| Versioning | One export per run. Re-exporting the same run yields byte-identical Parquet and the same manifest sha256. A verify run (`ml.verify`) exports its own dataset with `baseline_run_id` in the manifest and is never merged with the baseline's export. |
| License and redaction | The export inherits the source dataset's license and the section 11.5 policy. An export from a campaign on the vehicle-imagery dataset (11.3.1) or the aircraft fallback (11.3.2) contains photographs whose copyright the dataset tag does not clear, so it is written to a shared bucket only after the reviewer confirms redistribution under the export-redaction policy, which is decision D006 and remains OPEN: until D006 is resolved, imagery exports stay inside the team's artifacts bucket. Feature-vector exports from the CC0 malicious-URLs dataset (11.3.3) carry no such restriction. CIFAR-10 fixture runs and `TinyTarget` runs are never exported (section 11.1). |
| Consume side | The exchange runs both directions. **Models:** another team's model arrives as **ONNX** through the existing upload path, under the section 9 rules without change (sandboxed worker-side loading, pickles refused). **Evaluation slices:** another team's slice arrives as a Croissant manifest plus Parquet, or as Parquet alone with the license, class names and feature or image schema declared in the request, through the dataset registration route of section 17.4, which section 11.1 excluded for Phase A. The same open, unclassified, licensed rule applies: a slice with no license statement is refused. Consumed files are untrusted input: the API stores bytes, checks the Parquet magic (`PAR1`) and the manifest's JSON shape, and computes sha256; parsing happens on the worker with `pyarrow` (already in the `ml` extra) inside the sandbox child; Croissant `distribution` entries must reference files inside the registered upload, and any remote `contentUrl` is refused. A registered slice gets a dataset id and a revision (its manifest sha256), is bound to a model through the compatibility check of section 5.5, and a campaign on it is its own campaign under D9(i), never compared with a campaign on a bundled dataset. |
| Endpoints | `POST /v1/runs/{id}/dataset` builds and registers the dataset; `GET /v1/datasets/{id}` returns the Croissant manifest; `POST /v1/datasets` registers a consumed slice (section 17.4). |

### 27.2 MITRE ATLAS mapping

Every `Finding` is tagged with the **MITRE ATLAS** technique it demonstrates (ATLAS is the adversarial-ML companion to ATT&CK), so every team shares one vocabulary for the vulnerability.

| Attack family (section 12.2) | Attack ids | ATLAS technique (`atlas_technique`) |
|---|---|---|
| White-box evasion: gradient-crafted adversarial examples | `fgsm`, `pgd` (Phase A); `cw_l2`, `deepfool` (B1) | `AML.T0043 Craft Adversarial Data` |
| Black-box query attacks against the model's prediction interface | `hopskipjump` (Phase A tabular, B1 image); `zoo` (B1) | `AML.T0040 ML Model Inference API Access` |
| Benign noise control | `noise_control` | none: the control never creates a Finding (section 12.4) |

- **Where the tag lives.** The mapping is a property of the attack adapter, declared in the registry beside `AttackInfo.references` together with the ATLAS version it was checked against (27.4), and stamped onto the Finding at creation as `schema_blob.ml.atlas_technique` (`MLFindingDetail`, section 5.7). S1 §14.2's path `Finding.schema_blob.atlas_technique` resolves to that field, because the consolidated spec keeps all ML detail inside the `ml` block. It is `None` on every Finding written before B2 lands and is never back-filled by guesswork.
- **Where it is shown.** The findings table (`/findings` and panel 11 of `/runs/[id]`, section 18), the finding page header, the report's findings and candidate section (section 14.8), and the adversarial-dataset manifest (27.1).
- **Coverage view.** A per-campaign **ATLAS coverage** block on `/runs/[id]` (section 18.3) lists the techniques exercised by the in-scope attacks that ran, the techniques of declared attacks recorded as `not_run` (section 9.5), and the catalog techniques outside the declared set. It is a description of the declared attack set, not a score: it enters no subscore, has no colour grading, is never aggregated across campaigns (the analogue of D9(i)), and says nothing about techniques that were not run.
- **Community contribution.** S1 §14.2 notes that a program can contribute a sanitized case study back to the ATLAS community database. That is a human action outside the tool: the tool sends nothing to MITRE. "Sanitized" means the technique id, the attack settings, the per-family metrics with denominators and the limitations, with no images, model bytes, dataset rows or identifiers, subject to section 11.5 and to D006 while that decision is open.
- **Drift.** ATLAS technique ids and names change between releases. The registry records the ATLAS version, the Finding stores the id and name as written at creation, and a mapping change is a registry change with a test, never an in-place rewrite of stored findings (section 25).

### 27.3 Platform integrations

S1 §14.3 names two integrations that push results into platforms other DoD teams already operate. Both are env-selected, off by default, hold no standing credential beyond the connection each is configured with, and run as a worker job (`integration.push`, `default` pool, 27.4) whose admission and completion are chained audit events. Neither is an LLM call.

| Integration | Status in S1 | What is pushed | What is read | D9 and D3 bindings |
|---|---|---|---|---|
| **Palantir Foundry** | primary | The campaign's robustness scorecard and, when exported (27.1), the adversarial dataset, written as Foundry datasets through the Foundry REST API and keyed to the model's ontology object, so a Foundry team sees the Model Robustness Index beside the model it governs. | A model registered in Foundry, accepted only as ONNX and loaded only through the section 9 path; an evaluation dataset registered in Foundry, accepted only as Parquet or Croissant under 27.1's consume rules. | The scorecard dataset always contains the five subscores with their denominators, the per-family accuracy table with `n`, the ε grid points with `acc_adv` per point, `settings_hash`, the grade sentence of section 15.5 and the run's limitations, as rows of the same dataset as the MRI; the integration never writes a bare MRI column or a grade without the sentence (D9(ii), D9(iii)). Foundry is a data platform, not a mission system, but the operator confirms at configuration time that the target instance is an enterprise or non-operational one, consistent with the D3 bounds (section 21.8). |
| **Anduril Lattice** | exploratory | A **robustness attestation** as an attribute on the Lattice entity that runs a fielded edge model, so the operating picture shows that the asset's model was red-teamed, with its current MRI and grade. Lattice models entities and tasking rather than datasets, so this is a narrative integration gated on SDK access. | nothing | The attribute payload the tool would emit always carries, beside the number and grade, the five subscores with denominators, the ε grid points, `settings_hash`, `computed_at`, the grade sentence and a link to the full scorecard; how Lattice renders an attribute is outside the tool's control, which is one reason the integration stays exploratory (D9(ii), D9(iii)). **Conflict to resolve first:** the D3 bounds and constitution Principle II state "no mission-system connections", and Lattice is an operating-picture platform. Under the decisions of 2026-09-08 this integration cannot be enabled. It is recorded here as S1's proposal and needs an explicit product-owner decision and a constitution amendment proposal before any code is written; until then it is text only. |

### 27.4 Additions to the platform vocabulary when B2 lands

None of these exists today; each is the B2 extension of the section it names and is added in the same additive style as the Phase A vocabulary.

| Section | Addition |
|---|---|
| 5.7 `MLFindingDetail` | `atlas_technique` (27.2) |
| 5.8 `Artifact.kind` | `ml.dataset.manifest` (`application/ld+json`, the Croissant manifest), `ml.dataset.parquet` (`application/vnd.apache.parquet`, one row per file), `ml.dataset.card` (`text/markdown`, the generated dataset card) |
| 5.9 `Job.type` | `dataset.export` (`DatasetExportJobDetail`: `run_id`, `bucket`, `prefix`, `include_card`), `dataset.register` (`DatasetRegisterJobDetail`: `dataset_id`, `blob_location`, `declared_format`, `declared_sha256`), `integration.push` (`IntegrationPushJobDetail`: `run_id`, `integration` (`foundry`), `target_ref`). No detail carries a credential. |
| 5.11 `AuditEvent.action` | `dataset.export` (admission, run chain), `dataset.export.execute` (worker: manifest sha256, file count, byte total, bucket and prefix), `dataset.register` (admission, project chain: dataset id, sha256, declared license; `success=False` with `reason` on refusal), `integration.push` (admission, run chain: integration name, target reference), `integration.push.execute` (worker: host, object or entity id, content hashes, outcome; never a token) |
| 7.4 `Action` | `DATASET_EXPORT` (`remediator`), `DATASET_REGISTER` (`remediator`, parity with `MODEL_REGISTER`), `INTEGRATION_PUSH` (`admin`, because it sends data outside the deployment boundary) |
| 12.1 `AttackInfo` | `atlas_technique: {"id", "name", "atlas_version"} \| None` on each registry entry, the source of the Finding tag |
| 17.4 routes | `POST /v1/runs/{id}/dataset`, `GET /v1/datasets/{id}`, `POST /v1/datasets` |
| 18 UI | ATLAS technique column, ATLAS coverage block, "Export adversarial dataset" action, Integrations line on the campaign page |
| 20.3 environment | Export bucket override; Foundry connection (base URL, token or role, ontology object type); each read only by the `default` worker pool and absent by default. No Lattice setting is defined until the 27.3 conflict is decided. |
| 22 tests | Manifest validates as Croissant and every listed sha256 matches the written file; exported rows equal the run record's observations and flip matrix; a manifest with a remote `contentUrl` is refused; the registered slice is parsed only in the sandbox child; the ATLAS tag on a `fgsm` / `pgd` finding is `AML.T0043` and on a `hopskipjump` finding `AML.T0040`; the Foundry push payload contains subscores, denominators and the grade sentence, and no export or push payload contains a key, a model file or a URL string. |

### 27.5 What B2 does not change

- **D5.** No LLM is involved anywhere in this section. Pythia remains the only LLM transport and receives nothing from exports or pushes.
- **D9.** Every scorecard that leaves the platform carries its subscores, denominators, ε grid and grade sentence; no export, push or manifest carries a bare MRI or an expected gain; ΔMRI travels only as the measured `delta` block of a verify run's score record.
- **D3 and section 11.1.** Consumed slices obey the open, unclassified, licensed rule; the Lattice integration is blocked by the "no mission-system connections" bound until a decision says otherwise.
- **Section 14.7.** Illustrative content stays labelled, fixture runs are never exported, and nothing in this section is presented as implemented before it lands.
