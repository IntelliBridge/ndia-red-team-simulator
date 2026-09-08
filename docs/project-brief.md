# AI Assurance — Project Brief

## Status and purpose

This is the team's kickoff brief, not an implemented product or an approved final specification. It consolidates the supplied use case and the subsequent reference analysis so collaborators can make informed scope decisions. On 2026-09-08 the two copies of the brief that existed in this repository (`docs/project-brief.md` and `docs/brief.md`) were folded into this file; the original use-case text, the additional references, and the decisions taken that day now live here.

The brief's reporting principles are design constraints for the product. The product itself is specified in [Adversarial ML Red-Team Simulator — Product Spec](superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md); where the product spec knowingly diverges from this brief, the divergence is recorded in the "Decisions taken (2026-09-08)" section below and in the amendment proposals appended to the [constitution](../.specify/memory/constitution.md).

## Original context

The supplied document describes a military AI red-teaming concept: users select or connect a model, run adversarial evaluation, inspect visual explanations, and review mitigation recommendations.

Its requested interface places explanation outputs and recommendations side by side. It references the Adversarial Robustness Toolbox (ART) and SHAP, and discusses both evasion and data poisoning.

This source context is preserved for traceability; it is not authorization to build or optimize combat targeting, weapons, or operational military decision systems. Those applications are outside this project's scope.

The original document alternates between "DoD" and "DoW." The intended terminology remains unconfirmed.

Source: [original supplied document, unchanged](references/original-use-case.docx).

### Original use-case text

The DoD is rapidly deploying AI and Machine Learning models to the tactical edge for target recognition, threat detection, and decision support. However, these models are highly vulnerable to adversarial attacks, such as data poisoning or evasion techniques.

This concept is an automated "Red Team" simulator designed to stress-test military AI models before they hit the battlefield. Users can upload a model (or connect via API), and this will automatically generate adversarial examples designed to trick the system. Beyond just breaking the model, the tool uses explainability frameworks (like SHAP) to show exactly why the model failed (e.g., "The model was over-reliant on the background pixels rather than the target"). It then outputs natural language recommendations for hardening the AI.

*Requirements.* Build an automated red-teaming tool that evaluates the robustness of DoW AI models by generating adversarial attacks, utilizing explainable AI to map vulnerabilities, and recommending defensive countermeasures.

*Expected deliverables.* A web UI where a user can select a model, trigger an adversarial attack, and view the SHAP visual outputs and mitigation recommendations side-by-side.

*Resources.* ART https://github.com/Trusted-AI/adversarial-robustness-toolbox · SHAP https://shap.readthedocs.io/en/latest/ · garak https://github.com/NVIDIA/garak

## Reference map

| Reference | Role in the analysis | Limitations to retain |
| --- | --- | --- |
| [ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox) | A library for evaluating conventional ML against multiple adversarial threat categories. | Framework coverage does not guarantee compatibility with every uploaded model or evaluation pipeline. |
| [SHAP](https://shap.readthedocs.io/en/latest/) | Feature attribution and local explanations, including image and text applications. | Attribution is not proof of causality or a definitive explanation of why a failure occurred. |
| [NVIDIA garak](https://github.com/NVIDIA/garak) | Modular LLM vulnerability scanning, detectors, and structured reports. | Not a replacement for conventional ML evaluation or complete agent/application testing. |
| [The TIP of the Iceberg — ACL 2025](https://aclanthology.org/2025.acl-long.334/) | Research on Task-in-Prompt failures and the PHRYGE benchmark, informing possible LLM coverage. | The study covers six LLMs and text; automated evaluation has limitations. It does not validate countermeasures. Compatibility with garak has not been established. |
| [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) | Candidate execution-isolation and lifecycle infrastructure. | Not an evaluation engine or a model defense. Effective isolation depends on the runtime and configuration. Not selected (D004); the redsim plugin sandbox is used instead. |

The references describe complementary layers, not interchangeable tools or a pre-integrated stack.

## Additional references

- [IntelliBridge/pythia](https://github.com/IntelliBridge/pythia) — IntelliBridge's OpenAI-compatible agent gateway. Every LLM call the product makes goes through it (`POST {PYTHIA_BASE_URL}/v1/chat/completions`, `Authorization: Bearer pk_…`, optional `X-Pythia-Persona`, canonical model ids `<vendor>/<model>` or `pythia/auto`), so the product holds no provider credential and Pythia's guardrails, metering, and audit apply.
- [IntelliBridge/ndia-red-team-simulator](https://github.com/IntelliBridge/ndia-red-team-simulator) — this repository, a fork of IntelliBridge's aegis security platform. The redsim platform (FastAPI, Celery, Postgres, Redis, S3/MinIO, Keycloak/NextAuth, RBAC, Postgres RLS, hash-chained audit log, per-task LLM routing and budgets, observability) is reused whole; the ML red-team vertical is added under `redsim/ml/`.
- [GitHub Spec Kit](https://github.com/github/spec-kit) — the method the feature specifications under `specs/` follow. Its CLI is not installed.
- garak, the ACL 2025 TIP paper, and OpenSandbox: see the reference map above.

## Proposed first milestone

Demonstrate a single, benign evaluation workflow with traceable evidence and human review:

1. Identify an approved public or synthetic evaluation target and dataset.
2. Record the evaluation purpose, assumptions, and test coverage.
3. Perform a bounded, non-operational assessment.
4. Display observed results and supporting evidence.
5. Separate observations, interpretation, and candidate recommendations.
6. Save a report that states limitations and supports a follow-up comparison.

Choose **one evaluation domain first**:

- Conventional ML: prediction behavior and input sensitivity.
- LLM assistant: observable behavior against defined safety and quality requirements.
- Agent application: behavior involving tools, files, and permission boundaries; a separate scope requiring additional review.

The earlier image-classification-first recommendation was an assumption, not an approved choice, at the time this section was written. The decision taken on 2026-09-08 (D001, below) selects conventional ML — image and tabular classification — and defers the LLM domain to Phase B. The additional LLM references do not establish approval to implement all domains at once.

## Reporting principles

- Match the evidence to the evaluated system; do not require SHAP for every modality.
- Distinguish observed behavior from inferred causes.
- Record model and dataset versions, test configuration, evaluator configuration, and run limitations.
- Present results by test family with clear denominators and coverage. Avoid a universal score that mixes unrelated domains.
- Include benign controls and human review of flagged examples.
- Label any illustrative results as illustrative. Do not invent completed runs, measured improvements, or validated fixes.
- Treat recommendations as candidates until supported by a separate evaluation.
- State that passing a test suite does not establish complete safety or operational readiness.

These principles are binding on the product spec. The one knowing divergence — a per-campaign Model Robustness Index — is bounded so that it never mixes domains and always travels with its subscores, denominators, and ε curve (D005 below).

## Open decisions

The register of record is [specs/_shared/decisions.md](../specs/_shared/decisions.md). Positions as of 2026-09-08:

| Decision | Position on 2026-09-08 | Register |
| --- | --- | --- |
| First domain and benign use case | Resolved: image classification on open, unclassified, publicly licensed aerial / military-vehicle imagery, plus a tabular classifier; CIFAR-10 is the CI fixture dataset | D001 |
| Model access method | Resolved: bundled models plus bounded white-box upload (ONNX preferred, `state_dict` with explicit architecture, pickles refused by default, sandboxed worker-side loading); API endpoints Phase B | D003 |
| Dataset and handling rules | Resolved for the demo data: open, unclassified, clearly licensed public datasets only; retention and export redaction still open | D001, D006 |
| Evaluation criteria | Resolved: per-family metrics with denominators, benign noise control, ε sweep, SHAP per modality, per-campaign MRI with binding constraints, derived severity | D005 |
| Evidence presentation | Resolved: measurements, observations, interpretation, and candidate recommendations as separate fields and separate UI panels; SHAP for image and tabular | D005 |
| Execution environment | Resolved: Celery worker plus the redsim plugin sandbox; OpenSandbox not used | D004 |
| Managed identity | Resolved: redsim Keycloak OIDC + NextAuth; dev-token mode allowed for the demo | D002 |
| Retention, export redaction, licence restrictions | Open | D006 |
| Team roles and ownership | Open; unassigned | D007 |
| Licence and redistribution of a Phase B LLM-track corpus | Resolved (moot): the corpus was withdrawn on 2026-09-08 and the Phase B LLM track uses garak's bundled probe corpora | D008 |

No provider authorization, deployment, spending commitment, or collaborator invitation is implied by this brief.

## Decisions taken (2026-09-08)

Recorded here so the open decisions above have a traceable answer. The product owner made these decisions; they are final for the hackathon and override every source where they conflict. Divergences from this brief and from the constitution are stated explicitly. The earlier lean-era decisions (CIFAR-10 as the demo dataset, bundled-only ingest, in-process execution without a sandbox, no authentication) are superseded and retained only as history in `docs/superpowers/specs/2026-09-08-redsim-design.md`.

1. **Stack.** Reuse the full aegis platform now: FastAPI, Celery, Postgres, Redis, S3/MinIO, Keycloak/NextAuth authentication, RBAC, Postgres RLS, the hash-chained audit log, per-task LLM routing and budgets, observability. The lean, database-less design is retired.
2. **Model ingest (Phase A).** Bundled sample models and white-box artifact upload. ONNX preferred; PyTorch `state_dict` with an explicit architecture accepted; full pickles refused by default. Uploaded models are loaded only on the worker inside redsim's plugin sandbox (separate process, no network, rlimits), never in the API process. The black-box endpoint connector is Phase B. *Divergence from this brief:* "Unrestricted execution of uploaded model artifacts" stays excluded; bounded, sandboxed loading of declared formats is included.
3. **Demo data.** Aerial-target / military-vehicle imagery from open, unclassified, public datasets with a clear licence only. *Divergence from this brief and the constitution's non-operational language,* recorded as a team decision with bounds: open/unclassified data only; the tool evaluates and hardens the robustness of a classifier and never trains, optimizes, or deploys targeting or weapons models; no mission-system connections. CIFAR-10 is the image CI and fixture dataset, not the demo dataset. The tabular classifier's dataset is the Kaggle malicious-URLs dataset (https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset, CC0 per Kaggle; file `malicious_phish.csv`, columns `url` and `type`, 651,191 rows; classes benign / defacement / phishing / malware). Handling rule: URL strings are data — the pipeline never fetches, resolves, or renders any URL from the dataset; only lexical features are computed. The full download requires a Kaggle API token (`KAGGLE_USERNAME` / `KAGGLE_KEY`) read by the asset script; CI uses a small committed stratified sample (a few hundred rows) so tests never touch Kaggle. Feature-space perturbations of this classifier are evidence about its decision surface and count as a realizable attack only if the perturbed feature vector maps back to a constructible URL.
4. **Phase A also includes:** the verify-after-harden loop (apply an ART preprocessing defense such as feature squeezing or spatial smoothing, re-attack, report the measured delta); an ε sweep with a robustness curve (for example L∞ ε ∈ {0.01, 0.03, 0.1}); hash-chained audit events for every upload, attack, explain, harden, and verify (Postgres-backed chain, JSONL offline); and a live tabular classifier (bundled sklearn / XGBoost, PGD + HopSkipJump, TreeExplainer SHAP bar and beeswarm).
5. **LLM access.** Every LLM call goes through Pythia. redsim's per-task routing and budget caps remain the policy layer; Pythia is the only transport (no litellm, no direct provider keys). Environment: `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `PYTHIA_PERSONA`, `REDSIM_ML_LLM_MODEL`. The LLM writer receives only metrics and a SHAP text summary — never images or model data — in one plain, non-streaming chat completion with no tools, vision, or structured output.
6. **garak / LLM-domain red-teaming** is Phase B only; if added, garak's OpenAI-compatible generator points at Pythia.
7. **Naming.** Product: "Adversarial ML Red-Team Simulator". Python namespace `aegis`, new vertical in `aegis/ml/`. Web app `@aegis/web`. The lean-era name "redsim" is retired except as history. *Amended later on 2026-09-08 by the product owner:* the short name redsim is the product name, and the Python namespace and every identifier are renamed to redsim: package `redsim/`, vertical `redsim/ml/`, console script `redsim`, environment variables `REDSIM_*` (so item 5 reads `REDSIM_ML_LLM_MODEL`), API title "Redsim API", session cookie `redsim_api_session`, compose services, images and Helm chart `redsim-*` and `deploy/helm/redsim`, web packages `@redsim/web` and `@redsim/design-system`. `aegis` remains only as the name of the upstream fork. This supersedes the earlier "Python stays aegis" position (commit `b39d933`, spec section 4 rows D7 amended and 57).
8. **Timeline.** The milestones M0–M7 and B1+ from the hackathon spec are kept, as is its "freeze Phase A first" risk. Phase A as decided exceeds a 1–2 day build. The demo-critical order inside Phase A is: image path end-to-end (bundled model, FGSM/PGD, ε sweep, SHAP, rules + LLM writer) → MRI scorecard → verify-after-harden → tabular → ONNX upload → Fargate.
9. **Scoring.** Adopt the Model Robustness Index (five subscores weighted 0.35 / 0.25 / 0.20 / 0.10 / 0.10, aggregate, grade bands, derived finding severity, ΔMRI on verify) with binding constraints: one MRI per campaign (one model × one modality × declared attack set × declared ε grid × reference budget), never aggregated across modalities or compared across campaigns with different settings; never shown without its subscores, the per-family accuracy table with denominators, and the ε curve; grade readings describe robustness under the in-scope attacks only and no grade is a readiness or certification statement; ΔMRI is the only sanctioned form of "gain" and a recommendation carries no numeric expected gain until a verify measures it; demo-script numbers are illustrative. *Divergence from this brief's "avoid a universal score" principle,* justified as a per-campaign summary that never mixes domains and always travels with its denominators.
10. **Spec Kit layer.** The feature tree under `specs/` stays as the team's process framework and becomes the feature-level layer beneath the product spec. F001 ↔ redsim Keycloak/NextAuth + RBAC + RLS; F002 ↔ `/v1/models`, `Target.kind` `ml_model_artifact` / `ml_model_endpoint`, bundled datasets, upload rules; F003 ↔ the attack-campaign configuration stored with the Run; F004 ↔ redsim Run/Job and the Celery tasks; F005 ↔ the three-pane findings screen and SHAP artifacts; F006 ↔ Finding, derived severity, candidate recommendations, review; F007 ↔ md/json/html reports and ΔMRI comparison; F008 ↔ audit chain, WORM export, data policy. Implementation locations are redsim paths. redsim's Job state machine and Finding `status` / `validation_state` enums are canonical in code; finding reviewer states are Phase B.
11. **Decision register.** D001–D005 resolved as above, approver "product owner (hackathon), 2026-09-08". D006 and D007 remain open with no owners assigned.
12. **Constitution.** Principles are not rewritten. Three amendment proposals — (a) Principle II and vehicle imagery, (b) Principle II and bounded upload, (c) Principle III and the per-campaign score — are appended with status "proposed, pending named approval". Ratification is not claimed.
13. **Brief consolidation.** `docs/brief.md` is folded into this file and deleted; references in `docs/`, `specs/`, and `.specify/` point here.
14. **LLM-track corpora (2026-09-08, later).** The Phase B LLM-assistant domain (item 6: garak probes through Pythia) uses the probe corpora garak ships under `garak/data`: in-the-wild jailbreak prompts, the DAN templates, HarmBench, Do-Not-Answer, RealToxicityPrompts subsets and the payload sets (spec 11.6). garak's probe classes and detectors load these files directly. Nothing is extracted or re-packaged for this tool. The garak package is Apache-2.0 and each subset keeps its upstream terms (HarmBench ships its own LICENSE). Phase B only and probe material only: not a Phase A dataset, not a classifier dataset, never mixed into an MRI. Prompts are untrusted data, sent only to an explicitly entitled Pythia persona with the permission-gate-only guardrail default, never to a production system. The evidence for an LLM assessment is the test context, the observed response, the criterion, the detector result and the reviewer assessment. A third-party jailbreak corpus fetched earlier the same day was withdrawn because its repository declares no licence, so this brief's data-handling rule holds without divergence (D008 closed as moot).
15. **Public dataset repository (2026-09-08, later).** The Phase A datasets were published as the public GitHub repository [IntelliBridge/ai-red-teaming-data](https://github.com/IntelliBridge/ai-red-teaming-data) (commit `ff6a36b`, CC BY 4.0 for the repository's own contents, upstream licences kept per file): `data/military_vehicles.parquet` (9,444 JPEGs as bytes, HF `leibnitz-lab/military_vehicles` at `9f4ab217bda7a1dffbe0ff9c079fb2d0036cdf4a`, MIT), `data/malicious_urls.csv` (651,191 rows, CC0) and `data/malicious_urls_eval_split.csv` (128,224 rows, the seeded 20 percent holdout behind the URL classifier metrics), with `INDEX.csv` (size, sha256, source and licence per file), `MANIFEST.json`, `README.md` and `LICENSE`. No models and no CIFAR-10 are published. The public URL CSVs are redacted copies: credential-shaped query-parameter values (`password`, `token`, `guestaccesstoken`, `sid`, `key`, `access_token`, one AWS-key-shaped string) are replaced with the literal `REDACTED` in 2,346 of 651,191 rows of the full file and 406 of 128,224 rows of the eval split, with row count, order and labels unchanged so row indices still match upstream. The private build trains on the unredacted Kaggle file, so metrics re-derived from the public copy differ slightly on the 0.36 percent of redacted rows (spec 11.7, D001 and D003 addenda).

## Not in the first milestone

- Operational or sensitive datasets and live mission-system connections.
- Combat targeting, weapons integration, or optimization of operational military models. Evaluating and hardening the robustness of a classifier on open, unclassified imagery (D001) is in scope; the exclusion is unchanged.
- Unrestricted execution of uploaded model artifacts. Bounded, sandboxed, worker-side loading of ONNX and `state_dict` artifacts (D003) is in scope; formats that execute code on load are refused by default.
- A training-data poisoning pipeline.
- Simultaneous support for conventional ML, LLMs, and agents. The LLM domain is Phase B.
- Autonomous application of proposed mitigations. The verify-after-harden loop applies a preprocessing defense to a copy of the model for measurement when a user asks; it deploys nothing.
- Claims of certification, causal certainty, or deployment readiness.

## Completion criteria for the proposed proof of concept

- A teammate can understand and follow one documented benign workflow.
- Every reported finding links to observable evidence.
- The report preserves enough configuration to support a meaningful rerun; nondeterminism is disclosed.
- Interpretation and recommendations are distinguishable from measurements.
- Data handling and execution boundaries receive review before accepting uploads or external connections.
- Known limitations and unsupported paths are visible, not silently bypassed.

See the [product spec](superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md) for the approved design, the [feature specifications](../specs/README.md) for the Spec Kit–style breakdown, and the [team backlog](team-backlog.md) for kickoff review steps. The feature packages are drafts; D006 and D007 remain open.
