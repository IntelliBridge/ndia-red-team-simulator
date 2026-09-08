# Clarification and Decision Register

Every row is **OPEN** unless a reviewer explicitly records a decision below. D001–D005 were resolved by the product owner on 2026-09-08; their records follow the register in the "Recording a resolution" format. D006 and D007 remain open. The "Proposed starting point" column is kept as history so divergences are visible.

| ID | Status | Decision needed | Proposed starting point (history) | Blocks | Suggested decision owner |
| --- | --- | --- | --- | --- | --- |
| D001 | RESOLVED 2026-09-08 | First domain and benign use case | Pick either a public/synthetic document-category classifier or a synthetic FAQ assistant; not both | Domain-specific behavior in F002–F007 | Product lead + evaluation researcher |
| D002 | RESOLVED 2026-09-08 | Managed identity provider, initial owner bootstrap, and invitation verification/expiry policy | Reuse a supported managed provider for sign-in and invitations; no custom passwords or locally invented authentication tokens | F001 implementation and all shared-data release | Project owner + engineering lead |
| D003 | RESOLVED 2026-09-08 | Model/dataset access, permitted formats, and catalog approval policy | Versioned metadata plus approved benign fixtures; independent Reviewer/Owner approval per the proposed matrix; defer arbitrary uploads and arbitrary API endpoints | F002 validation/approval, F003 compatibility, F004 execution | Evaluation researcher + security reviewer |
| D004 | RESOLVED 2026-09-08 | Approved runtime, isolation boundary, resource ceilings, timeout/cancel semantics | A bounded worker separate from the web process; OpenSandbox is only a candidate | F004 live execution | Platform lead + security reviewer |
| D005 | RESOLVED 2026-09-08 | Evaluation definitions, benign controls, denominators, review thresholds, and explanation support | One versioned suite and one adapter; SHAP only if meaningful and supported for the selected domain | F003–F007 domain-specific acceptance | Evaluation lead + independent reviewer |
| D006 | OPEN | Retention period, export redaction, license restrictions, and audit metadata retention | Minimize retained content; exports redacted by policy; block destructive purge until approved | F007 export policy and F008 retention operations | Data owner + security reviewer |
| D007 | OPEN | Named feature owners and independent reviewers | Assign one accountable owner per feature; specialists may contribute across features | Team scheduling and approval, not document drafting | Project owner |

## Recording a resolution

For each decision, add:

- Decision ID and status: OPEN / RESOLVED / SUPERSEDED.
- Chosen option, rationale, and alternatives rejected.
- Approver and approval date.
- Affected feature requirements and acceptance scenarios.
- Any new dependencies or changed exclusions.

When a decision is superseded, retain the previous record and re-review affected specs and plans. Do not mark a feature approved simply because its files exist.

## Resolutions recorded 2026-09-08

All five records below are reflected in the product spec ([docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md)) and in the amendment proposals appended to the constitution. The constitution itself has not been ratified; where a resolution diverges from a constitution principle, the amendment proposal records the rationale and bounds and awaits named approval.

### D001 — First domain and benign use case

- **Status:** RESOLVED.
- **Chosen option:** Two modalities in Phase A. (1) Image classification on aerial-target / military-vehicle imagery drawn **only** from open, unclassified, public datasets with a clear licence. (2) A tabular classifier (bundled sklearn / XGBoost model) trained on lexical features of the Kaggle malicious-URLs dataset ([sid321axn/malicious-urls-dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset), owner Manu Siddhartha; file `malicious_phish.csv`, columns `url` and `type`; 651,191 rows, 45,664,439 bytes; licence "CC0: Public Domain" as stated by Kaggle's metadata API; classes benign / defacement / phishing / malware, benign the majority at roughly two thirds, exact per-class counts recorded at asset-build time; compiled from ISCX-URL-2016, PhishTank, the Malware Domain Blacklist, faizann24's phishing-URL set and a 2021 Kaggle URL dataset). Handling rule: URL strings are data — the pipeline never fetches, resolves, or renders any URL from the dataset; only lexical features are computed. The full download requires a Kaggle API token (`KAGGLE_USERNAME` / `KAGGLE_KEY`) read by the asset script; CI uses a small committed stratified sample (a few hundred rows) so tests never touch Kaggle. CIFAR-10 is the image CI and fixture dataset (tiny, deterministic), not the demo dataset.
- **Rationale:** The original use case is target-recognition robustness; a demo on recognizable imagery communicates the failure mode. Bounds recorded as a team decision: open/unclassified data only; the tool evaluates and hardens the robustness of a classifier and never trains, optimizes, or deploys targeting or weapons models; no mission-system connections.
- **Diverges from the proposal:** yes. The proposal was one domain, a document-category classifier or a synthetic FAQ assistant. It also diverges from the brief's and constitution's non-operational language on imagery; see constitution amendment proposal (a).
- **Alternatives rejected:** CIFAR-10 as the demo dataset (kept for CI); document classifier; synthetic FAQ assistant; the LLM-assistant domain (Phase B, via garak pointed at Pythia if added); the HuggingFace partial mirrors `joshtobin/malicious_urls` (<1K rows) and `JorgeGMM/malicious_urls` (10K–100K rows) as the tabular source of record — neither is the full table, and each is usable only as a fallback fixture if its licence is confirmed.
- **Approver:** product owner (hackathon), 2026-09-08.
- **Affected requirements:** F002 domain validation and dataset licence fields; F003 per-modality attack sets (image: FGSM, PGD; tabular: PGD, HopSkipJump); F005 modality-appropriate explanations (image saliency overlays; tabular SHAP bar and beeswarm); F007 per-modality reports; every acceptance scenario that named a document classifier or FAQ assistant.
- **New dependencies / changed exclusions:** the `ml` extra (CPU torch, ART, SHAP, ONNX loading, sklearn / XGBoost). A Kaggle API token is a build-time dependency of the tabular asset script only — never a runtime dependency, and CI does not need one. Exclusions unchanged: no poisoning pipeline, no operational or sensitive data, no targeting or weapons optimization.

### D002 — Managed identity, owner bootstrap, invitations

- **Status:** RESOLVED.
- **Chosen option:** aegis's Keycloak OIDC (`AEGIS_AUTH_MODE=oidc`, JWKS verification, project roles from the `aegis_project_roles` claim) with NextAuth in the web app. Dev-token mode (`AEGIS_AUTH_MODE=dev`, bearer `dev:<email>`, refused when `AEGIS_ENV=prod`, the value `aegis/api/settings.py` and `aegis/config.py` test for) is allowed for the demo. Initial owner bootstrap is Keycloak realm configuration under `deploy/keycloak/`. Invitations are Keycloak-managed; the application has no invitation table and stores no invitation secrets.
- **Rationale:** the platform already ships managed authentication, role-rank RBAC, and Postgres RLS; the constitution's Principle IV is satisfied without custom password handling.
- **Diverges from the proposal:** no.
- **Alternatives rejected:** custom passwords or locally minted tokens; hosting-platform collaborator inheritance; the lean design's "no auth" posture.
- **Approver:** product owner (hackathon), 2026-09-08.
- **Affected requirements:** F001 invitation and membership-editing stories are re-scoped to Keycloak; F001 role names become `scanner` / `remediator` / `approver` / `admin` (see the architecture baseline); F008 actor identity is the OIDC `sub` / email.
- **New dependencies / changed exclusions:** none beyond what aegis already deploys. Dev-token mode must never be enabled outside the demo.

### D003 — Model and dataset access, permitted formats, approval policy

- **Status:** RESOLVED.
- **Chosen option:** Phase A ingest is bundled sample models **and** white-box artifact upload: ONNX preferred; PyTorch `state_dict` with an explicit, registered architecture accepted; full pickles refused by default. Uploaded models are loaded only on the worker, inside aegis's plugin-sandbox pattern (separate process, no network, rlimits, minimal environment), never in the API process. Black-box endpoint connectors (`ml_model_endpoint`, query-only) are Phase B. Registration and upload are `admin`-gated (`target.manage`); format validation and sandboxing are the Phase A approval controls, and the independent Reviewer/Owner approval workflow for catalog versions is Phase B.
- **Rationale:** the use case requires evaluating a user's own model; the format rules and the sandbox make this bounded execution rather than unrestricted execution of uploaded code. See constitution amendment proposal (b).
- **Diverges from the proposal:** yes. The proposal deferred uploads and endpoints; uploads are now Phase A within these bounds. Endpoints stay deferred.
- **Alternatives rejected:** bundled-only ingest (the lean design); accepting full pickles behind a consent checkbox in Phase A; loading in the API process.
- **Approver:** product owner (hackathon), 2026-09-08.
- **Affected requirements:** F002 upload validation (format sniffing, size limits, sha256, refusal messages), F002 dataset licence recording, F004 execution boundary, F008 upload audit event with the artifact sha256 and never its bytes.
- **New dependencies / changed exclusions:** ONNX runtime in the worker image only. "Unrestricted execution of uploaded model artifacts" remains excluded; "bounded, sandboxed, worker-side loading of ONNX / `state_dict`" is included.

### D004 — Runtime, isolation boundary, ceilings, timeout and cancel semantics

- **Status:** RESOLVED.
- **Chosen option:** Celery workers behind Redis (aegis's existing worker) run every attack, explanation, hardening, and verify task; model loading and inference happen inside the aegis plugin sandbox (`AEGIS_PLUGINS_SANDBOX` pattern). Resource ceilings are the sandbox rlimits plus the stale-job reaper's runtime TTL (`aegis/workers/tasks/reaper.py`, which marks a stuck job `failed` with `error = "reaped: exceeded max runtime TTL"`). Cancellation is `aegis/services/runs.py`: the run and its queued/running jobs are marked `cancelled`; terminal states are sinks (`aegis/workers/job_state.py`). OpenSandbox is not used.
- **Rationale:** the boundary already exists, is tested, and satisfies Principle IV ("never fall back to executing untrusted work in the web process").
- **Diverges from the proposal:** no; the proposal asked for a bounded worker separate from the web process and treated OpenSandbox as a candidate only.
- **Alternatives rejected:** OpenSandbox; the lean design's in-process `ThreadPoolExecutor`.
- **Approver:** product owner (hackathon), 2026-09-08.
- **Affected requirements:** F004 isolation, timeout, and cancel requirements adopt the aegis state machine mapping in the architecture baseline; F004 acceptance scenarios for `timed_out` and `cancel_requested` are rewritten against `failed` (reaped) and immediate `cancelled`.
- **New dependencies / changed exclusions:** none new. GPU is out of scope; all demo models run on CPU.

### D005 — Evaluation definitions, controls, denominators, thresholds, explanations

- **Status:** RESOLVED.
- **Chosen option:**
  - Per-test-family metrics with denominators: clean accuracy; adversarial accuracy per attack per ε; attack success rate; confidence gap; mean perturbation norm; per-class counts. Every table shows `n`.
  - A benign random-noise control at the same ε as each attack, reported as its own family.
  - An ε sweep (default L∞ ε ∈ {0.01, 0.03, 0.1} for images) with a robustness curve.
  - SHAP per modality: image `DeepExplainer` / `PartitionExplainer` producing clean-vs-adversarial saliency overlays plus raw values JSON; tabular `TreeExplainer` producing bar and beeswarm plots. Attribution is evidence, not causal proof; the center-mass ratio is labelled heuristic.
  - Tabular target: the malicious-URL classifier of D001 (Kaggle `sid321axn/malicious-urls-dataset`, https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset, CC0 per Kaggle). Features are lexical and computed from the URL string only: length, digit/letter ratios, counts of `.`, `-`, `@`, `?`, `%`, `=`, subdomain count, path depth, IP-address host flag, URL-shortener flag, https flag, suspicious-TLD flag, Shannon entropy. Clean metrics and per-class counts are recorded in the asset manifest at build time. URL strings are data and are never fetched, resolved, or rendered. Attack applicability, stated plainly: PGD on the continuous features (with rounding) and HopSkipJump are evidence about the classifier's decision surface; a perturbation counts as a realizable attack only if the perturbed feature vector maps back to a constructible URL, and no report may claim otherwise. Recorded limitations: label noise, dataset age (2021), class imbalance, the Kaggle-token requirement for the full build, and the realizability gap. CI runs against the committed stratified sample, never Kaggle.
  - The Model Robustness Index per the product spec: five subscores (robust accuracy 0.35, evasion resistance 0.25, budget resilience 0.20, confidence calibration 0.10, explanation stability 0.10), an aggregate, grade bands with attack-scoped readings, derived finding severity, and ΔMRI on verify. Binding constraints: one MRI per campaign (one model × one modality × declared attack set × declared ε grid × reference budget); never aggregated across modalities or compared across campaigns with different settings; never shown without its subscores, the per-family table with denominators, and the ε curve; no grade is a readiness or certification statement; ΔMRI measured on this model at these settings is the only sanctioned form of "gain"; demo-script numbers are illustrative.
  - Finding severity thresholds: critical — succeeds at ε ≤ ε_small with ASR ≥ 0.5; high — ε ≤ ε_small with ASR ≥ 0.2, or ε_mid with ASR ≥ 0.5; medium — only at ε_mid; low — only at ε_large.
- **Rationale:** matches the brief's reporting principles (per-family results with denominators, benign controls, illustrative labels, candidates until measured) while giving the demo a per-campaign summary.
- **Diverges from the proposal:** partly. The proposal asked for one suite and one adapter with SHAP "only if meaningful"; the resolution adopts two modalities with SHAP for both and a per-campaign index. It diverges from the brief's "avoid a universal score that mixes unrelated domains" only in adopting a score at all; the constraints above keep it per-campaign and never mixed. See constitution amendment proposal (c).
- **Alternatives rejected:** no score (the lean design); a cross-modality or cross-campaign aggregate; hand-set severities; expected-gain numbers on recommendations before a verify.
- **Approver:** product owner (hackathon), 2026-09-08.
- **Affected requirements:** F002 bundled tabular dataset reference (Kaggle id, licence, sha256, committed CI sample); F003 profile fields (attack set, ε grid, reference budget, scoring weights, control on/off, sample size, seed); F005 panels (measurements / observations / interpretation / candidates as separate panels; scorecard always with subscores, table, and curve); F006 derived severity and candidate labels; F007 ΔMRI comparison restricted to compatible runs.
- **New dependencies / changed exclusions:** none new. "A universal score that mixes test families or domains" remains excluded; "a per-campaign index that travels with its denominators" is included.

### D006 — Retention, export redaction, licence restrictions, audit metadata retention

- **Status:** OPEN. Not decided on 2026-09-08. Blocks F007 export policy and F008 retention operations; does not block Phase A evidence capture. aegis's WORM export and redaction paths exist and can be reviewed once a data owner and security reviewer are named.

### D007 — Named feature owners and independent reviewers

- **Status:** OPEN. No owners or reviewers have been assigned; no names are recorded here. The product owner assigns them at the first team meeting.

## Work that can begin before the open decisions close

The team can implement Phase A in the product spec's demo-critical order, map evidence fields, draft UI flows, and review the aegis authorization and audit paths. Export redaction policy, destructive retention operations, endpoint connectors, and production release remain gated by D006 and by the constitution amendment approvals.
