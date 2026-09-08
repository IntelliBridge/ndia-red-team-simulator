# Adversarial ML Red-Team Simulator — Hackathon Spec

> Automated red-team simulator for DoD AI models. Upload or connect a model.
> Generate adversarial attacks with ART. Explain each failure with SHAP.
> Output natural-language hardening recommendations. Prove the whole trail on
> the Aegis audit chain.

Status: draft v0.1. Owner: hackathon team. Base: this Aegis fork
(`IntelliBridge/ndia-red-team-simulator`).

---

## 1. Goal

Build a web tool that stress-tests a machine-learning model before deployment.
A user selects a model, triggers an adversarial attack, and views the SHAP
explanation and the mitigation recommendations side by side.

The tool answers three questions for each model:

1. **Can it be fooled?** Generate adversarial examples that flip predictions.
2. **Why did it fail?** Use SHAP to show which features or pixels drove the
   wrong output.
3. **How do we fix it?** Emit natural-language hardening steps, scored by
   expected robustness gain.

## 2. Why reuse Aegis

Aegis already ships the platform we need for the loop. We add one new vertical
instead of building infrastructure from scratch. We reuse:

| Aegis capability | Reuse for the ML red-team |
|---|---|
| FastAPI + Celery + Postgres + Redis | Attack jobs run async on workers. |
| Hash-chained audit log (WORM to S3) | Every attack, explanation, and model access is recorded and verifiable. |
| RBAC + Postgres row-level security | Cross-org tenant isolation for model owners. |
| `Run` / `Job` / `Finding` / `Artifact` models | Map directly to campaigns, attacks, vulnerabilities, and SHAP outputs. |
| Scanner registry + capability vocabulary | ART attacks register the same way scanner adapters do. |
| Verify-after-fix pattern (`verify.replay`) | Re-run the attack after hardening to prove the gain. |
| Next.js web + design system + command palette | Extend with model and attack pages. |
| Helm chart / container images | Adapt for the ECS Fargate target. |
| Per-task LLM routing + budget caps | Drive the natural-language recommendation writer. |

The core insight: Aegis red-teams **code and services**. This vertical
red-teams **models**. The lifecycle (discover, exploit, explain, remediate,
verify) is identical.

## 3. Scope and phasing

The team chose all four modalities and both ingest paths. We phase the build so
the demo-day critical path is never at risk.

### Phase A — demo-critical path (must land)

- **Modalities:** image classifier (CV) and tabular classifier.
- **Ingest:** white-box artifact upload plus 3 bundled sample models.
- **Attacks:** FGSM and PGD (image); PGD and boundary/HopSkipJump (tabular).
- **Explain:** SHAP image saliency (image); SHAP bar and beeswarm (tabular).
- **Recommend:** LLM-written hardening report from attack + SHAP results.
- **Verify:** re-run the attack after applying a preprocessing defense.
- **UI:** model page, attack trigger, side-by-side SHAP + recommendations.
- **Deploy:** ECS Fargate + RDS Postgres + S3.

### Phase B — stretch (add if time allows)

- **Ingest:** black-box API endpoint connector (query-only).
- **Modalities:** text/NLP classifier and object detection (YOLO-style).
- **Attacks:** Carlini-Wagner, DeepFool, query-based black-box attacks;
  adversarial-patch for detection.
- **Explain:** KernelSHAP for black-box models; text token attributions.
- **Harden:** apply adversarial training on a bundled model and show the delta.

### Non-goals for the hackathon

- Training pipelines or model registries beyond upload.
- GPU. All demo models run on CPU. Keep sample models small.
- Real classified data. Ship only open, unclassified sample data.

## 4. Domain model mapping

We reuse the existing tables. We add two enum values and one detail shape. No
new core tables are required for Phase A.

| Existing concept | ML red-team meaning |
|---|---|
| `Target.kind` (`url` / `github_repo` / `image`) | Add `ml_model_artifact` and `ml_model_endpoint`. |
| `Target.value` | S3 key of the uploaded model, or the inference URL. |
| `Run` | An attack campaign against one model. |
| `Job.type` | Add `attack.run`, `explain.run`, `harden.recommend`. |
| `Finding` | One adversarial vulnerability (attack succeeded at budget ε). |
| `Finding.schema_blob` (`AegisFinding`) | Carries attack name, ε, success rate, confidence drop, SHAP artifact ids. |
| `Finding.validation_state` | Reused for verify-after-harden (`verified` / `still_vulnerable`). |
| `Artifact` | Stores adversarial examples, SHAP images, perturbation maps, robustness curves. |
| `AuthProfile` (Fernet-encrypted) | Reused for black-box endpoint credentials (bearer/header). |
| `AuditEvent` chain | Records model upload, each attack, each explanation, each report. |

New capability tags in the scanner registry vocabulary:
`adversarial_ml`, `explainability`.

## 5. Architecture

```
                          ┌─────────────────────────────────────────┐
   Browser (Next.js) ───► │ FastAPI /v1  (reuse Aegis API)           │
                          │  + /v1/models  /v1/attacks  /v1/explain  │
                          └───────────────┬─────────────────────────┘
                                          │ enqueue Job (audit event first)
                                          ▼
                          ┌─────────────────────────────────────────┐
   Redis broker ◄────────►│ Celery workers                          │
                          │  attack.run   → ART attack engine        │
                          │  explain.run  → SHAP explainer           │
                          │  harden.recommend → LLM writer           │
                          │  verify.replay → re-attack hardened model│
                          └───────┬─────────────────────┬───────────┘
                                  │                      │
                       Postgres (RDS)             S3 (models, artifacts,
                    runs/jobs/findings/audit       SHAP images, adv. examples)
```

New Python packages inside the `aegis` namespace:

- `aegis/ml/loaders.py` — load a model from artifact or endpoint into an ART
  estimator. Detects framework by file signature.
- `aegis/ml/attacks/` — ART attack adapters. One module per attack, registered
  through the existing registry so they list in `/tools`.
- `aegis/ml/explain/` — SHAP explainers per modality. Emit PNG + JSON artifacts.
- `aegis/ml/harden.py` — map (attack result + SHAP signal) to a ranked list of
  defenses, then call the LLM writer for prose.
- `aegis/ml/eval.py` — robustness metrics: clean accuracy, robust accuracy,
  attack success rate, mean perturbation, confidence drop.
- `aegis/workers/tasks/{attack,explain,harden}.py` — Celery tasks mirroring the
  existing `scan` / `fix` / `verify` tasks.

### Model loading and isolation

Untrusted model files are dangerous. A pickle can execute code on load.

- **Preferred formats:** ONNX and TensorFlow SavedModel (no arbitrary code on
  load). Accept PyTorch `state_dict` with an explicit architecture, not full
  pickles.
- **Sandbox:** load and run every uploaded model in the existing plugin
  sandbox pattern (`AEGIS_PLUGINS_SANDBOX`): separate process, dropped network,
  rlimits, minimal env. Reject full-pickle `torch.load` by default.
- **Never load a model file in the API process.** Loading happens only on the
  worker, in the sandbox.

## 6. Attack catalog (ART)

Adversarial Robustness Toolbox provides the attacks. We wrap each as an adapter
with a common `run(estimator, data, budget) -> AttackResult` interface.

| Modality | Attack | Access | Phase |
|---|---|---|---|
| Image | FGSM | white-box | A |
| Image | PGD (L∞, L2) | white-box | A |
| Image | Carlini-Wagner L2 | white-box | B |
| Image | DeepFool | white-box | B |
| Image | HopSkipJump | black-box | B |
| Tabular | PGD | white-box | A |
| Tabular | Boundary / HopSkipJump | black-box | A |
| Tabular | Zeroth-Order Optimization | black-box | B |
| Text | TextFooler-style word substitution | black/white | B |
| Detection | Adversarial patch / DPatch | white-box | B |

Each attack sweeps a small budget grid (for example ε in
`{0.01, 0.03, 0.1}` for L∞ images) so the UI can plot a robustness curve. An
attack produces a `Finding` when success rate crosses a configurable threshold
at any budget.

## 7. Explainability (SHAP)

SHAP explains why the model failed. We show clean vs adversarial side by side.

| Modality | SHAP explainer | Output artifact |
|---|---|---|
| Image | `DeepExplainer` (white-box) or `PartitionExplainer` | Pixel saliency overlay, clean vs adversarial. |
| Tabular | `TreeExplainer` (trees) or `KernelExplainer` | Bar plot, beeswarm, per-sample force plot. |
| Text | `PartitionExplainer` | Token attribution highlight. |
| Black-box any | `KernelExplainer` | Same plots, sampled. |

The key demo narrative comes from the diff: the SHAP overlay shows the model
relied on background pixels rather than the target, which is why the small
perturbation flipped the label. `aegis/ml/explain` writes both a rendered PNG
and the raw SHAP values JSON to S3 as `Artifact` rows.

## 8. Scoring system — the Model Robustness Index

The tool reduces every campaign to one number: the **Model Robustness Index
(MRI)**, on a 0 to 100 scale, where higher means more robust. The MRI drives
the scorecard, the finding severities, and the ranked recommendations. It is
deterministic and reproducible from the stored metrics, so two runs are
comparable when they use the same attack set and budget grid.

### 8.1 Inputs

For each attack `a` at each perturbation budget ε, the engine records:

- `acc_clean` — accuracy with no attack (the baseline).
- `acc_adv(a, ε)` — accuracy on the adversarial examples.
- `asr(a, ε)` — attack success rate, the fraction of correctly classified
  inputs the attack flips.
- `pert(a)` — mean perturbation size at first success, in the attack's Lp norm.
- `conf_gap(a, ε)` — mean confidence on the wrong label minus the right label.
- `expl_shift(a, ε)` — `1 − cosine similarity` of the SHAP attributions, clean
  vs adversarial.
- `queries(a)` — queries needed to break the model (black-box attacks only).

### 8.2 Dimension subscores

Each subscore is on a 0 to 100 scale, where 100 is ideal. Each is the mean over
the in-scope attacks.

| Dimension | Symbol | Definition | Weight |
|---|---|---|---|
| Robust accuracy | `S_acc` | Worst-case `acc_adv` across ε, divided by `acc_clean`. | 0.35 |
| Evasion resistance | `S_asr` | `1 − mean ASR` at the reference budget. | 0.25 |
| Budget resilience | `S_eps` | Normalized area under the robust-accuracy vs ε curve. | 0.20 |
| Confidence calibration | `S_conf` | `1 − clamp(conf_gap)`; a model that is confidently wrong scores low. | 0.10 |
| Explanation stability | `S_expl` | `1 − mean expl_shift`. | 0.10 |

Explanation stability is the SHAP-native signal. A model whose reasoning moves
to irrelevant features under a tiny perturbation is brittle even when its
accuracy holds. This dimension is unique to this tool.

### 8.3 Aggregate

```
MRI = round( 0.35·S_acc + 0.25·S_asr + 0.20·S_eps + 0.10·S_conf + 0.10·S_expl )
```

Weights live in a `scoring` config block and are overridable per project. The
reference budget and the ε grid are stored with each score, so a score is only
ever compared against another at the same settings.

### 8.4 Grade bands

| MRI | Grade | Reading |
|---|---|---|
| 90–100 | A | Hardened. Resists every in-scope attack at the reference budget. |
| 75–89 | B | Strong. Minor degradation under the strongest attack. |
| 60–74 | C | Moderate. Breaks under standard PGD. Harden before fielding. |
| 40–59 | D | Weak. Cheap attacks succeed. Not deployment-ready. |
| 0–39 | F | Failing. Flips under near-imperceptible perturbation. |

### 8.5 Finding severity is derived, not hand-set

Each attack that crosses its success threshold becomes a `Finding`. Severity
follows from the budget at first success and the ASR, so it cannot be gamed by
inspection:

- **critical** — succeeds at ε ≤ ε_small with ASR ≥ 0.5.
- **high** — succeeds at ε ≤ ε_small with ASR ≥ 0.2, or at ε_mid with ASR ≥ 0.5.
- **medium** — succeeds only at ε_mid.
- **low** — succeeds only at ε_large.

This writes to the existing `Finding.severity` field, so the findings table,
filters, and audit trail work unchanged.

### 8.6 Score delta on verify

After a hardening defense is applied, the campaign re-runs and the tool reports
**ΔMRI**, the new score minus the old, plus each per-dimension delta. A
recommendation's expected gain (section 9) is checked against the actual ΔMRI,
which closes the loop from finding to proven fix.

## 9. Hardening recommendations

`aegis/ml/harden.py` turns results into action. It runs in two layers.

1. **Rule layer (deterministic).** Map observed signals to candidate defenses.
   Examples:
   - High FGSM success at small ε → recommend adversarial training and
     gradient masking review.
   - SHAP concentrated on background/irrelevant features → recommend
     input preprocessing, feature squeezing, or retraining with masking.
   - Large confidence with wrong label → recommend confidence calibration and
     an out-of-distribution reject option.
   - Black-box query success → recommend rate limiting and query-pattern
     monitoring at the inference API.
2. **LLM writer layer.** Feed the ranked candidates, metrics, and SHAP summary
   to the LLM (reuse per-task routing + budget caps). It writes a concise,
   plain-language report with prioritized steps and expected robustness gain.

Each recommendation links to the ART defense that implements it (adversarial
training, feature squeezing, spatial smoothing, defensive distillation) so a
Phase B step can apply it and re-measure.

## 10. API surface

Reuse the existing `/v1` router and auth. Add:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/models` | Register a model target: upload artifact (multipart to S3) or endpoint URL. Returns a `Target`. |
| `GET` | `/v1/models` | List model targets for the project. |
| `POST` | `/v1/models/{id}/attacks` | Start an attack campaign. Body: modality, attacks, budget grid, sample dataset id. Creates a `Run` + `attack.run` jobs. |
| `GET` | `/v1/runs/{id}` | Reuse. Campaign status + stage table. |
| `GET` | `/v1/findings?run_id=` | Reuse. Adversarial findings with metrics. |
| `POST` | `/v1/findings/{id}/explain` | Enqueue `explain.run`. Returns SHAP artifact ids. |
| `POST` | `/v1/findings/{id}/harden` | Enqueue `harden.recommend`. Returns the report. |
| `GET` | `/v1/artifacts/{id}` | Reuse. Stream SHAP PNG / JSON with strict CSP. |
| `POST` | `/v1/findings/{id}/verify` | Reuse `verify.replay` to re-attack after hardening. |

Every mutating call emits a chained audit event before enqueue, exactly as the
existing scan flow does.

## 11. Web UI

Extend the Next.js app. Reuse the design system, tables, and RBAC gating.

- **`/models`** — model list; upload dialog; "Connect endpoint" form; bundled
  sample picker.
- **`/models/[id]`** — model summary; "Run attack" launcher with modality,
  attack checklist, and budget slider.
- **`/runs/[id]`** — campaign progress; the MRI scorecard (score, grade, and
  the five dimension bars); robustness curve; findings table.
- **`/findings/[id]`** — the money screen. Three panes side by side:
  1. Original vs adversarial input (image pair, or feature diff table).
  2. SHAP explanation (clean vs adversarial saliency).
  3. Ranked hardening recommendations with expected gain and "Verify fix".
- Reuse `/audit` to show the tamper-evident trail of the whole campaign.

## 12. AWS deployment (ECS Fargate)

Target: ECS Fargate + RDS Postgres + S3 + ElastiCache Redis. No GPU.

| Component | AWS service | Notes |
|---|---|---|
| API (`aegis-api`) | ECS Fargate service behind ALB | Reuse `deploy/Dockerfile.api`. |
| Worker (`aegis-worker`) | ECS Fargate service | Reuse `deploy/Dockerfile.worker`, add ART + SHAP + ONNX/torch-cpu to the image. |
| Web (`aegis-web`) | ECS Fargate service behind ALB, or Amplify | Reuse `deploy/Dockerfile.web`. |
| Postgres | RDS PostgreSQL 16 | Enable RLS. Run Alembic migrations on deploy. |
| Redis | ElastiCache (Redis) | Celery broker + result backend. |
| Object store | S3 bucket | Models, artifacts, SHAP outputs. Enable Object Lock for WORM audit export. |
| Secrets | AWS Secrets Manager | LLM keys, worker signing key, Fernet key. |
| Auth | Keycloak on Fargate, or Cognito via OIDC | Dev mode acceptable for the hackathon demo. |

Build steps:

1. Add `art`, `shap`, `onnxruntime`, `torch` (CPU wheel), `scikit-learn`, and
   `matplotlib` to a new `ml` optional-dependency group in `pyproject.toml`.
   Install it only in the worker image to keep API and web images small.
2. Write a Terraform or Copilot definition for the four Fargate services, RDS,
   ElastiCache, S3, and the ALB. Reuse the Helm env var names as task-def env.
3. Set `AEGIS_BLOB_BACKEND=s3` and point Postgres/Redis at the managed
   endpoints.
4. Seed 3 bundled sample models and 2 sample datasets into S3 on first deploy.

## 13. Security and trust notes

- **Model files are untrusted input.** Load only in the worker sandbox. Prefer
  ONNX/SavedModel. Refuse full pickle load unless the user checks an explicit
  "I trust this file" box, and even then, sandbox it.
- **Attacks stay in-boundary.** We never send a target model's data to a third
  party. Only the SHAP summary text and metrics reach the LLM writer, with
  secrets redacted, reusing the existing redaction path.
- **Multi-tenancy.** Model artifacts and findings inherit Postgres RLS by
  `org_id`. One tenant never sees another's model or results.
- **Audit.** Upload, attack, explain, harden, and verify each append to the
  hash-chained log. `aegis audit verify` proves the campaign trail.
- **Data.** Ship only unclassified, open sample data. Document this in the UI.

## 14. Build sequence and milestones

Ordered for a 2-day hackathon. Each milestone is demo-able on its own.

| # | Milestone | Deliverable |
|---|---|---|
| M0 | Scaffold | `aegis/ml/` package, `ml` dep group, migration adding the two `Target.kind` values and the new `Job.type`s. |
| M1 | Load + attack (image) | Load a bundled CNN from ONNX in the sandbox. Run FGSM + PGD. Write `Finding`s with metrics. |
| M2 | SHAP (image) | `explain.run` produces clean vs adversarial saliency PNGs as `Artifact`s. |
| M3 | Recommendations | Rule layer + LLM writer produce the hardening report. |
| M4 | Tabular path | Load a bundled XGBoost/sklearn model. PGD + boundary attack. TreeExplainer SHAP. |
| M5 | UI | `/models`, attack launcher, and the three-pane `/findings/[id]` screen. |
| M6 | Verify loop | Apply a feature-squeezing defense, re-attack, show the robustness delta. |
| M7 | Deploy | Push the three Fargate services + RDS + S3. Run the demo end to end. |
| B1+ | Stretch | Black-box connector, text and detection modalities, adversarial-training defense. |

## 15. Demo script (target)

1. Open `/models`. Pick the bundled aerial-target CNN.
2. Click **Run attack**. Select FGSM + PGD, ε slider at 0.03. Start.
3. Watch the campaign complete on `/runs/[id]`. The MRI scorecard lands at
   about 38 (grade F), and a critical finding appears.
4. Open the finding. Left: the tank image, clean vs perturbed (near-identical to
   the eye). Middle: SHAP shows the model fixated on background terrain, not the
   vehicle. Right: recommendations — adversarial training, input preprocessing,
   confidence calibration — with expected gain.
5. Click **Verify fix**. The tool applies feature squeezing and re-attacks.
   The MRI climbs to about 71 (grade C), the ΔMRI of +33 shows on the
   scorecard, and the finding flips to `verified`.
6. Open `/audit`. Show the tamper-evident chain of the whole campaign.

## 16. Open risks

- **ART + SHAP + torch image size.** Keep it in the worker image only. Use the
  CPU torch wheel. Pin versions early.
- **SHAP on images is slow.** Use small models and a handful of samples for the
  demo. Cache explanations.
- **Pickle safety.** Default to ONNX. Treat any pickle as hostile.
- **Scope creep across four modalities.** Freeze Phase A first. Do not start
  text or detection until the image + tabular demo runs end to end.
