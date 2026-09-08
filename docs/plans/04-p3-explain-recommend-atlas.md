# Phase P3 · Milestones M2/M3/M6 · Features F005/F006 (v2, redsim substrate)

Status: v2, 2026-09-08. Owner: Dev C (WS3). Wave: Slice 2 into Slice 3.

Read `docs/plans/00-master-plan.md` first (v2, sections 2, 5, 7), then this
file. Build to the canonical spec
`docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`, sections 13
(explainability), 14 (evidence model), 15 (scoring), 16 (hardening), and to the
feature specs `specs/005-evidence-workbench/spec.md` and
`specs/006-findings-review/spec.md`. All contracts are the redsim platform. The
deleted `redsim/` package and its filesystem store no longer exist. Use the
redsim paths below, not the v1 paths.

This phase turns a finished attack campaign into evidence, candidate advice, and
a measured verify delta. It owns the explain layer, the recommend layer, the ML
projection onto the redsim `Finding`, and three Celery tasks. MITRE ATLAS tagging
is **Phase B2** (canonical section 27.2, tag at `Finding.schema_blob.ml.atlas_technique`),
so this Phase A phase does not build it. The filename keeps the word "atlas" for
continuity only.

---

## 1. Objective

Deliver three outcomes for one completed campaign:

1. **Explanation (M2, F005).** Run SHAP on the target model. For selected
   samples write clean, adversarial, difference, and attribution artifacts.
   Store the raw arrays as an `.npz` plus a JSON meta file. Register every
   artifact as an `Artifact` row in S3/MinIO. Build one `Observation` per
   selected sample with the centre-mass heuristic and the per-sample
   `expl_shift`. Return the per-attack `expl_shift_mean` and its noise floor so
   WS2 can compute the MRI subscore `S_expl`.
2. **Recommendations (M3, F006).** Read the measurements, observations, and
   score. Emit deterministic `Interpretation` statements and
   `CandidateRecommendation` candidates by the fixed rule set R1 through R7.
   Each candidate cites the measurement or observation ids that triggered it.
   An optional Pythia narrative rewrites the ranked rule output under
   guardrails. The narrative may add no claim, number, or recommendation.
3. **Findings projection and verify (M3, M6, F006).** Project the run record
   onto `Finding.schema_blob.ml` with a derived severity. Run the
   verify-after-harden loop: wrap the ART estimator with a preprocessing
   defense, re-run the identical campaign, and compute the measured ΔMRI.

Every honesty invariant holds. A recommendation is always `status="candidate"`
and `validation="not evaluated"` until a verify run measures it. The centre-mass
metric is always `metric_kind="heuristic"`. SHAP is supporting evidence, not
causal proof. The words "hardened", "deployment-ready", "certified", and "safe"
never appear in any output.

## 2. Scope

### In scope

- `redsim/ml/explain/base.py` - the `ExplainOutput` dataclass.
- `redsim/ml/explain/shap_image.py` - `explain()` for image targets, on
  `shap.GradientExplainer` (default) with a `shap.PartitionExplainer` fallback
  for non-differentiable modules.
- `redsim/ml/explain/shap_tabular.py` - `explain()` for tabular targets, on
  `shap.TreeExplainer` for tree models (exact, deterministic) and
  `shap.KernelExplainer` for non-tree models.
- `redsim/ml/explain/summary.py` - the deterministic SHAP text summary
  (`ml.shap.summary_text`), the only explanation content the LLM writer sees.
- `redsim/ml/recommend/interpret.py` - `interpret()` for the I1 through I6 rules.
- `redsim/ml/recommend/rules.py` - `recommend()` for the R1 through R7 rules.
- `redsim/ml/recommend/narrative.py` - `narrate()`, the optional Pythia rewrite.
- `redsim/services/ml_findings.py` - the `Finding.schema_blob.ml` projection and
  derived severity.
- The Celery tasks `explain.run`, `harden.recommend`, and `verify.replay`, and
  the ML step of the verify loop.
- The pytest modules under `tests/ml/` that cover all of the above.

### Out of scope

- **MITRE ATLAS tagging.** Phase B2 (canonical section 27.2), not Phase A. This
  phase adds no `atlas.py`, no technique map, and no ATLAS field wiring. When B2
  lands, the tag is stamped at `Finding.schema_blob.ml.atlas_technique` from the
  attack registry, not now.
- The scoring math and the `MRIRecord`. That is WS2 (`redsim/ml/scoring.py`). P3
  reads the score and supplies `expl_shift_mean`. It does not compute the MRI.
- The attack run, the ε sweep, the clean and control evaluations, and `x_adv`.
  That is WS2 (`redsim/ml/attacks/`, `campaign.py`, `eval.py`). P3 receives the
  arrays and the measurements.
- The target model, weights, dataset slice, and the sandboxed loader. That is
  WS1 (`redsim/ml/targets/`). P3 calls `Target.torch_model()`,
  `Target.art_estimator()`, and `Target.predict_proba()`.
- The API routers, the campaign service, and the WS event channel. That is WS4.
  P3 exposes the three Celery tasks and the projection that WS4 mounts.
- The web panels (three-pane findings screen, run page). That is WS5. P3 supplies
  the artifacts and the projection they render.
- The MRI scorecard component, the schema widening to `CampaignConfig`, and the
  `REDSIM_ML_LLM_MODEL` env rename. Those land in WS0 (M0) and WS2. P3 consumes
  them.

## 3. Prerequisites and dependencies

### Needs (inputs P3 consumes)

- **From WS0 (M0 scaffold):** the widened `CampaignConfig` (attack set, ε grid,
  reference budget, MRI weights, `explain_k`, `llm_narrative`), the schema
  additions of section 5.3 (`Observation.expl_shift`, `top_features_clean`,
  `top_features_adv`, `CandidateRecommendation.validation` extended to
  `"measured"`, the `MeasuredDelta` type), the `Action` members for explain,
  harden, and verify, and the env rename from `REDSIM_LLM_MODEL` to
  `REDSIM_ML_LLM_MODEL` in `redsim/llm/pythia.py`. P3 depends on these but does
  not create them.
- **From WS1 (targets):** a loaded `Target` in the sandboxed worker.
  `torch_model()` returns the differentiable module in eval mode.
  `art_estimator()` returns the ART estimator (`PyTorchClassifier`,
  `SklearnClassifier`, or `XGBoostClassifier`). `predict_proba(x)` returns
  probabilities. Tree targets carry the real model, never the PGD surrogate.
- **From WS2 (attacks and scoring):** the adversarial array `x_adv(a,
  reference_eps)` aligned index-for-index with the sampled slice, the control
  array `x_ctrl` at the same ε, the `Measurement` rows, and the `MRIRecord`.
  The explain stage runs after the attack Jobs of the campaign.
- **From the redsim platform:** `Observation`, `Interpretation`,
  `CandidateRecommendation`, `Measurement`, `Provenance`, `RunRecord` in
  `redsim/ml/schema.py`, the `Artifact` model and the blob store in
  `redsim/storage`, the `Finding` model in `redsim/db/models.py`, the audit chain
  in `redsim/audit/chain.py`, Pythia in `redsim/llm/pythia.py` and guardrails in
  `redsim/llm/guardrails.py`.

### Provides (outputs P3 exposes)

- `expl_shift(a, reference_eps)` with its `n` and its noise floor, written on the
  attack's `reference_eps` `Measurement` row (`expl_shift_mean`,
  `expl_shift_n`) and returned on `ExplainOutput`. WS2 reads it for `S_expl`.
- `Observation` rows with SHAP artifacts, back to the run record and the F005
  observation gallery.
- `Interpretation` and `CandidateRecommendation` lists, back to the run record
  and pane 3 of the findings screen.
- The `Finding.schema_blob.ml` projection with derived severity, back to WS4 and
  the F006 findings table.
- The measured ΔMRI and the `MeasuredDelta`, back to the recommendation and the
  finding after a verify run.

### The WS2 to WS3 seam

The MRI dimension `S_expl` (spec section 15.2) consumes `expl_shift` from the
explain stage. The contract:

- `explain()` computes `expl_shift_i = clamp(1 - cos(flatten(phi_clean),
  flatten(phi_adv)), 0, 1)` per explained sample, over the clean-predicted class
  on both inputs, at the reference budget. The aggregate is the mean over the
  explained set, reported with its `n` and `n_excluded`.
- `S_expl = 1 - mean over in-scope attacks of expl_shift(a, reference_eps)`, and
  WS2 computes it. If `explain_k == 0`, the explainer is unsupported, or the
  explain stage failed, `S_expl` has no input and the MRI is not computed (spec
  15.4, D9(ii)). P3 must record the reason so the scorecard can state it.
- A near-zero-norm attribution pair is undefined. Exclude it and count it in
  `expl_shift_n_excluded`. Never treat an excluded pair as a stable pair.
- The noise floor `expl_shift_noise_floor` uses the control attributions at the
  same ε. It is context, not an MRI input. The rule layer and the UI compare the
  attack shift against it.

## 4. Interfaces consumed and exposed

### Exposed - `ExplainOutput` (`redsim/ml/explain/base.py`)

```python
from dataclasses import dataclass, field
from redsim.ml.schema import Observation

@dataclass
class ExplainOutput:
    observations: list[Observation]           # one per explained sample
    expl_shift_mean: float | None             # None when nothing was comparable
    expl_shift_n: int                         # |E(a)| - n_excluded
    expl_shift_n_excluded: int
    expl_shift_noise_floor: float | None      # control attribution shift, context only
    noise_floor_n: int
    explainer: str                            # "GradientExplainer" | "PartitionExplainer"
                                              # | "TreeExplainer" | "KernelExplainer"
    background_size: int
    nsamples: int
    shap_version: str
    summary_text: str                         # ml.shap.summary_text content
    artifacts: dict[str, str] = field(default_factory=dict)  # campaign-level name -> Artifact.id
    wall_time_s: float = 0.0
```

Land this file first so WS2 and WS4 can import the type while the rest of P3 is
in progress.

### Exposed - `explain()` (image and tabular)

Both modality modules expose the same signature:

```python
def explain(target: Target,
            x_clean: np.ndarray, y_true: np.ndarray, sample_indices: list[int],
            x_adv: np.ndarray, x_ctrl: np.ndarray,
            *, k: int, seed: int, reference_eps: float,
            sink: ArtifactSink) -> ExplainOutput: ...
```

- `k` is `CampaignConfig.explain_k` (default 8, bounds 0 to 32, capped at 8 on
  the `PartitionExplainer` path). The function explains up to `k` flipped and up
  to `k` non-flipped samples in slice order.
- `seed` seeds the sampled explainers so a rerun reproduces the maps.
- `reference_eps` selects the budget at which `x_adv` and `x_ctrl` were
  produced. Phase A explains at the reference budget only.
- `sink` is the artifact sink the task provides. It writes bytes to S3/MinIO
  through `redsim/storage` and registers an `Artifact` row
  (`id`, `run_id`, `project_id`, `org_id`, `kind`, `sha256`, `location`,
  `content_type`, `size_bytes`, unique on `(run_id, kind, sha256)`). It returns
  the `Artifact.id` and `sha256`. `Observation.artifacts` maps a stable name to
  the `Artifact.id`. `Observation.artifact_sha256` mirrors `Artifact.sha256`.

### Exposed - `interpret()` and `recommend()`

```python
def interpret(measurements: list[Measurement],
              observations: list[Observation],
              score: MRIRecord,
              settings: ScoringConfig) -> list[Interpretation]: ...

def recommend(measurements: list[Measurement],
              observations: list[Observation],
              score: MRIRecord,
              settings: ScoringConfig) -> list[CandidateRecommendation]: ...
```

`settings` carries the thresholds of spec 15.3 (0.20, 0.05, 0.10, 0.15, 0.5).
Each rule prints its threshold in the rationale.

### Exposed - `narrate()` (optional Pythia rewrite)

```python
def narrate(recommendations: list[CandidateRecommendation],
            payload: NarrativePayload,
            *, config: RedsimConfig | None = None) -> list[CandidateRecommendation]: ...
```

`payload` holds only the text of spec 16.3: the measurements table as text, the
scorecard numbers, the ranked rule outputs, the SHAP text summary, and the
limitations. It carries no images, arrays, weights, dataset samples, or
identifiers.

### Exposed - the findings projection

```python
def project_finding_ml(record: RunRecord, score: MRIRecord,
                       settings: ScoringConfig) -> dict: ...   # writes Finding.schema_blob["ml"]
def derive_severity(attack_id: str, per_eps: dict, settings: ScoringConfig) -> Severity: ...
```

`derive_severity` follows spec 15.5 exactly, from the first-success ε and the
ASR. It never reads free text. `Severity = Literal["critical","high","medium","low"]`
already exists in `redsim/schema.py`.

### Consumed

- `Target` from `redsim/ml/targets/base.py` (`torch_model`, `art_estimator`,
  `predict_proba`).
- `redsim/storage` for the blob store, `redsim/db/models.py` for `Artifact` and
  `Finding`.
- `redsim/ml/schema.py` for the evidence types, `redsim/ml/scoring.py` for the
  `MRIRecord` and `ScoringConfig` (owned by WS2).
- `redsim/llm/pythia.py` (`PythiaSettings.from_env`, `chat_text`, `make_backend`,
  `PythiaUnavailable`, `PythiaSettings.redacted`) and the router
  `redsim/llm/router.py` (`route(task="ml.harden_narrative")`) with the budget
  checker.
- `redsim/llm/guardrails.py` (`guard_input`, `guard_output`, `GuardrailViolation`)
  and `redsim/audit/redact.py`.
- `redsim/audit/chain.py` (`AuditWriter.append`) for the explain, harden, and
  verify events.
- ART preprocessing defenses:
  `art.defences.preprocessor.FeatureSqueezing`,
  `art.defences.preprocessor.SpatialSmoothing`,
  `art.defences.preprocessor.JpegCompression`.

### Schema fields P3 writes (exact names, do not invent)

`Observation`: `id`, `sample_index`, `true_label`, `pred_clean`, `pred_adv`,
`flipped`, `confidence_clean`, `confidence_adv`, `artifacts`,
`artifact_sha256`, `center_mass_ratio_clean`, `center_mass_ratio_adv`, and the
added `expl_shift`, tabular adds `top_features_clean` and `top_features_adv`.
Leave `metric_kind` at `"heuristic"` and keep the default `metric_note`.

`Interpretation`: `id`, `statement`, `basis` (min length 1). Leave `kind` at
`"inferred"`.

`CandidateRecommendation`: `id` (`r.R1` through `r.R7`), `title`, `rationale`,
`triggered_by` (min length 1), `references`, and, only when the narrative runs,
`narrative` and `narrative_source="llm"`. Leave `status` at `"candidate"`.
Leave `validation` at `"not evaluated"` until a verify run measures it, then a
verify run sets `validation="measured"` and attaches `measured: MeasuredDelta`.

`Finding` (through the projection): `severity`, `finding_type="adversarial_ml"`,
`title`, `description` (measurement text only), `confidence`,
`source_tool="redsim.ml/<attack_id>"`, `status="open"`, `evidence` (measurement
ids), and the full `schema_blob["ml"]` derivation. Never write `Finding.status`
transitions here, those belong to F006 (spec section 6). Verify writes
`validation_state` through the existing `_STATE_MAP`.

## 5. Ordered implementation steps

### Step 1 - `explain/base.py`

Define `ExplainOutput` as in section 4. Land it first for WS2 and WS4.

### Step 2 - `explain/shap_image.py`: selection

- Get clean predictions from `predict_proba(x_clean)` and adversarial
  predictions from `predict_proba(x_adv)`. Take the argmax for the class and the
  max probability for the confidence.
- A sample flipped when its clean argmax differs from its adversarial argmax.
- Select the first `k` flipped and the first `k` non-flipped samples in slice
  order. Do not shuffle. Record the size of each group when it is smaller than
  `k`.

### Step 3 - `explain/shap_image.py`: attribution

- Build the background from 50 images drawn with the run seed from the
  evaluation slice, excluding the explained set when the slice allows. Cap the
  background at the slice size. Record `background_size`.
- Default path: build `shap.GradientExplainer(target.torch_model(),
  background_tensor)`. The module is already in eval mode.
- Fallback path (non-differentiable module, for example a converted ONNX graph
  outside the supported layer set): build `shap.PartitionExplainer` with
  `shap.maskers.Image` over `predict_proba`, and cap `k` at 8. Record which
  explainer ran in `explainer` and in `Provenance`.
- Compute three attributions per explained sample: `phi_clean` for the
  clean-predicted class on `x_clean`, `phi_adv` for the same class on `x_adv`,
  and, for flipped samples only, `phi_adv_predclass` for the adversarial
  predicted class on `x_adv`. Compute `phi_ctrl` for the clean-predicted class
  on `x_ctrl` for the noise floor.
- Keep the raw per-pixel arrays in memory for the shift, the heuristic, and the
  `.npz` before rendering.

### Step 4 - `explain/shap_image.py`: artifacts

For each explained sample, write under a per-sample prefix:

- `clean.png` (`ml.input.clean`), `adv.png` (`ml.input.adv`), and `diff.png`
  (`ml.perturbation`, the per-pixel absolute difference summed over channels,
  scaled so ε maps to full intensity, scale recorded in the meta file).
- `shap_clean.png` and `shap_adv.png` (`ml.shap.image`), attribution overlays
  for the clean-predicted class, one shared diverging colour scale per sample
  across its clean and adversarial maps.
- `shap_adv_predclass.png` (`ml.shap.image`, flipped only), labelled as the
  adversarial predicted class.
- `shap_values.npz` (`ml.shap.values`), float32 arrays `clean`, `adv`,
  `adv_predclass` (if any), `control`, and `indices`.
- `shap_meta.json` (`ml.shap.meta`), the explainer name and version, the class
  explained, the background size, `nsamples`, the seed, `center_mass_ratio_*`,
  `expl_shift`, the norms, the `diff.png` scale, and the wall time.

Render to an in-memory bytes buffer with a non-interactive matplotlib backend.
Do not start a GUI. Write every buffer through the `sink`.

### Step 5 - `explain/shap_image.py`: heuristic and shift

- `center_mass_ratio`: the share of total absolute attribution, summed over
  channels, inside the centred box covering 50 percent of the image area (side
  length 1 over root 2 of each dimension). Compute it on `phi_clean`
  (`center_mass_ratio_clean`) and `phi_adv` (`center_mass_ratio_adv`). It is a
  proxy for attention on the subject, not a segmentation. Leave
  `metric_kind="heuristic"` and keep the default `metric_note`. Append the
  weak-subject caveat when the dataset manifest flags `subject_centered: false`.
- `expl_shift`: per flipped and non-flipped sample, flatten `phi_clean` and
  `phi_adv` to vectors summed over channels, and compute `clamp(1 - cos, 0, 1)`.
  Guard a norm below 1e-12 by excluding the pair and counting it in
  `expl_shift_n_excluded`. Store the per-sample value on `Observation.expl_shift`.
  The aggregate is the mean over the explained set.
- `expl_shift_noise_floor`: the same computation against `phi_ctrl`. Record it
  beside the aggregate. It is context, not an MRI input.

### Step 6 - `explain/shap_image.py`: observations and output

Build one `Observation` per explained sample with the fields of section 4.
Assemble `ExplainOutput` with the aggregate shift, its `n` and `n_excluded`, the
noise floor, the explainer name, the background size, `nsamples`, the shap
version, and the wall time. Time the whole call.

### Step 7 - `explain/shap_tabular.py`

Mirror the image path. Choose the explainer by model type: `shap.TreeExplainer`
with `feature_perturbation="tree_path_dependent"` for tree models (exact,
deterministic, always on the real model), or `shap.KernelExplainer` over
`predict_proba` with a seeded 100-row background for non-tree models. Selection,
flip logic, and `expl_shift` are the same, with the feature vector as the flatten
target. Write `feature_diff.json` (`ml.feature_diff`), per-sample
`shap_force_<i>.png` (`ml.shap.force`), and the campaign-level
`shap_bar_clean.png` / `shap_bar_adv.png` (`ml.shap.bar`) and
`shap_beeswarm_clean.png` / `shap_beeswarm_adv.png` (`ml.shap.beeswarm`), all
sharing the clean feature order and the x-axis range. There is no spatial
centre-of-mass for tabular targets. Leave `center_mass_ratio_clean` and
`center_mass_ratio_adv` at `None`. Fill `top_features_clean` and
`top_features_adv` by mean absolute SHAP.

### Step 8 - `explain/summary.py`

Generate the SHAP text summary deterministically from templates (spec 13.7), per
attack at the reference budget, from the campaign-level aggregates. Each sentence
carries its denominator. Every summary ends with the fixed sentence "SHAP
attributions describe the model's sensitivity, not the cause of a failure."
Write it as `shap_summary.txt` (`ml.shap.summary_text`) and return it on
`ExplainOutput.summary_text`. This is the only explanation content the LLM
writer receives.

### Step 9 - `recommend/interpret.py`

Implement the I1 through I6 rules of spec 14.6 exactly, from the measurement and
observation values. Each `Interpretation` cites the ids it rests on in `basis`
(measurement ids like `m.clean`, `m.evasion.pgd.eps0.03`, `m.control.noise.eps0.03`,
observation ids like `o.003`). Report facts only: the accuracy drop, the flip
count, the gradient-versus-noise contrast, the shift, the confidence gap. Give
no advice here. Leave `kind="inferred"`. The demo sentence about background
pixels is permitted only as the I4 statement, labelled inferred and heuristic.

### Step 10 - `recommend/rules.py`

Implement the R1 through R7 rule table of spec 16.2 exactly. Fire each rule from
the measurement and observation values, not from prose:

- **R1** - `asr(fgsm, eps_small) >= 0.2` and control accuracy within 0.05 of
  clean at the reference budget. Candidate: adversarial training (PGD-based) and
  gradient-masking review.
- **R1b** - `asr(fgsm, eps_small) >= 0.2` and control accuracy below clean minus
  0.10. Candidate: noise-robust training and input-quality controls.
- **R2** - `acc(pgd, eps) < acc(fgsm, eps) - 0.10` for any grid ε. Candidate:
  evaluate with iterative attacks at multiple ε and iteration counts.
- **R3** - mean `center_mass_ratio_adv` on flipped observations at most mean
  `center_mass_ratio_clean` minus 0.15 (image), or `expl_shift_mean(eps_ref) >=
  0.5` (any modality). Candidate: investigate reliance on peripheral or
  irrelevant features, input preprocessing, feature squeezing, spatial
  smoothing, cropping. Marked heuristic. ART link: `FeatureSqueezing`,
  `SpatialSmoothing`.
- **R3t** - tabular: the top-3 SHAP features under attack differ from the clean
  top-3 on at least 50 percent of flipped samples. Candidate: feature range
  validation and clipping at inference. Marked heuristic. ART link:
  `FeatureSqueezing`, estimator `clip_values`.
- **R4** - `conf_gap_mean(eps_ref) >= 0.5`. Candidate: confidence calibration and
  an out-of-distribution reject option.
- **R6** - any evasion row with `accuracy < acc(m.clean) - 0.05`. Candidate:
  input preprocessing defenses as a cheap first experiment (JPEG compression,
  spatial smoothing, feature squeezing), with the adaptive-attack caveat. ART
  link: `JpegCompression`, `SpatialSmoothing`, `FeatureSqueezing`.
- **R7** - always. Candidate: rerun with a larger slice and a different seed.

Rules for the rules:

- Every `CandidateRecommendation` sets `triggered_by` to the measurement or
  observation ids that fired it. R7 cites `m.clean` so it still points at real
  evidence.
- State each tolerance and threshold as a named constant read from `settings`,
  and print it in the rationale.
- R2 fires only when both attacks ran at the same ε in this run. R3's image
  branch and R3t read the flipped observations and skip when the ratios or the
  feature lists are absent (the other modality leaves them `None`).
- Set `references` to the ART class path and the motivating paper (spec 16.6),
  including the known bypass. R5 (black-box query rate) applies to Phase A
  tabular black-box and Phase B endpoints, include it when a HopSkipJump row
  exists.
- Keep every candidate at `status="candidate"` and `validation="not evaluated"`.
  Give each a stable `id` (`r.R1` through `r.R7`).
- Rank the output by the derived Finding severity, then by the degradation
  magnitude at the reference budget, then by rule id. Store the order.
- On a flat measurement set only R7 fires. Test this.

### Step 11 - `recommend/narrative.py`

Optional Pythia rewrite of the ranked rule output, off by default:

- Require both `CampaignConfig.llm_narrative == True` and Pythia configured.
  `PythiaSettings.from_env()` returning `None` raises `PythiaUnavailable`, catch
  it, record "LLM narrative: not configured", and return the recommendations
  unchanged. Never fail the campaign for a missing gateway.
- Resolve the model through `redsim.llm.router.route(task="ml.harden_narrative")`,
  seeded from `REDSIM_ML_LLM_MODEL`, with the per-organisation override and the
  per-project and per-organisation budget caps. Reject a non-Pythia id.
- Assemble the user message from the `NarrativePayload` text only (spec 16.3).
  The system prompt states the contract: rewrite the rule outputs into prose,
  keep every number identical, add no recommendation or claim, and never use the
  words "validated", "proven", "guaranteed", "hardened", "deployment-ready",
  "certified", or "safe".
- Guard the round trip: `guard_input()` on the assembled user message before the
  call (model, dataset, and class names are user-supplied and could carry an
  injection), and `guard_output()` on the returned text after. Both fail safe.
- Run two post-checks: a numeric-consistency check rejecting any number token
  absent from the payload, and a banned-word check rejecting any banned word. A
  rejected narrative is discarded, `narrative_source` stays `"rules"`, and the
  UI shows the rejection reason.
- On success write the prose into `CandidateRecommendation.narrative` and set
  `narrative_source="llm"`. Never overwrite `title`, `rationale`,
  `triggered_by`, `status`, or `validation`. Record the attempt in the
  `harden.execute` audit event with `PythiaSettings.redacted()`, `prompt_sha256`,
  `completion_sha256`, and token counts. Never log the key or the text.

### Step 12 - `services/ml_findings.py`: projection and severity

- `derive_severity` from the first-success ε and the ASR (spec 15.5): critical,
  high, medium, or low. It never reads free text, so it cannot be adjusted by
  inspection.
- `project_finding_ml` fills the required `Finding` fields deterministically and
  writes `schema_blob["ml"]` with the full derivation: attack id and resolved
  params, grid, per-ε ASR and adversarial accuracy with denominators,
  first-success ε, `pert`, `conf_gap`, `expl_shift`, `queries`, the SHAP
  artifact ids, and the thresholds used, so severity is recomputable and
  auditable. A projection that disagrees with the run record is a bug.
- The projection reads the record and writes the finding row. It never blends
  measurement, observation, interpretation, and recommendation.

### Step 13 - Celery tasks

- `explain.run` (`redsim.explain_run`): pre-created at admission, runs after the
  attack Jobs. It loads the target in the sandboxed worker, reads the attack and
  control outputs, calls the modality `explain()`, registers the artifacts,
  writes the observations and the `expl_shift` onto the reference-budget
  measurement row, and appends the `explain.execute` audit event. It can also be
  triggered per finding through `POST /v1/findings/{id}/explain` (WS4).
- `harden.recommend` (`redsim.harden_recommend`): runs the `interpret` and
  `recommend` stages after `explain.run`, then the optional `narrate` stage. It
  needs only the run's own rows. A narrative failure leaves the rule output
  standing. It appends the `harden.execute` audit event.
- `verify.replay` (`redsim.verify_replay`): the verify-after-harden loop, step 14.

Admission is audit-first: the audit event is appended before any Run or Job row.

### Step 14 - the verify loop

`verify.replay` measures one preprocessing defense on a worker-side copy of the
pipeline (spec 16.5). It never modifies the stored model, the target, or a
profile.

- Load the same model artifact (same `model_sha256`) in the sandboxed loader and
  the same dataset revision, split, indices, and seed as the baseline
  (`settings_hash` equality).
- Wrap the ART estimator with the chosen preprocessor as
  `preprocessing_defences`, so both prediction and attack go through the defense.
  Defaults: `FeatureSqueezing(bit_depth=4)`, `SpatialSmoothing(window_size=3)`,
  `JpegCompression(quality=50)`, `clip_values` from the target.
- Re-run the identical attack set, ε grid, noise control, and the explanations at
  the reference budget. Write a full `RunRecord`, compute the MRI (WS2), and
  compute `ΔMRI = MRI(verify) - MRI(baseline)` with each per-dimension delta and
  the change in clean accuracy, only when the ΔMRI preconditions of spec 15.6
  hold.
- Update `Finding.validation_state` on the baseline's findings through the
  worker's `VerifyStatus` and the existing `_STATE_MAP` in
  `redsim/workers/tasks/verify.py` (`poc_passed`, `poc_failed`, `inconclusive`).
  Attach the `MeasuredDelta` to the recommendation whose ART link the verify run
  applied, and set that recommendation's `validation="measured"`. Other
  recommendations stay `not evaluated`.
- Append the verify-specific standing limitation about the straight-through
  gradient estimate through the defense, record `Provenance.defense`, and append
  the `verify.execute` audit event. Adversarial training and defensive
  distillation are Phase B, their verify button is disabled with no estimate.

### Step 15 - tests

Write the pytest modules of section 7.

## 6. Files to create and modify

Create:

- `redsim/ml/explain/base.py` - `ExplainOutput`.
- `redsim/ml/explain/shap_image.py` - image `explain()`.
- `redsim/ml/explain/shap_tabular.py` - tabular `explain()`.
- `redsim/ml/explain/summary.py` - the SHAP text summary.
- `redsim/ml/recommend/interpret.py` - `interpret()`.
- `redsim/ml/recommend/rules.py` - `recommend()`.
- `redsim/ml/recommend/narrative.py` - `narrate()`.
- `redsim/services/ml_findings.py` - the projection and `derive_severity`.
- The Celery tasks `explain.run`, `harden.recommend`, `verify.replay` under the
  redsim worker layout (for example `redsim/workers/tasks/`), plus the verify ML
  step. Register the tasks and the `Action` handlers with WS4 and WS0.
- Tests: `tests/ml/test_explain_image.py`, `tests/ml/test_explain_tabular.py`,
  `tests/ml/test_summary.py`, `tests/ml/test_interpret.py`,
  `tests/ml/test_recommend.py`, `tests/ml/test_narrative.py`,
  `tests/ml/test_ml_findings.py`, and verify-loop coverage extending
  `tests/test_verify.py` with the `ml` marker.

Modify:

- `redsim/ml/explain/__init__.py` - replace the one-line stub with re-exports of
  `explain` (both modalities) and `ExplainOutput`.
- `redsim/ml/recommend/__init__.py` - re-export `interpret`, `recommend`,
  `narrate`.

Depends on, do not modify (owned by WS0, WS1, WS2, or the redsim foundation):
`redsim/ml/schema.py`, `redsim/ml/scoring.py`, `redsim/ml/targets/base.py`,
`redsim/ml/attacks/base.py`, `redsim/storage`, `redsim/db/models.py`,
`redsim/llm/pythia.py`, `redsim/llm/guardrails.py`, `redsim/llm/router.py`,
`redsim/audit/chain.py`, `redsim/audit/redact.py`,
`redsim/workers/tasks/verify.py` (the `_STATE_MAP` and `VerifyStatus`).

No new migration. The schema additions (`Observation.expl_shift`,
`top_features_*`, the extended `validation`, `MeasuredDelta`,
`Finding.schema_blob.ml`) land with WS0's single `0010_ml_vertical` migration.

## 7. Testing and validation

All tests run offline in a few seconds each. Use a tiny random-weight model
(`TinyTarget` from `tests/ml/fakes.py`) and a handful of small images or rows so
SHAP stays fast. Do not load the real CNN in unit tests.

- **`test_explain_image.py`**
  - `explain()` writes each PNG and the `.npz` and meta per explained sample.
    Assert the `sink` received each `Artifact.kind` and that the bytes are a
    non-empty PNG or NPZ. Assert `Observation.artifacts` and `artifact_sha256`
    carry the stable keys and that each sha256 mirrors the registered
    `Artifact.sha256`.
  - `Observation.center_mass_ratio_clean` and `center_mass_ratio_adv` are floats
    in [0, 1], and `metric_kind == "heuristic"`.
  - `expl_shift` is a float in [0, 1] per sample. With a forced flip the
    aggregate is greater than 0. With no comparable pair the aggregate is `None`
    and the reason is recorded. `expl_shift_n_excluded` counts the zero-norm
    pairs.
  - `ExplainOutput.explainer`, `background_size`, `nsamples`, `shap_version`,
    `summary_text`, and `wall_time_s` are populated.
- **`test_explain_tabular.py`**
  - `TreeExplainer` is chosen for a tree model, `KernelExplainer` for a non-tree
    model. Bar, beeswarm, and force artifacts are written with a shared feature
    order. `center_mass_ratio_*` stay `None`. `top_features_*` are populated.
    `expl_shift` is computed the same way.
- **`test_summary.py`**
  - The summary is deterministic for fixed aggregates, carries every denominator,
    and ends with the fixed non-causal sentence.
- **`test_interpret.py`**
  - Each of I1 through I6 fires on a synthetic set built to trip it, and each
    statement's `basis` ids all exist in the input. Every statement has
    `kind == "inferred"`.
- **`test_recommend.py`**
  - Each of R1 through R7 (and R1b, R3t where applicable) fires on a synthetic
    measurement and observation set built to trip exactly that trigger, and the
    resulting `triggered_by` cites the right ids.
  - On a flat set (no degradation) only R7 fires.
  - Every emitted candidate has `status == "candidate"` and
    `validation == "not evaluated"`. The ranking is stable.
- **`test_narrative.py`**
  - With `PYTHIA_*` unset or `llm_narrative == False`, `narrate()` returns the
    recommendations unchanged and sets no `narrative`.
  - With a fake backend injected and the env set, `narrate()` fills `narrative`
    and sets `narrative_source == "llm"`, runs the input and output through the
    guardrails (a planted secret in the output is scrubbed, a planted injection
    in the prompt is caught), and passes the numeric and banned-word
    post-checks. A narrative that introduces a new number or a banned word is
    rejected and `narrative_source` stays `"rules"`.
  - The narrative introduces no new `triggered_by` id and changes no `title`,
    `rationale`, `status`, or `validation`.
- **`test_ml_findings.py`**
  - `derive_severity` returns critical, high, medium, and low on the boundary
    cases of spec 15.5, from the first-success ε and the ASR only.
  - `project_finding_ml` fills `finding_type="adversarial_ml"`,
    `source_tool="redsim.ml/<attack_id>"`, `status="open"`, the measurement-only
    description, and a `schema_blob["ml"]` that recomputes the same severity. A
    projection that disagrees with the record fails the test.
- **verify-loop coverage** (extending `tests/test_verify.py`)
  - The ART estimator is wrapped with the chosen preprocessor. The verify run
    reuses the baseline indices and seed. ΔMRI is computed only when the
    preconditions hold, and it is refused when `settings_hash` or
    `sample_indices_sha256` differ. The measured delta attaches only to the
    matching recommendation and sets `validation="measured"`.

## 8. Acceptance criteria and definition of done

1. `redsim/ml/explain/base.py` defines `ExplainOutput`, and WS2 and WS4 import it
   without a circular dependency.
2. `explain()` in both modality modules matches the section 4 signature, writes
   the artifacts through the `sink` as `Artifact` rows in S3/MinIO, stores the
   raw arrays as `.npz` plus a JSON meta file, and returns `Observation` rows
   with the heuristic ratios and populated `artifact_sha256`.
3. `expl_shift` is `clamp(1 - cos(phi_clean, phi_adv), 0, 1)` per explained
   sample over the clean-predicted class, aggregated at the reference budget and
   returned with its `n`, its `n_excluded`, and its noise floor. The no-input
   case returns `None` with a recorded reason so WS2 leaves the MRI uncomputed.
4. The SHAP text summary is deterministic, denominator-bearing, ends with the
   non-causal sentence, and is the only explanation content the LLM writer sees.
5. `interpret()` follows spec 14.6 and `recommend()` follows spec 16.2 exactly.
   Every statement and candidate cites existing ids. Every candidate stays
   `status="candidate"`, `validation="not evaluated"`. On a flat set only R7
   fires.
6. `narrate()` is off unless `llm_narrative` and Pythia are configured. When on,
   it goes through the router and the budget, runs `guard_input` and
   `guard_output`, passes the numeric and banned-word post-checks, adds no
   claim, and sets `narrative_source="llm"`.
7. `services/ml_findings.py` derives severity from the ASR and first-success ε
   only, fills the `Finding` fields deterministically, and writes a
   recomputable `schema_blob["ml"]`.
8. `explain.run`, `harden.recommend`, and `verify.replay` are registered Celery
   tasks. Admission is audit-first. The verify loop wraps the ART estimator with
   a preprocessing defense, reuses the baseline slice, computes ΔMRI under the
   preconditions, updates `validation_state`, and attaches the `MeasuredDelta`.
9. No ATLAS code exists. ATLAS is Phase B2 (canonical section 27.2), not built here.
10. `pytest` under `tests/ml/` passes, and every honesty label holds: candidates
    are "candidate / not evaluated", the centre-mass metric is "heuristic", the
    narrative is labelled LLM-generated, and the banned words never appear.

## 9. Effort estimate and special considerations

**Estimate:** about 3 to 3.5 developer-days. The image `explain()` and its
artifact rendering are the bulk (about 1.5 days). The rule and interpret layers
plus the findings projection are about 0.75 day. The narrative, the tabular
path, and the summary are about 0.75 day. The verify-loop ML step is about 0.5
day on top of the existing `verify.replay`. Tests run through all of it.

**SHAP cost on images.** `GradientExplainer` is the slow stage (spec 13.10).
Keep the CNN small, keep the background at 50, keep `explain_k` at 8, explain at
most `2k` samples, and explain at the reference budget only. Cache clean
attributions by `(model_sha256, dataset_revision, sample_index, attack_id, eps,
explainer, nsamples, seed)` so `explain.run` and `verify.replay` reuse them. A
run that exceeds its wall-clock budget fails that Job with the reason, and the
MRI is not computed. Nothing is interpolated.

**Honesty labels are load-bearing.** The `metric_kind="heuristic"` default and
its note, the `status="candidate"` and `validation="not evaluated"` literals,
the LLM-narrative label, and the banned-word list are the contract with the
reviewer. Never set them to anything else, never let the narrative rewrite them,
and never let a recommendation imply it was validated. The centre-mass ratio is
a proxy for attention, not a segmentation. SHAP is sensitivity evidence, not
causal proof. Every statement P3 emits traces to a measurement or observation id.

**A measured delta is not transferable.** A ΔMRI is evidence about this model,
this slice, this defense, and this attack set. Do not carry it into another
campaign, and do not show a past measured delta on a different run. The only
sanctioned gain is a measured ΔMRI at equal settings.

**Determinism.** `TreeExplainer` is deterministic. `GradientExplainer`,
`KernelExplainer`, and `PartitionExplainer` sample. Seed the sampled explainers
from the `seed` argument, and record "SHAP GradientExplainer/DeepExplainer
background sampling (background_size=<n>, nsamples=<n>)" or its Kernel or
Partition equivalent in `Provenance.nondeterminism`. SHAP sampling is not
bit-exact across BLAS builds and thread counts even under a seed. The report
says so.

**ATLAS is Phase B2, not built here.** MITRE ATLAS tagging is specified in the
canonical spec as Phase B2 (section 27.2), so this Phase A phase builds no ATLAS
map, no technique field, and no coverage helper. When B2 lands, the technique
attaches at `Finding.schema_blob.ml.atlas_technique`, stamped from the attack
registry. The filename keeps "atlas" for continuity with the earlier plan set only.
