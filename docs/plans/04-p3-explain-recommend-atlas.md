# Phase P3 — Explanation, recommendations & ATLAS

Status: v1, 2026-09-08. Owner: Dev C. Wave: 1 (parallel build).

Read `docs/plans/00-master-plan.md` first, then this file. Build to the shared
contracts in master section 6. This phase owns the `ExplainOutput` dataclass
(master 6.1), the `explain()` interface (master 6.4), the `interpret()` and
`recommend()` interfaces (master 6.5), and the ATLAS mapping.

---

## 1. Objective

Turn a finished attack into evidence and advice. P3 delivers three things:

1. **Explanation.** Run SHAP on the target model. For selected samples, write
   `clean.png`, `adv.png`, `shap_clean.png`, and `shap_adv.png`. Compute the
   `center_mass_ratio_clean` and `center_mass_ratio_adv` heuristic. Build one
   `schema.Observation` per selected sample. Return the whole set plus
   `expl_shift_mean`, the value P2 needs for its explanation-stability
   subscore.
2. **Recommendations.** Read the measurements, observations, and scoring. Emit
   `schema.Interpretation` statements and `schema.CandidateRecommendation`
   candidates by the fixed rules in design spec section 2.5. Every candidate
   cites the measurement that triggered it and keeps its honesty labels.
3. **ATLAS.** Map each attack id to a MITRE ATLAS technique and fill
   `RunRecord.atlas_coverage`.

The whole phase keeps the design spec's honesty invariants. A recommendation is
always `status="candidate"` and `validation="not evaluated"`. The center-mass
metric is always `metric_kind="heuristic"`. SHAP is evidence, not proof.

## 2. Scope

### In scope

- `redsim/explain/base.py` — the `ExplainOutput` dataclass (master 6.1).
- `redsim/explain/shap_image.py` — `explain()` for the CIFAR-10 image target,
  built on `shap.GradientExplainer`.
- `redsim/explain/shap_tabular.py` — `explain()` for the tabular target, built
  on `shap.KernelExplainer`. This path ships behind the tabular target, which
  is a registered stub in the first milestone. Write it to the same interface,
  keep it small, and let it stay dormant until the tabular target is live.
- `redsim/recommend/rules.py` — `interpret()` and `recommend()`.
- `redsim/recommend/narrative.py` — optional LLM rewrite of rule outputs.
- `redsim/atlas.py` — the attack-to-technique map and the coverage helper.
- The pytest modules that cover all of the above.

### Out of scope

- The scoring math (`redsim/scoring.py`) and the `Scoring` model. That is P2.
  P3 reads `Scoring`; it does not compute it.
- The attack run and `AttackOutput`. That is P2. P3 receives `x_adv` as input.
- The target model, weights, and data slice. That is P1. P3 calls
  `target.torch_model()`, `target.art_classifier()`, and reads the `Sample`.
- Pipeline wiring, run-dir creation, and stage order. That is P4 (`runs.py`).
  P3 exposes pure functions that P4 calls.
- The web UI panels. That is P5.

## 3. Prerequisites & dependencies

### Needs (inputs P3 consumes)

- **From P1 (Targets):** a loaded `Target` with `torch_model()` returning the
  `torch.nn.Module` in eval mode, `art_classifier()` returning the ART
  estimator, `predict_proba(x)`, and a `Sample` (`x`, `y`, `indices`,
  `class_names`). SHAP builds its background from `sample.x`.
- **From P2 (Attacks):** the attack output array `x_adv` (float32, `[0,1]`,
  NCHW for images), aligned index-for-index with `sample.x`. Also the
  `Measurement` list and, once available, the `Scoring` block. `interpret()`
  and `recommend()` take `measurements`, `observations`, and `scoring`.
- **From P0 (Schema):** `Observation`, `Interpretation`,
  `CandidateRecommendation`, `Measurement`, `Scoring`, and `RunStore`.

### Provides (outputs P3 exposes)

- `ExplainOutput` back to P4, which stores `observations` on the `RunRecord`
  and hands `expl_shift_mean` to P2's scorer.
- `list[Interpretation]` and `list[CandidateRecommendation]` back to P4.
- `atlas_coverage` and the per-attack technique fields back to P4.

### The P2↔P3 seam — call this out

Master sections 5 and 6.1 define one coordination seam. P2's MRI has an
explanation-stability subscore `S_expl` that consumes `expl_shift_mean` from
P3. The contract:

- `explain()` computes `expl_shift_mean = mean(1 - cosine(SHAP_clean,
  SHAP_adv))` over the **flipped** samples only, and returns it on
  `ExplainOutput`.
- P4 passes that float into `score_run(measurements, expl_shift_mean,
  reference_eps, eps_grid)` (master 6.3).
- Until P3 lands, P2 calls `score_run` with `expl_shift_mean=None` and
  renormalizes its weights. P3 must therefore never make P2 wait: the value is
  a single float on an already-defined struct.
- If no sample flips, there is nothing to average. `explain()` returns
  `expl_shift_mean=0.0` and records a note; P4 and P2 treat `0.0` as "no
  measured shift", not as "perfectly stable". Document this in the docstring so
  P2 reads it the same way.

## 4. Interfaces consumed & exposed

### Exposed — `ExplainOutput` (master 6.1, owned here)

Define in `redsim/explain/base.py` exactly as master 6.1 states:

```python
from dataclasses import dataclass
from redsim.schema import Observation

@dataclass
class ExplainOutput:
    observations: list[Observation]     # artifacts already written to the store
    expl_shift_mean: float              # mean 1 - cosine(SHAP_clean, SHAP_adv) over flipped
    shap_version: str
    background_size: int
    nsamples: int
    wall_time_s: float
```

### Exposed — `explain()` (master 6.4)

Both `shap_image.py` and `shap_tabular.py` expose the same signature:

```python
def explain(target: Target, sample: Sample, x_adv: np.ndarray,
            k: int, seed: int, store: RunStore) -> ExplainOutput: ...
```

Notes on the arguments:

- `k` is `RunConfig.explain_k` (default 8). The function explains up to `k`
  flipped samples and up to `k` not-flipped samples, per design spec 2.4.
- `seed` seeds the explainer sampling so the run is reproducible. Record
  "GradientExplainer sampling" in `Provenance.nondeterminism` upstream.
- `store` is the `RunStore`. Write every PNG through
  `store.record_artifact(name, content, content_type="image/png")`. The
  returned `ArtifactRef.name` (run-relative, e.g.
  `artifacts/obs_003/shap_adv.png`) goes into `Observation.artifacts`, and
  `ArtifactRef.sha256` goes into `Observation.artifact_sha256`.

### Exposed — `interpret()` and `recommend()` (master 6.5)

```python
def interpret(measurements: list[Measurement],
              observations: list[Observation],
              scoring: Scoring) -> list[Interpretation]: ...

def recommend(measurements: list[Measurement],
              observations: list[Observation],
              scoring: Scoring) -> list[CandidateRecommendation]: ...
```

### Exposed — ATLAS

```python
# redsim/atlas.py
ATLAS_BY_ATTACK: dict[str, tuple[str, str]]     # attack_id -> (technique_id, technique_name)

def technique_for(attack_id: str) -> tuple[str, str] | None: ...
def atlas_coverage(attack_ids: Iterable[str]) -> list[str]: ...  # de-duped technique ids
```

### Consumed

- `Target` and `Sample` from `redsim/targets/base.py`.
- `AttackOutput.x_adv` from `redsim/attacks/base.py` (P2 hands over the array).
- `RunStore.record_artifact()` from `redsim/state.py`.
- `Scoring`, `Observation`, `Interpretation`, `CandidateRecommendation`,
  `Measurement` from `redsim/schema.py`.
- `pythia_client` and `guardrails` for the optional narrative.

### Schema fields P3 writes (exact names, do not invent)

`Observation`: `id`, `sample_index`, `true_label`, `pred_clean`, `pred_adv`,
`flipped`, `confidence_clean`, `confidence_adv`, `artifacts`,
`artifact_sha256`, `center_mass_ratio_clean`, `center_mass_ratio_adv`.
Leave `metric_kind` at its default `"heuristic"` and keep the default
`metric_note`.

`Interpretation`: `id`, `statement`, `basis`. Leave `kind` at its default
`"inferred"`.

`CandidateRecommendation`: `id`, `title`, `rationale`, `triggered_by`,
`references`, and, only when the narrative runs, `narrative` and
`narrative_source`. Leave `status` at `"candidate"` and `validation` at
`"not evaluated"`; both are Literal defaults, so do not set them to anything
else.

## 5. Ordered implementation steps

### Step 1 — `explain/base.py`

Define `ExplainOutput` as in section 4. This is a small file; land it first so
P2 and P4 can import the type while the rest of P3 is still in progress.

### Step 2 — `atlas.py`

Fill the mapping and helpers:

```python
ATLAS_BY_ATTACK = {
    "fgsm": ("AML.T0043", "Craft Adversarial Data"),
    "pgd":  ("AML.T0043", "Craft Adversarial Data"),
    # noise_control is a benign control, not an ATLAS technique -> no entry
}
```

`technique_for(attack_id)` returns the tuple or `None`. `atlas_coverage(ids)`
returns the de-duplicated list of technique ids for the attacks that map to
one, in a stable order. P4 uses `technique_for` to set
`AttackInfo.atlas_technique_id` / `atlas_technique_name` (master 6.1) and
`atlas_coverage` to fill `RunRecord.atlas_coverage`. The control has no entry
because it exercises no adversarial technique; that keeps the mapping honest.

### Step 3 — `explain/shap_image.py`: sample selection

- Get clean predictions from `target.predict_proba(sample.x)` and adversarial
  predictions from `target.predict_proba(x_adv)`. Take the argmax for the
  predicted class and the max probability for the confidence.
- A sample **flipped** when its clean argmax differs from its adversarial
  argmax.
- Select up to `k` flipped indices and up to `k` not-flipped indices. Order by
  `sample.indices` for reproducibility; do not shuffle.

### Step 4 — `explain/shap_image.py`: SHAP attribution

- Build the background from the eval slice: take the first `background_size`
  images from `sample.x` (design spec 2.4 says 50). Cap `background_size` at
  the slice size so a 50-image run still works.
- Build `shap.GradientExplainer(target.torch_model(), background_tensor)`. The
  model is already in eval mode (P1 guarantees it).
- Compute SHAP values for the clean and adversarial versions of the selected
  samples. Attribute against the **clean-predicted class** for both, so the
  clean and adversarial maps are comparable (design spec 2.4).
- Keep the raw per-pixel attribution arrays in memory for the shift and the
  center-mass metric before rendering.

### Step 5 — `explain/shap_image.py`: artifacts

For each selected sample, write four PNGs under a per-sample prefix
(`artifacts/obs_<index>/`):

- `clean.png`, `adv.png` — the images, upscaled from 32×32 for the UI.
- `shap_clean.png`, `shap_adv.png` — the attribution maps (matplotlib, no
  interactive backend; render to a bytes buffer, then `record_artifact`).

Store each `ArtifactRef.name` under a stable key in `Observation.artifacts`
(`clean`, `adv`, `shap_clean`, `shap_adv`) and each `ArtifactRef.sha256` under
the same key in `Observation.artifact_sha256`.

### Step 6 — `explain/shap_image.py`: heuristic and shift

- `center_mass_ratio`: the share of total absolute attribution that falls
  inside the central 50% of the image (the middle 16×16 box of a 32×32 image).
  Compute it for the clean map (`center_mass_ratio_clean`) and the adversarial
  map (`center_mass_ratio_adv`). This is a proxy for "attention on the
  subject", not a segmentation. Leave `metric_kind="heuristic"` and keep the
  default `metric_note`; do not relabel it.
- `expl_shift_mean`: for each **flipped** selected sample, flatten its clean
  and adversarial SHAP maps to vectors and compute `1 - cosine(clean, adv)`.
  Average over the flipped samples. Guard against a zero-norm vector (return a
  shift of `0.0` for that sample) and against no flipped samples (return
  `expl_shift_mean=0.0` overall, per the seam contract in section 3).

### Step 7 — `explain/shap_image.py`: build observations

Build one `Observation` per selected sample with the fields listed in
section 4. Assemble `ExplainOutput(observations=..., expl_shift_mean=...,
shap_version=shap.__version__, background_size=..., nsamples=len(selected),
wall_time_s=...)` and return it. Time the whole call for `wall_time_s`.

### Step 8 — `explain/shap_tabular.py`

Mirror the image path with `shap.KernelExplainer` over `target.predict_proba`.
Selection, flip logic, `expl_shift_mean`, and the `Observation` build are the
same. The artifacts differ: write a bar plot and a beeswarm plot instead of
image PNGs, keyed in `artifacts` as `shap_bar` and `shap_beeswarm`. There is no
spatial center-of-mass for tabular features, so leave `center_mass_ratio_clean`
and `center_mass_ratio_adv` as `None` (the schema allows it) and note why. Keep
`expl_shift_mean` so the tabular path feeds P2 the same way.

### Step 9 — `recommend/rules.py`: `interpret()`

Emit `Interpretation` statements grounded in the measurements and scoring. Each
statement cites the ids it rests on in `basis` (measurement ids like
`m.clean`, `m.evasion.fgsm`, `m.control.noise`; observation ids like `o.003`).
Keep the statements factual: report the accuracy drop, the flip count, the
grade. Do not give advice here; advice is `recommend()`'s job. Leave
`kind="inferred"`.

### Step 10 — `recommend/rules.py`: `recommend()`

Implement the design spec 2.5 rules table exactly. Fire each rule from the
measurement values, not from prose:

| Trigger (from the measurements) | Candidate |
|---|---|
| `adv_accuracy < clean_accuracy - 0.20` **and** `noise_control_accuracy ≈ clean_accuracy` | Adversarial training (PGD-based). Rationale cites that random noise did not degrade the model, so the failure is gradient-aligned. |
| `pgd` degrades more than `fgsm` at the same eps | Iterative attacks matter; evaluate at multiple eps and iterations before deployment. |
| mean `center_mass_ratio_adv` drops ≥ 0.15 vs mean `center_mass_ratio_clean` on flipped samples | Investigate reliance on peripheral/background pixels; consider input cropping or augmentation. Marked heuristic in the rationale. |
| any degradation (`adv_accuracy < clean_accuracy`) | Input preprocessing defenses (JPEG compression, spatial smoothing via ART preprocessors) as a cheap first experiment, with the caveat that gradient-masking defenses are often bypassed. |
| always | Rerun with a larger slice and a different seed before drawing conclusions. |

Rules for the rules:

- Every `CandidateRecommendation` sets `triggered_by` to the measurement (or
  observation) ids that fired it. The "always" rule cites the clean
  measurement so it still points at real evidence.
- The `≈` in the first rule means "within a small tolerance", e.g. control
  accuracy within 0.05 of clean. State the tolerance as a named constant.
- The "pgd degrades more than fgsm" rule only fires when both attacks ran at
  the same eps in this run; skip it otherwise.
- The center-mass rule reads the flipped observations, averages the two
  ratios, and only fires when both ratios are present (the tabular path leaves
  them `None`).
- Keep every candidate at `status="candidate"` and
  `validation="not evaluated"`. Add `references` where the spec names a source
  (ART preprocessors, PGD adversarial training). Give each a stable `id`
  (e.g. `r.adv_training`) so P4 and the UI can key on it.
- On a flat measurement set only the "always" rerun rule fires. Test this.

### Step 11 — `recommend/narrative.py`

Optional LLM rewrite of the rule outputs, off by default:

- Read settings with `PythiaSettings.from_env()`. When it returns `None` (any
  of `PYTHIA_BASE_URL`, `PYTHIA_API_KEY`, `REDSIM_LLM_MODEL` missing), return
  the recommendations unchanged. Never raise for a missing gateway.
- Also require the per-run opt-in `RunConfig.llm_narrative`; when it is
  `False`, skip even if the env is set.
- Build a system prompt that forbids new claims: the model rewrites the given
  candidates into prose and may not add a recommendation, a number, or a
  claim. Pass only the rule outputs as the user content.
- Guard the round trip with `guardrails`: `guard_input()` on the assembled
  prompt before the call, `guard_output()` on the returned text after. Both are
  secret-free and fail safe.
- Write the prose into `CandidateRecommendation.narrative` and set
  `narrative_source="llm"`. Never overwrite `title`, `rationale`,
  `triggered_by`, `status`, or `validation`. The rules output stays the source
  of truth; the narrative is a labelled restatement.

### Step 12 — Tests

Write the pytest modules in section 7.

## 6. Files to create / modify

Create:

- `redsim/explain/base.py` — `ExplainOutput`.
- `redsim/explain/shap_image.py` — `explain()` for the image target.
- `redsim/explain/shap_tabular.py` — `explain()` for the tabular target.
- `redsim/atlas.py` — `ATLAS_BY_ATTACK`, `technique_for`, `atlas_coverage`.
- `redsim/recommend/rules.py` — `interpret()`, `recommend()`.
- `redsim/recommend/narrative.py` — `narrate()` (optional LLM rewrite).
- `tests/test_explain_image.py`, `tests/test_recommend.py`,
  `tests/test_narrative.py`, `tests/test_atlas.py`.

Modify:

- `redsim/explain/__init__.py` — replace the one-line stub with re-exports of
  `explain` and `ExplainOutput`.
- No schema changes. `Observation`, `Interpretation`, and
  `CandidateRecommendation` already carry every field P3 needs.

Depends on (do not modify): `redsim/schema.py`, `redsim/state.py`,
`redsim/targets/base.py`, `redsim/attacks/base.py`,
`redsim/recommend/guardrails.py`, `redsim/recommend/pythia_client.py`.

## 7. Testing & validation

All tests run offline in under a few seconds each. Use a tiny random-weight
model and a handful of small images so SHAP stays fast; do not load the real
CNN in unit tests.

- **`test_explain_image.py`**
  - `explain()` writes the four PNGs (`clean.png`, `adv.png`, `shap_clean.png`,
    `shap_adv.png`) per selected sample. Assert each artifact path exists under
    the run dir and is a non-empty PNG.
  - It returns `Observation` objects with `center_mass_ratio_clean` and
    `center_mass_ratio_adv` set to floats in `[0, 1]`, `metric_kind ==
    "heuristic"`, and `artifacts` / `artifact_sha256` populated with the four
    keys.
  - `expl_shift_mean` is a float in `[0, 2]` (cosine distance range) computed
    over the flipped samples; with a forced flip it is `> 0`; with no flip it
    is `0.0`.
  - `ExplainOutput.shap_version`, `background_size`, `nsamples`, `wall_time_s`
    are all populated.
- **`test_recommend.py`** (matches design spec section 7)
  - Each rule fires on a synthetic measurement set built to trip exactly that
    trigger, and the resulting `CandidateRecommendation.triggered_by` cites the
    right measurement ids.
  - On a flat set (no degradation), only the "rerun with a larger slice" rule
    fires.
  - Every emitted candidate has `status == "candidate"` and `validation ==
    "not evaluated"`.
  - `interpret()` returns statements whose `basis` ids all exist in the input.
- **`test_narrative.py`**
  - With `PYTHIA_*` unset (and/or `llm_narrative=False`), `narrate()` returns
    the recommendations unchanged and sets no `narrative`.
  - With a fake gateway backend injected and the env set, `narrate()` fills
    `narrative` and sets `narrative_source == "llm"`, and it runs the input
    and output through the guardrails (assert a planted secret in the model
    output is scrubbed, and a planted injection in the prompt is caught).
  - The narrative introduces no new `triggered_by` id and does not change
    `title` or `rationale`.
- **`test_atlas.py`**
  - `technique_for("fgsm")` and `technique_for("pgd")` both return
    `("AML.T0043", "Craft Adversarial Data")`.
  - `technique_for("noise_control")` returns `None`.
  - `atlas_coverage(["fgsm", "pgd", "noise_control"])` returns `["AML.T0043"]`
    (de-duplicated, control excluded).

## 8. Acceptance criteria / definition of done

1. `redsim/explain/base.py` defines `ExplainOutput` with the six fields of
   master 6.1, and P2/P4 import it without a circular dependency.
2. `explain()` in `shap_image.py` matches the master 6.4 signature, writes the
   four PNGs per selected sample through `store.record_artifact`, and returns
   `Observation` objects with the heuristic ratios and populated
   `artifact_sha256`.
3. `expl_shift_mean` is computed as `mean(1 - cosine(SHAP_clean, SHAP_adv))`
   over flipped samples and returned on `ExplainOutput`; the no-flip case
   returns `0.0` with a note.
4. `shap_tabular.py` exposes the same `explain()` signature with bar/beeswarm
   artifacts and a working `expl_shift_mean`.
5. `interpret()` and `recommend()` follow the design spec 2.5 table exactly.
   Every recommendation cites its triggering measurement in `triggered_by` and
   keeps `status="candidate"`, `validation="not evaluated"`.
6. `narrative.py` is off unless `PYTHIA_*` and `RunConfig.llm_narrative` are
   set. When on, it runs through `guardrails`, adds no new claims, and sets
   `narrative_source="llm"`.
7. `atlas.py` maps `fgsm` and `pgd` to `AML.T0043` "Craft Adversarial Data",
   excludes the control, and fills `atlas_coverage`.
8. The pytest modules in section 7 pass; `make check` stays green for P3's
   files.
9. Every honesty label holds: candidates are "candidate / not evaluated", the
   center-mass metric is "heuristic", and the narrative is labelled
   LLM-generated. Nothing in P3 states a causal claim about a failure.

## 9. Effort estimate & special considerations

**Estimate:** ~2 to 2.5 developer-days. The image `explain()` is the bulk
(~1 day with the SHAP tuning). Rules and ATLAS are ~0.5 day. Narrative and
tabular are ~0.5 day. Tests are ~0.5 day.

**SHAP speed on CPU.** `GradientExplainer` is the slow stage. Keep the CNN
small (P1 does), keep the background small (50 images, per design spec 2.4),
and keep `explain_k` at its default 8. Explain at most `2k` samples per run
(`k` flipped + `k` not-flipped). Render PNGs to an in-memory buffer with a
non-interactive matplotlib backend; do not spin up a GUI. Master section 9
already flags SHAP-on-images as a risk and caps the slice at 50 to 500; honor
that. If a run still drags, the mitigation is fewer explained samples, not a
larger background.

**Background size.** Cap `background_size` at the eval-slice size so a
50-image run still builds a valid explainer. Record the actual
`background_size` on `ExplainOutput` so the report states what was used rather
than assuming 50.

**Honesty labels are load-bearing, not decoration.** The `metric_kind =
"heuristic"` default and its `metric_note`, the `status="candidate"` /
`validation="not evaluated"` literals, and the LLM narrative label are the
contract with the reviewer. Never set them to anything else, never let the
narrative rewrite them, and never let a recommendation imply it was validated.
The center-mass ratio is a proxy for attention, not a segmentation, and SHAP is
sensitivity evidence, not causal proof. Every statement P3 emits must be
traceable to a measurement or observation id.

**Determinism.** Seed the explainer sampling from the `seed` argument so a
rerun reproduces the maps. Note "GradientExplainer sampling" as a
nondeterminism source upstream in `Provenance.nondeterminism`; SHAP sampling is
not bit-exact across environments even under a seed.
