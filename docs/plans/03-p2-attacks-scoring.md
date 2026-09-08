# Phase P2 · Milestones M1/M3/M4/M6 · Features F003/F004 + MRI (v2, redsim substrate)

Status: v2, 2026-09-08. Owner: Dev B (WS2). Wave: Slice 2 (the engine). Critical
path: yes.

Read these first, in order:

1. `docs/plans/00-master-plan.md`, sections 2, 5, and 7.
2. `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`, sections
   12 (attack catalog), 15 (MRI), and 10 (job and worker flow). These are
   authoritative.
3. `specs/003-evaluation-profiles/spec.md` (F003, the campaign configuration)
   and `specs/004-run-management/spec.md` (F004, the run lifecycle).
4. The frozen code: `redsim/ml/attacks/base.py`, `redsim/ml/schema.py`,
   `redsim/ml/targets/base.py`, `redsim/workers/job_state.py`.

This phase builds the attack and scoring half of a campaign on the redsim
platform. It supersedes the deleted `redsim/` plan. Every path below is a real
redsim path.

---

## 1. Objective

Deliver the attack execution and MRI scoring of one campaign:

1. Five ART attack adapters under `redsim/ml/attacks/`, each satisfying the
   `AttackAdapter` protocol in `redsim/ml/attacks/base.py` and registering in one
   `ATTACKS` registry:
   - `fgsm` — `art.attacks.evasion.FastGradientMethod`, image, white-box.
   - `pgd` — `art.attacks.evasion.ProjectedGradientDescent`, image and tabular.
     For tabular the adapter runs PGD against a differentiable **surrogate** and
     scores the result on the real bundled tree model (spec 12.2, 12.9).
   - `hopskipjump` — `art.attacks.evasion.HopSkipJump`, tabular, black-box, no
     surrogate.
   - `noise_control` — benign random noise at the same ε and norm. Family
     `control`. It never creates a Finding (spec 12.4).
2. `redsim/ml/eval.py` — turn clean, adversarial, and control predictions into
   `Measurement` objects, one row per (attack, ε) plus one clean row and the
   control rows (spec 12.5).
3. `redsim/ml/scoring.py` — the five-subscore MRI and the derived Finding
   severity, computed exactly per spec section 15. This is a pure function.
4. `redsim/ml/campaign.py` — assemble the campaign `RunRecord`, write it as a
   sha256 `Artifact`, and project it onto `ml_campaigns.score` and
   `Finding.schema_blob.ml`.

The attack set runs as a **Celery chain**, one `attack.run` Job per attack. It
is not a thread pool. The first job also runs the `sample`, `clean_eval`, and
`control` stages, then every later job reuses those rows (spec 10.3).

Success means the `attack.run` chain produces the measurements, findings, and
artifacts of a campaign, and `score_run(...)` reproduces the MRI record that the
scorecard and severity rules read.

## 2. Scope

### In scope

- `redsim/ml/attacks/{fgsm,pgd,hopskipjump,noise_control}.py` and the `ATTACKS`
  registry that lists them.
- `redsim/ml/eval.py`: build `Measurement` objects from a `Sample` and
  predictions, for clean, evasion, and control families.
- `redsim/ml/scoring.py`: `score_run(...)` and `severity_for(...)`, per spec 15.
- `redsim/ml/campaign.py`: the `RunRecord` assembly, its sha256 `Artifact`, and
  the projection onto `ml_campaigns.score` and `Finding.schema_blob.ml`.
- The ε sweep `{0.01, 0.03, 0.1}` with `reference_eps = 0.03`, the robustness
  curve inputs, and the benign control at every ε (spec 12.3, 12.4).
- The tabular surrogate fit and the per-feature ε scaling for the tabular PGD
  row (spec 12.9), and the query counter for HopSkipJump (spec 12.5).
- The `redsim.attack_run` task body (`redsim/workers/tasks/attack.py`) that drives
  the chain and calls `eval.py` and `campaign.py`.
- Finding creation by ASR threshold and derived severity (spec 12.6, 15.5).
- Unit tests under `tests/ml/` for attacks, evaluation, scoring, and severity.

### Out of scope

- The `Target` implementations, `art_classifier()`, and `torch_model()` (WS1,
  F002). P2 consumes the `Target` protocol only.
- SHAP, `expl_shift`, and the `S_expl` subscore (WS3, P3). P2 leaves `S_expl`
  absent. See section 4 and the note below on why the MRI is then not computed.
- The **score stage** call site. `scoring.py` is P2 code, but the score stage
  that runs it lives in the `explain.run` task (WS3), because the MRI is written
  only once all five subscores exist (spec 10.2, 10.3). P2 delivers and tests
  the pure function.
- The interpretation and recommendation rules and the Pythia writer (WS3, P3).
- The admission service, routers, RLS, and audit wiring (WS4, F004 API side).
  P2 assumes admission already wrote the audit row and the Run and Job rows.
- The sandbox child process and model loading (WS0/WS1, D2). P2 runs inside the
  child but does not own it.
- Datasets upload, Croissant, and ATLAS export (dropped in consolidation, master
  section 6).

## 3. Prerequisites and dependencies

### Must exist before P2 integrates

- `redsim/ml/schema.py` widened per spec 5.3 and 12.5. P2 needs the new
  `Measurement` fields `n_clean_correct`, `attack_success_rate`, `conf_gap_mean`,
  `conf_gap_n`, `queries_mean`, `pert_first_success_mean`, `pert_first_success_n`,
  and the aggregate `expl_shift_mean` and `expl_shift_n` on the reference-ε row.
  `RunConfig` widens to an attack set, an ε grid, and the MRI weight vector
  (F003). These are WS0 schema work. P2 codes against the widened shapes and
  raises a schema note rather than editing the frozen contract locally.
- `redsim/ml/attacks/base.py`: the `AttackAdapter` protocol and `AttackOutput`
  dataclass. Present and frozen.
- `redsim/ml/targets/base.py`: the `Target` protocol and `Sample` dataclass.
  Present and frozen. P2 uses `target.art_classifier()`, `target.predict_proba`,
  `target.torch_model()` for the tabular surrogate fit, and `target.manifest()`
  for the perturbable-feature list and the surrogate record.
- `redsim/registry.py`: the generic `Registry[T]` with duplicate-id detection
  (spec 12.1).
- `redsim/workers/job_state.py`: `set_job_status` is the only writer of
  `Job.status`. P2 never assigns `Job.status` directly.
- The `ml_campaigns` table and the `Artifact` kinds `ml.run_record`, `ml.score`,
  `ml.curve`, `ml.adv_slice`, and `ml.flip_matrix` (WS0, migration
  `0010_ml_vertical`).

### The one value from P3

- `S_expl` needs `expl_shift_mean` from P3's SHAP stage (spec 13.5).
- P2 builds and tests everything with `S_expl` absent. In that state
  `score_run` does **not** compute the MRI. It records the four available
  subscores with their denominators and the text
  `"MRI not computed: explanation stability unavailable (explain stage not run)"`.
- Weights are **never** renormalised over the four present dimensions. That is
  the spec rule (spec 15.4). Renormalising would make the number look identical
  while being incomparable with any five-dimension MRI.
- When P3 lands, no P2 signature changes. The score stage passes the real
  `expl_shift_mean`, `S_expl` re-enters at weight 0.10, and the MRI is written.

### Third-party libraries

- `adversarial-robustness-toolbox` (ART): `FastGradientMethod`,
  `ProjectedGradientDescent`, `HopSkipJump`. Wrap the target through
  `target.art_classifier()` for white-box, and around `predict` for HopSkipJump.
- `numpy` for perturbation, norm, and control-noise math.
- `scikit-learn` or a small torch MLP for the tabular PGD surrogate.
- `torch` and `xgboost` are pulled in by the target, not by P2 directly.

## 4. Interfaces consumed and exposed

### Consumed

- `Target` protocol: `art_classifier()`, `predict_proba(x)`, `torch_model()`,
  `manifest()`, `info()`.
- `Sample`: `x` (float32 in `[0, 1]`, NCHW for images), `y` (int labels),
  `indices`, `class_names`.
- `Registry[T]` from `redsim/registry.py`.
- Schema models: `AttackInfo`, `ParamSpec`, `Measurement`, and the widened
  `RunConfig`.

### Exposed

**The `ATTACKS` registry** (within `redsim/ml/attacks/`):

```python
from redsim.ml.attacks import ATTACKS      # Registry[AttackAdapter]
# ATTACKS.get(id), .maybe_get(id), .ids(), .items(), iteration
```

Registered ids: `fgsm`, `pgd`, `hopskipjump`, `noise_control`. Each module
constructs its adapter and registers it under the capability tags
`adversarial_ml` and `explainability` (spec 12.1). `redsim/ml/attacks/__init__.py`
imports the modules so importing `ATTACKS` registers them all.

**The `AttackAdapter` surface** (per `redsim/ml/attacks/base.py`):

```python
adapter.id                                       # "fgsm" | "pgd" | "hopskipjump" | "noise_control"
adapter.info() -> AttackInfo                     # id, name, domain, family, params_schema, references
adapter.resolve_params(params) -> dict           # defaults, coercion, ValueError on out-of-range → HTTP 422
adapter.run(target, x, y, params, seed) -> AttackOutput
```

`resolve_params` is the single guard on parameter bounds. Admission calls it and
the worker calls it again before running, so a stale client cannot widen a bound
(spec 12.1).

**Scoring** (`redsim/ml/scoring.py`, exact signatures):

```python
def score_run(measurements: list[Measurement],
              observations: list[Observation],
              settings: ScoringSettings) -> MRIRecord: ...

def severity_for(finding_row: dict,
                 settings: ScoringSettings) -> Severity | None: ...
```

`score_run` is the pure MRI function of spec 15 (`redsim.ml.scoring.compute_mri`
in the spec text). It reads the campaign weights, `eps_grid`, `reference_eps`,
and `finding_asr_threshold` from `settings`. It returns an `MRIRecord` (spec
5.6) with `mri`, `grade`, `completeness`, `missing`, the five `subscores` with
denominators, the `per_attack` breakdown, `weights`, `settings_hash`, and the
grade `reading`. `severity_for` maps one attack's per-ε table to a `Severity`
(`redsim/schema.py`) by the rules in spec 15.5. It never sets severity by hand
and never writes `Finding.status`.

**Evaluation** (`redsim/ml/eval.py`, new; the `attack.run` task consumes it):

```python
def measure_clean(target, sample, wall_time_s) -> Measurement: ...
def measure_evasion(target, sample, out, attack_id, eps, params, wall_time_s) -> Measurement: ...
def measure_control(target, sample, out, eps, wall_time_s) -> Measurement: ...
```

### Measurement id convention (spec 12.3, 12.4)

- Clean family: `"m.clean"`, `family = "clean"`, `attack_id = None`. Computed
  once per campaign by the first attack job.
- Evasion family: `"m.evasion.<attack_id>.eps<ε>"`, `family = "evasion"`, one
  row per (attack, ε). Example: `"m.evasion.fgsm.eps0.03"`.
- Control family: `"m.control.noise.eps<ε>"`, `family = "control"`,
  `attack_id = "noise_control"`. Computed once per (norm, ε) by the first job
  and shared by every attack.

These ids are cited by the curve artifact, by `score_run`, and by P3
interpretation. Keep them stable.

## 5. Ordered implementation steps

1. **Registry.** Create the `ATTACKS` registry in `redsim/ml/attacks/__init__.py`
   as `Registry[AttackAdapter]`. Import the four attack modules so registration
   is a side effect of import. Assert no duplicate id.

2. **`noise_control.py` first** (no gradient, simplest). `info()` returns
   `family = "control"`, `domain` per target, one `ParamSpec` for `eps`. `run`
   draws `u ~ Uniform(-eps, +eps)` per element with `np.random.default_rng(seed)`,
   adds it, and clips to the valid range (`[0, 1]` for images, the feature range
   for tabular). L2 uses a random direction scaled to norm ε. For tabular it
   touches only the declared perturbable features. It never returns a Finding.

3. **`fgsm.py`.** `info()` with `family = "evasion"`, `domain = "image"`, one
   `ParamSpec` for `eps` (bounds from the grid), `norm = ∞`. `run` gets the ART
   estimator from `target.art_classifier()`, builds
   `FastGradientMethod(estimator, eps=eps, norm=np.inf)`, calls
   `attack.generate(x=x)`, and returns `AttackOutput`. Record
   `library_versions = {"art": ..., "numpy": ..., "torch": ...}`.

4. **`pgd.py` (image).** `ParamSpec`s: `eps` (from grid), `eps_step = eps / 4`
   (the ratio rule, spec 12.2), `max_iter = 10` (bounds 1–50),
   `num_random_init = 0`, `norm ∈ {∞, 2}`. `run` builds
   `ProjectedGradientDescent(...)` and calls `generate`.

5. **`pgd.py` (tabular surrogate).** When `target.info().domain == "tabular"`,
   fit or load a differentiable surrogate (sklearn `LogisticRegression` in
   `ScikitlearnLogisticRegression`, or a small torch MLP in `PyTorchClassifier`)
   against the target's predicted labels, run PGD on the surrogate, then measure
   every metric on the **real** bundled model. Scale ε per feature over the
   training-split range and map back (spec 12.9). Hold frozen features with the
   ART `mask` or re-impose them after each step. Round integer features and
   measure the post-rounding prediction. Record the surrogate type, sha256, and
   agreement rate in `notes` and note "white-box via surrogate transfer".

6. **`hopskipjump.py`.** Tabular black-box. `ParamSpec`s: `norm ∈ {∞, 2}`,
   `max_iter = 20` (1–50), `max_eval = 1000` (100–5000), `init_eval = 100`,
   `init_size = 100`. `run` wraps the bundled tree model through ART's
   `SklearnClassifier` or `XGBoostClassifier` with a prediction counter, runs
   HopSkipJump, and records `queries_mean`. No surrogate. Success at ε is defined
   by thresholding the achieved perturbation norm (spec 15.1).

7. **Norm helper.** Add a private `_norms(x, x_adv) -> tuple[float, float]` that
   computes mean L∞ and mean L2 of the per-sample perturbation. Reuse it in every
   `run` so both norms are always recorded, whatever the attack norm.

8. **Determinism.** Seed `np.random.default_rng(seed)` for the slice and control
   noise, `np.random.seed(seed)` for ART, and `torch.manual_seed(seed)` before
   each attack. Record residual nondeterminism strings on `AttackOutput.notes`
   (`"CPU float32 reductions"`, `"HopSkipJump random initialisation"`) for
   `Provenance.nondeterminism` (spec 12.7).

9. **`redsim/ml/eval.py`.** Implement the three builders.
   - Run `target.predict_proba` on `sample.x` for clean, and on `out.x_adv` for
     evasion and control. Take `argmax` for the predicted label.
   - Set `n`, `n_correct`, `accuracy = n_correct / n`, and `per_class`.
   - Evasion and control: `n_flipped_from_clean` counts samples correct on clean
     but wrong under the perturbation. Set `n_clean_correct` and
     `attack_success_rate = n_flipped_from_clean / n_clean_correct` (spec 12.5).
   - `conf_gap_mean`: per sample `g_i = max(0, max_{j≠y} p_j(x_adv) − p_y(x_adv))`,
     mean over all `n`, so a robust model scores 0 (spec 12.5, 15.1). Set
     `conf_gap_n = n`.
   - Copy `linf_norm_mean` and `l2_norm_mean` from `out`. Copy `queries_mean` for
     HopSkipJump.
   - Clean row: `n_flipped_from_clean`, the norms, and the confidence gap are
     `None`.
   - Set `id`, `family`, `attack_id`, `params` (including `eps` and `norm`), and
     `wall_time_s` per section 4.

10. **`redsim/ml/scoring.py` subscores** (spec 15.2). Each subscore is on 0–100
    and is the unweighted mean over the in-scope attacks. Clamp every ratio to
    `[0, 1]` before scaling.
    - `S_acc` = `100 · mean_a( min_ε acc_adv(a, ε) / acc_clean )`.
    - `S_asr` = `100 · mean_a( 1 − asr(a, ε_ref) )`.
    - `S_eps` = `100 · mean_a( trapz(acc_adv(a, ε) / acc_clean, ε_grid) / (ε_max − ε_min) )`.
      The clean point ε = 0 is drawn but excluded from the integral. A one-point
      grid degenerates to the ratio at that point and records the limitation.
    - `S_conf` = `100 · mean_a( 1 − conf_gap(a, ε_ref) )`.
    - `S_expl` = `100 · mean_a( 1 − expl_shift(a, ε_ref) )`, only when the
      explain stage provided `expl_shift_mean`.

11. **Aggregate and grade** (spec 15.3, 15.5). Compute
    `MRI = round(0.35·S_acc + 0.25·S_asr + 0.20·S_eps + 0.10·S_conf + 0.10·S_expl)`
    with Python round-half-to-even. Store subscores to one decimal. Assign the
    grade band: A `90–100`, B `75–89`, C `60–74`, D `40–59`, F `0–39`. Attach the
    attack-scoped reading from spec 15.5 and the fixed grade sentence. Never emit
    the banned words `"hardened"`, `"harden before fielding"`, `"deployment-ready"`,
    `"not deployment-ready"`, `"certified"`, `"safe"` (spec 15.5, 15.8(iii)).

12. **The MRI-not-computed rule** (spec 15.4). Compute the MRI **only** when all
    five subscores exist. If any is unavailable, set `mri = None`, `grade = None`,
    fill `completeness` and `missing` with the reason, and return the available
    subscores with denominators. Do **not** renormalise the weights. The cases:
    `acc_clean == 0` or `m.clean.n_correct == 0` (S_acc, S_asr, S_eps undefined);
    a missing reference-ε row for some attack (partial run); `explain_k == 0` or
    the explainer failed (S_expl unavailable); any declared attack with no rows
    (partial run). An attack recorded `not_run` for a declared reason is removed
    from the in-scope set before scoring, and the removal is stated on the record.

13. **`severity_for`** (spec 15.5). With the grid sorted ascending, set
    `ε_small = min`, `ε_large = max`, and `ε_mid = ε_ref` when strictly between,
    else the median. Read the first-success ε and the ASR from the finding's
    per-ε table. Return the highest matching band:
    - `critical` — succeeds at `ε ≤ ε_small` with `asr ≥ 0.5`.
    - `high` — `ε ≤ ε_small` with `asr ≥ 0.2`, or `ε_mid` with `asr ≥ 0.5`.
    - `medium` — first success at `ε_mid` and not high, or `ε_small` with
      `asr < 0.2`.
    - `low` — first success only at `ε_large`.
    "Succeeds at ε" means `asr(a, ε) ≥ finding_asr_threshold` (default 0.2).

14. **Finding creation** (spec 12.6). In the `attack.run` task, create at most one
    Finding per attack per campaign when the attack crosses `finding_asr_threshold`
    at any grid ε. Skip the Finding when `n_clean_correct < 10` at the reference
    budget and note "denominator too small for a finding". Fill `severity` from
    `severity_for`, `scanner_finding_id = "ml.<attack_id>"`,
    `source_tool = "redsim.ml/<attack_id>"`,
    `dedup_key = "ml:<model_sha256[:16]>:<attack_id>:<settings_hash[:16]>"`, and
    the full per-ε derivation into `Finding.schema_blob.ml`. Controls never create
    a Finding. Scoring writes `severity`, never `Finding.status`.

15. **`redsim/ml/campaign.py`.** Assemble the `RunRecord` from the measurements,
    findings, the curve, and (later) observations. Write it as a sha256-addressed
    `Artifact` of kind `ml.run_record`. Project it onto `ml_campaigns.score` (the
    `MRIRecord`, kind `ml.score`) and onto each `Finding.schema_blob.ml`. A
    projection that disagrees with the record is a bug (master section 5). Write
    the robustness curve as an `ml.curve` artifact with every point carrying its
    denominator `n`.

16. **The `attack.run` chain** (`redsim/workers/tasks/attack.py`, spec 10.2, 10.3).
    One `attack.run` Job per attack. Inside the job, spawn the sandbox child
    `--stage attack`. If `chain_position == 0`, run `sample`, `clean_eval`
    (`m.clean`), and the benign `control` at every ε, and write `slice.npz`. Then
    run this attack at each ε on the same slice with the same seed. Build the
    measurements through `eval.py`, create the Finding, record the artifacts
    (`ml.adv_slice` per ε within the size cap, `ml.flip_matrix`, `ml.curve`),
    write the attack rows into the campaign record, and enqueue the next attack
    job, or the pre-created `explain.run` when this was the last attack. Route
    every status write through `set_job_status`. On failure, cancel the remaining
    queued chain jobs (`queued → cancelled`) and set `Run.status = failed`.

17. **Tests.** Add the pytest modules of section 7 under `tests/ml/`. Use the
    `TinyTarget` fake in `tests/ml/fakes.py`, tiny arrays, and a tiny model so the
    suite stays well under the sandbox budget.

## 6. Files to create and modify

### Create

- `redsim/ml/attacks/__init__.py` — the `ATTACKS` registry, imports the modules.
- `redsim/ml/attacks/fgsm.py` — `FastGradientMethod` adapter.
- `redsim/ml/attacks/pgd.py` — `ProjectedGradientDescent` adapter, image and
  tabular-surrogate paths.
- `redsim/ml/attacks/hopskipjump.py` — `HopSkipJump` adapter, tabular black-box.
- `redsim/ml/attacks/noise_control.py` — benign-noise control, no gradient.
- `redsim/ml/eval.py` — `measure_clean`, `measure_evasion`, `measure_control`.
- `redsim/ml/scoring.py` — `score_run`, `severity_for`, and the subscore helpers.
- `redsim/ml/campaign.py` — the `RunRecord` assembly, its sha256 `Artifact`, and
  the projections.
- `redsim/workers/tasks/attack.py` — the `redsim.attack_run` task and the chain
  driver (shared with WS4 on the admission side).
- `tests/ml/test_attacks.py`, `tests/ml/test_eval.py`,
  `tests/ml/test_scoring.py`, and fixtures in `tests/ml/fakes.py`.

### Modify

- `redsim/ml/schema.py` — only through the WS0 schema widening (the new
  `Measurement` fields and the widened `RunConfig`). P2 does not edit the frozen
  contract locally. If a field is missing at integration, raise a schema note
  (master section 7).
- No other frozen file. Do not assign `Job.status` outside `set_job_status`.

## 7. Testing and validation

All tests run offline, CPU only, and deterministic (spec 12.7). Use the `ml`
pytest marker where torch, ART, or a surrogate is needed, and the sqlite session
factory from `tests/conftest.py`.

- **`test_attacks.py`.**
  - FGSM and PGD on a tiny random-weight model over small random images:
    `x_adv.shape == x.shape`; every per-sample L∞ perturbation `≤ eps + tol`;
    `x_adv` stays in `[0, 1]`. This is the "perturb within the ε ball" check.
  - `AttackOutput.linf_norm_mean` and `l2_norm_mean` are non-negative and
    `linf_norm_mean ≤ eps + tol`.
  - The same seed twice gives an identical `x_adv`.
  - `resolve_params` fills defaults, coerces an int-like `eps` to float, and
    raises `ValueError` above `max` and below `min`.
  - `noise_control` stays inside the same ε ball with no gradient call, reports
    `family == "control"`, and never returns a Finding.
  - `hopskipjump` records `queries_mean` and a nondeterminism note.
  - A brittle tiny model flips at least one prediction under FGSM at `eps = 0.03`,
    confirmed through `measure_evasion` (`n_flipped_from_clean > 0`).

- **`test_eval.py`.**
  - `measure_clean` ids as `m.clean`, `attack_id is None`,
    `accuracy == n_correct / n`, and `per_class` sums to `n`.
  - `measure_evasion` ids as `m.evasion.fgsm.eps0.03`, sets `attack_id`, copies
    the norms, and computes `n_flipped_from_clean`, `n_clean_correct`, and
    `attack_success_rate` correctly on a crafted prediction set.
  - `measure_control` ids as `m.control.noise.eps0.03`.
  - `conf_gap_mean` is 0 on a robust fixture and positive on a confidently-wrong
    fixture.

- **`test_scoring.py`.**
  - On a fixture measurement set with known numbers, `score_run` returns the
    expected `mri` and `grade`. Include one fixture in each band A–F to pin the
    boundaries and the round-half-to-even rule.
  - `severity_for` thresholds: `ε ≤ ε_small` with `asr ≥ 0.5` → `critical`;
    `ε ≤ ε_small` with `asr == 0.3` → `high`; `ε_mid` with high ASR → `high`; a
    mid-only success → `medium`; a large-ε-only success → `low`.
  - **MRI-not-computed when `S_expl` is absent:** with no `expl_shift_mean`,
    `mri is None`, `grade is None`, `missing` names explanation stability, the
    four available subscores are returned with denominators, and
    `weights` is **not** renormalised (the four present weights still read
    0.35/0.25/0.20/0.10 and do not sum to 1.0). This is the spec 15.4 rule.
  - MRI-not-computed also holds when `acc_clean == 0` and when a reference-ε row
    is missing for some attack.
  - No banned word appears in any grade text, reading, or record field.
  - Determinism: the same measurement list scores identically twice, and the
    stored `MRIRecord` recomputes to the same value.

## 8. Acceptance criteria (Definition of Done)

1. `from redsim.ml.attacks import ATTACKS` registers `fgsm`, `pgd`,
   `hopskipjump`, and `noise_control`; `ATTACKS.ids()` returns them; each
   satisfies the `AttackAdapter` protocol at registration.
2. `fgsm` and image `pgd` produce `x_adv` inside the L∞ ε ball and report both
   norms; `noise_control` stays inside the same ball with no gradient call and
   never creates a Finding.
3. Tabular `pgd` runs on a differentiable surrogate and scores on the real
   bundled model, with the surrogate recorded; tabular `hopskipjump` runs
   black-box and records `queries_mean`.
4. `eval.py` builds `Measurement` objects with the section-4 ids, correct
   accuracies, flip counts, ASR, per-class counts, confidence gap, and norms.
5. `score_run` reproduces the spec 15 math: five subscores with the
   0.35/0.25/0.20/0.10/0.10 weights and the correct round-half-to-even MRI and
   A–F grade. It is a pure function and the stored record recomputes.
6. When `S_expl` is absent, `score_run` sets `mri = None`, states the reason,
   returns the four available subscores with denominators, and does **not**
   renormalise the weights.
7. `severity_for` returns `critical | high | medium | low` per spec 15.5, and no
   banned word appears anywhere in the product output.
8. The `attack.run` chain runs one Job per attack, the first job writes the
   clean and control rows, later jobs reuse them, and every status write goes
   through `set_job_status`. On failure the remaining chain jobs are cancelled.
9. The `RunRecord` is written as a sha256 `Artifact` and projected onto
   `ml_campaigns.score` and `Finding.schema_blob.ml`; the projection matches the
   record.
10. `pytest -m ml` passes for `test_attacks.py`, `test_eval.py`, and
    `test_scoring.py`; `make check` stays green for P2 files; no frozen file is
    edited outside the WS0 schema widening.

## 9. Effort estimate and special considerations

**Effort.** About 2.5 to 3 developer-days: one day for the four adapters and the
registry (the tabular surrogate and HopSkipJump wrapper are the heavy parts),
half a day for `eval.py`, one day for `scoring.py` and `campaign.py` plus tests.
The scoring math and the MRI-not-computed rule are the subtle parts, not the
attacks.

**The Celery chain, not a thread pool.** The v1 plan ran attacks in an in-process
thread pool. That is gone. Attacks run as a Celery chain, one `attack.run` Job
per attack, each in the sandboxed worker child. The first job owns the shared
`sample`, `clean_eval`, and `control` stages and writes `slice.npz`; later jobs
re-fetch it digest-checked and reuse the clean and control rows, so every row is
computed on the same indices. This is the single largest substrate change from
v1.

**Wrapping the target.** Always get the ART estimator through
`target.art_classifier()`. Never build a `PyTorchClassifier` inside P2. That
coupling belongs to WS1 so the attack code stays target-agnostic.

**The score stage is not in `attack.run`.** `scoring.py` is P2 code, but the MRI
is written in the `explain.run` task's score stage, because it needs all five
subscores (spec 10.2, 10.3). P2 delivers and tests the pure `score_run`; WS3
calls it once `S_expl` exists.

**Renormalisation is forbidden.** The most important scoring behaviour is that
`score_run` returns no MRI when `S_expl` is absent, and it does not divide the
four remaining weights by their sum. A renormalised four-dimension number looks
identical to a real MRI while being incomparable with every five-dimension one.
Keep the weight table in one place, validate that it sums to 1.0, and store the
applied weights and the `missing` reasons in every record.

**Determinism and provenance.** Seed numpy, ART, and torch before every attack,
and record residual nondeterminism on `AttackOutput.notes` so the worker folds
it into `Provenance.nondeterminism`. Every `Measurement` must reproduce from
`(model_sha256, dataset_revision, split, indices, attack_id, resolved params,
seed)`, which is what a rerun and a ΔMRI comparison match (spec 12.7, 14).

**Tabular awkwardness.** L∞ budgets on mixed-type tabular data are a standing
limitation. Scale ε per declared feature, freeze categorical columns and the
label, round integer features and measure the post-rounding prediction, and
state all of it in `notes`. Tabular MRIs are never compared with image MRIs
(spec 12.9, 15.8(i)).
