# Phase P2 — Attacks & MRI scoring

Status: v1, 2026-09-08. Owner: Dev B. Wave 1 (parallel). Critical path: yes.

Read the master plan first (`docs/plans/00-master-plan.md`), then this file.
Build against the shared contracts in master section 6. This phase delivers the
ART attack adapters and the Model Robustness Index (MRI) scorer.

---

## 1. Objective

Deliver the attack and scoring half of a run:

1. Three ART attack adapters (`fgsm`, `pgd`, `noise_control`) that each satisfy
   the `AttackAdapter` Protocol in `redsim/attacks/base.py`, register in one
   `ATTACKS` registry, and carry their MITRE ATLAS technique.
2. An evaluation step that turns clean and adversarial predictions into
   `Measurement` objects (clean accuracy, adversarial accuracy, flip count,
   per-class counts, perturbation norms).
3. A deterministic MRI scorer (`score_run`) and a severity classifier
   (`severity_for`) that follow hackathon spec section 8 exactly, including the
   renormalization rule when the P3 explanation signal is absent.

Success means P4 can call `ATTACKS.get(id).run(...)`, build measurements, and
call `score_run(...)` to attach a `Scoring` block to a `RunRecord`, with every
number reproducible from the stored config and seed.

## 2. Scope

### In scope

- `redsim/attacks/fgsm.py`, `pgd.py`, `noise_control.py`.
- `redsim/attacks/registry.py` exposing `ATTACKS: Registry[AttackAdapter]`.
- `redsim/eval.py`: build `Measurement` objects from a `Sample` and predictions.
- `redsim/scoring.py`: `score_run(...)` and `severity_for(...)`.
- ATLAS tagging on `AttackInfo` for the evasion attacks (`AML.T0043`).
- The eps grid sweep that feeds `S_eps` and severity thresholds.
- Unit tests for attacks, evaluation, and scoring.

### Out of scope

- The `Target` implementations and their `art_classifier()` / `torch_model()`
  (P1). P2 consumes the Protocol, never a concrete target.
- SHAP and the `expl_shift_mean` value (P3). P2 accepts it as an argument and
  handles `None` by renormalizing weights.
- Interpretation and recommendation rules (P3, `recommend/rules.py`).
- Pipeline orchestration, `run.json` writing, and the HTTP routes (P4).
- Croissant export and ATLAS coverage aggregation on `RunRecord` (P6 / P4).
- Tabular and LLM attacks. Image evasion only for the milestone.

## 3. Prerequisites and dependencies

### Must exist before P2 integrates (from P0)

- `redsim/schema.py` with the P0 additions from master section 6.1:
  - `Scoring` model (`mri`, `grade`, `subscores`, `weights`, `reference_eps`,
    `eps_grid`, `delta_mri`).
  - `AttackInfo.atlas_technique_id` and `AttackInfo.atlas_technique_name`.
  - `Measurement.severity` (`Literal["critical","high","medium","low"] | None`).
  - `RunRecord.scoring` and `RunRecord.atlas_coverage`.
  The current `schema.py` does not yet hold these; P2 codes against the master
  6.1 shapes and must not merge ahead of the P0 schema freeze.
- `redsim/attacks/base.py`: `AttackAdapter` Protocol and `AttackOutput`
  dataclass. Present and frozen.
- `redsim/targets/base.py`: `Target` Protocol and `Sample` dataclass. Present
  and frozen. P2 uses `target.art_classifier()`, `target.predict_proba(x)`, and
  the `Sample` fields `x`, `y`, `indices`, `class_names`.
- `redsim/registry.py`: generic `Registry[T]`. Present and frozen.
- `Measurement` and `ParamSpec` as they already stand in `schema.py`.

### The one value from P3

- `S_expl` needs `expl_shift_mean` from P3's `ExplainOutput` (master 6.1).
- P2 builds and tests everything with `expl_shift_mean=None`. In that state
  `score_run` drops `S_expl` and renormalizes the remaining four weights so
  they sum to 1.0, then records the applied set in `Scoring.weights`.
- When P3 lands, no P2 signature changes. P4 passes the real mean and `S_expl`
  re-enters with weight 0.10. This is the P2 to P3 coupling in master section 5.

### Third-party libraries (design spec 2.1)

- `adversarial-robustness-toolbox` (ART): `FastGradientMethod`,
  `ProjectedGradientDescent`. Wrap the target through `target.art_classifier()`.
- `numpy` for perturbation and norm math.
- CPU `torch` is pulled in by the target, not by P2 directly.

## 4. Interfaces consumed and exposed

### Consumed

- `Target` Protocol: `art_classifier()`, `predict_proba(x)`, plus `info()` for
  the domain.
- `Sample`: `x` (float32 in `[0,1]`, NCHW), `y` (int labels), `indices`,
  `class_names`.
- `Registry[T]` from `redsim/registry.py`.
- Schema models: `AttackInfo`, `ParamSpec`, `Measurement`, `Scoring`.

### Exposed

**Attack registry** (master 6.2):

```python
from redsim.attacks.registry import ATTACKS   # Registry[AttackAdapter]
# ATTACKS.get(id), .maybe_get(id), .ids(), .items(), iteration — never .list()
```

Registered ids: `fgsm`, `pgd`, `noise_control`. Each module constructs its
adapter and calls `ATTACKS.register(...)` at import; `registry.py` imports the
three modules so importing `ATTACKS` registers all three.

**Attack adapter surface** (per `AttackAdapter` Protocol):

```python
adapter.id                                   # "fgsm" | "pgd" | "noise_control"
adapter.info() -> AttackInfo                 # incl. atlas fields + params_schema
adapter.resolve_params(params) -> dict       # defaults, coercion, range check
adapter.run(target, x, y, params, seed) -> AttackOutput
```

**Scoring** (master 6.3, exact signatures):

```python
def score_run(measurements: list[Measurement],
              expl_shift_mean: float | None,
              reference_eps: float,
              eps_grid: list[float]) -> Scoring: ...

def severity_for(measurement: Measurement,
                 eps_small: float, eps_mid: float) -> str:  # critical|high|medium|low
    ...
```

**Evaluation** (new, P2 owns the shape; P4 consumes):

```python
# redsim/eval.py
def measure_clean(target, sample, wall_time_s) -> Measurement: ...
def measure_evasion(target, sample, out: AttackOutput, attack_id, params,
                    wall_time_s) -> Measurement: ...
def measure_control(target, sample, out: AttackOutput, wall_time_s) -> Measurement: ...
```

### Measurement id convention

`Measurement.id` is formed as:

- clean family: `"m.clean"`.
- evasion family: `"m.evasion.<attack_id>"`, for example `"m.evasion.fgsm"` or
  `"m.evasion.pgd"`.
- control family: `"m.control.noise"`.

These ids are cited by P3 interpretation and recommendation `basis` /
`triggered_by` lists and by `score_run` when it reads families, so keep them
stable. Set `Measurement.attack_id` to the attack id for evasion and control,
and `None` for clean.

### ATLAS mapping

- `fgsm` and `pgd`: `atlas_technique_id="AML.T0043"`,
  `atlas_technique_name="Craft Adversarial Data"`.
- `noise_control`: leave both ATLAS fields `None`; the control is not an attack
  technique. P4 aggregates the non-null ids into `RunRecord.atlas_coverage`.

## 5. Ordered implementation steps

1. **Attack registry skeleton.** Create `redsim/attacks/registry.py` with
   `ATTACKS = Registry[AttackAdapter]("attack", protocol=AttackAdapter)`. Import
   the three attack modules at the bottom so registration is a side effect of
   importing `ATTACKS`.

2. **`noise_control.py` first** (no gradient, simplest). Implement `info()`
   returning `AttackInfo(id="noise_control", family="control", domain="image",
   params_schema=[ParamSpec(name="eps", type="float", default=0.03, min=0.0,
   max=0.3, ...)])` with both ATLAS fields `None`. `resolve_params` fills
   `eps=0.03`, coerces to float, rejects out of `[min,max]` with `ValueError`.
   `run` draws uniform noise in `[-eps, +eps]` with a seeded `numpy` generator,
   adds it to `x`, clips to `[0,1]`, and returns `AttackOutput` with `x_adv`,
   `linf_norm_mean`, `l2_norm_mean`, `wall_time_s`, `params`, and
   `library_versions={"numpy": ...}`. No target gradient is touched.

3. **`fgsm.py`.** `info()` with `family="evasion"`, `atlas_technique_id=
   "AML.T0043"`, `atlas_technique_name="Craft Adversarial Data"`, and one
   `ParamSpec` for `eps` (default 0.03, min 0.0, max 0.3, L-infinity).
   `resolve_params` as above. `run` gets the ART estimator from
   `target.art_classifier()`, builds `FastGradientMethod(estimator, eps=eps,
   norm=np.inf)`, calls `attack.generate(x=x)`, and returns `AttackOutput`.
   Record `library_versions={"art": art.__version__}`.

4. **`pgd.py`.** Same shape with three `ParamSpec`s: `eps` (0.03, L-infinity),
   `eps_step` (0.007), `max_iter` (10, type `int`). `run` builds
   `ProjectedGradientDescent(estimator, eps=eps, eps_step=eps_step,
   max_iter=max_iter, norm=np.inf)` and calls `generate`.

5. **Determinism.** Seed `numpy` in `noise_control` from the `seed` argument.
   For FGSM and PGD, set torch and numpy seeds through a small local helper
   before `generate` so repeated runs match under the same seed (design spec
   test 7: "deterministic under seed"). Record any residual nondeterminism as a
   note on `AttackOutput.notes` for provenance.

6. **Norm helpers.** Add a private `_norms(x, x_adv) -> tuple[float, float]`
   that computes mean L-infinity and mean L2 of the per-sample perturbation
   `x_adv - x` flattened per sample. Reuse in all three `run` methods so
   `linf_norm_mean` and `l2_norm_mean` are computed one way.

7. **`redsim/eval.py`.** Implement the three `measure_*` builders:
   - Run `target.predict_proba` on `sample.x` for clean, and on `out.x_adv` for
     evasion and control. Take `argmax` for predicted labels.
   - `n` = slice size, `n_correct` = count where prediction equals `sample.y`,
     `accuracy = n_correct / n`.
   - `n_flipped_from_clean` (evasion and control): count of samples that were
     correct on clean but wrong under the perturbation. Clean measurement sets
     it to `None`.
   - `per_class`: for each label in `sample.class_names`, `{"n": ..,
     "n_correct": ..}` using the true label as the key.
   - `linf_norm_mean` / `l2_norm_mean`: copy from `out` for evasion and control;
     `None` for clean.
   - Set `id`, `family`, `attack_id`, `params`, `wall_time_s` per section 4.

8. **`redsim/scoring.py` subscores.** Implement the five subscores on a 0 to 100
   scale, each the mean over in-scope evasion attacks (hackathon spec 8.2):
   - `S_acc` = 100 * (worst-case `acc_adv` across the eps grid) / `acc_clean`,
     clamped to `[0,100]`. `acc_clean` is the `m.clean` accuracy; `acc_adv` per
     eps is read from the evasion measurements produced across the eps sweep.
   - `S_asr` = 100 * (1 - mean ASR at `reference_eps`). ASR for an evasion
     measurement = `n_flipped_from_clean / clean_correct`, where `clean_correct`
     is `m.clean.n_correct`.
   - `S_eps` = 100 * normalized area under the robust-accuracy vs eps curve:
     trapezoidal integral of `acc_adv(eps)` over `eps_grid`, divided by
     `acc_clean * (max(eps_grid) - min(eps_grid))`, clamped to `[0,100]`. When
     the grid has one point, fall back to `S_eps = S_acc`.
   - `S_conf` = 100 * (1 - clamp(`conf_gap`, 0, 1)), where `conf_gap` is the
     mean of (confidence on the wrong label minus confidence on the true label)
     over flipped samples. eval.py exposes the per-run `conf_gap`; if unavailable
     for a measurement, treat it as 0 and note the omission.
   - `S_expl` = 100 * (1 - `expl_shift_mean`) when the value is not `None`.

9. **Weights and renormalization.** Base weights: `S_acc` 0.35, `S_asr` 0.25,
   `S_eps` 0.20, `S_conf` 0.10, `S_expl` 0.10. When `expl_shift_mean is None`,
   drop `S_expl`, divide the remaining four by their sum (0.90) so they total
   1.0, and put only those four keys in `Scoring.weights`. When it is present,
   record all five. Never mutate a shared dict; build a fresh weights dict.

10. **Aggregate and grade.** `mri = round(sum(weight[k] * subscore[k]))` over the
    applied weights. Grade bands (spec 8.4): A `90-100`, B `75-89`, C `60-74`,
    D `40-59`, F `0-39`. Return `Scoring(mri=..., grade=..., subscores=...,
    weights=..., reference_eps=..., eps_grid=...)`. `subscores` holds every
    computed subscore including any that were dropped from the weighting, so the
    UI can still show `S_expl` as "not scored" when absent — confirm this
    display choice with P5; if they prefer only weighted keys, restrict
    `subscores` to the applied set.

11. **`severity_for`.** Map an evasion measurement to a severity string using
    the eps at which it succeeded and its ASR (spec 8.5). Read `eps` from
    `measurement.params["eps"]`. Compute the measurement ASR as
    `n_flipped_from_clean / measurement.n` (the flip rate over the evaluated
    slice; see the note in section 9 on the denominator). Rules:
    - `critical`: `eps <= eps_small` and `asr >= 0.5`.
    - `high`: (`eps <= eps_small` and `asr >= 0.2`) or (`eps <= eps_mid` and
      `asr >= 0.5`).
    - `medium`: succeeds at `eps <= eps_mid` (ASR below the high thresholds).
    - `low`: succeeds only above `eps_mid`.
    "Succeeds" means at least one flip (`n_flipped_from_clean > 0`). Return the
    highest matching band.

12. **Wire severity into the pipeline path.** `score_run` (or a thin helper P4
    calls) assigns `measurement.severity = severity_for(m, eps_small, eps_mid)`
    for each evasion measurement, using `eps_small = min(eps_grid)` and
    `eps_mid` = the middle grid point. P4 stores the updated measurements on the
    `RunRecord`.

13. **Tests.** Add the pytest modules in section 7. Run under the pinned 3.12
    venv (`make test`), keep the full attack and scoring suite under a few
    seconds by using tiny arrays and a tiny model.

## 6. Files to create and modify

### Create

- `redsim/attacks/registry.py` — `ATTACKS` registry, imports the three modules.
- `redsim/attacks/fgsm.py` — `FastGradientMethod` adapter, ATLAS `AML.T0043`.
- `redsim/attacks/pgd.py` — `ProjectedGradientDescent` adapter, ATLAS `AML.T0043`.
- `redsim/attacks/noise_control.py` — uniform-noise control, no gradient.
- `redsim/eval.py` — `measure_clean`, `measure_evasion`, `measure_control`.
- `redsim/scoring.py` — `score_run`, `severity_for`, subscore helpers.
- `tests/test_attacks.py`, `tests/test_noise_control.py`,
  `tests/test_eval.py`, `tests/test_scoring.py`.

### Modify

- None of P0's frozen files. P2 depends on the P0 schema additions but does not
  edit `schema.py`; if a field is missing at integration, raise it as a schema
  note per master section 7, do not add it locally.

## 7. Testing and validation

All tests offline, CPU only, deterministic (design spec section 7).

- **`test_attacks.py`.**
  - FGSM and PGD on a 1-layer random-weight model over 16 random 3x8x8 images:
    `x_adv` shape equals `x`; every per-sample L-infinity perturbation `<= eps`
    within a small float tolerance; `x_adv` stays in `[0,1]`.
  - `AttackOutput.linf_norm_mean` and `l2_norm_mean` are non-negative and
    `linf_norm_mean <= eps + tol`.
  - Same seed twice gives identical `x_adv` (determinism).
  - `resolve_params` fills defaults, coerces an int-like `eps` to float, and
    raises `ValueError` for `eps` above `max` and below `min`.
  - `info()` returns `atlas_technique_id == "AML.T0043"` for fgsm and pgd.
  - A known-brittle tiny model flips at least one prediction under FGSM at
    `eps=0.03`: build a small model that is easy to fool, confirm
    `n_flipped_from_clean > 0` through `measure_evasion`.

- **`test_noise_control.py`.**
  - Control perturbation stays inside the eps ball: per-sample L-infinity of
    `x_adv - x` `<= eps`.
  - `info().family == "control"` and both ATLAS fields are `None`.
  - Seeded noise is reproducible.

- **`test_eval.py`.**
  - `measure_clean` ids as `m.clean`, `attack_id is None`,
    `accuracy == n_correct / n`, `per_class` sums to `n`.
  - `measure_evasion` ids as `m.evasion.fgsm`, sets `attack_id`, copies norms
    from `AttackOutput`, computes `n_flipped_from_clean` correctly on a crafted
    prediction set.
  - `measure_control` ids as `m.control.noise`.

- **`test_scoring.py`.**
  - On a fixture set of measurements with known numbers, `score_run` returns the
    expected `mri` and `grade`. Include one fixture that lands in each band
    (A through F) to pin the boundaries.
  - `expl_shift_mean=None` drops `S_expl` and renormalizes: assert
    `Scoring.weights` has exactly the four keys `S_acc, S_asr, S_eps, S_conf`
    summing to 1.0 (within tolerance), and the ratio 0.35:0.25:0.20:0.10 is
    preserved.
  - `expl_shift_mean=0.4` restores five weights totalling 1.0 and
    `S_expl == 60.0`.
  - `severity_for` thresholds: a case at `eps <= eps_small` with `asr >= 0.5`
    returns `critical`; `eps <= eps_small` with `asr == 0.3` returns `high`;
    `eps <= eps_mid` with high ASR returns `high`; a mid-only success returns
    `medium`; a large-eps-only success returns `low`.
  - Determinism: the same measurement list scores identically twice.

## 8. Acceptance criteria (Definition of Done)

1. `from redsim.attacks.registry import ATTACKS` registers `fgsm`, `pgd`,
   `noise_control`; `ATTACKS.ids()` returns the three sorted ids.
2. Each adapter satisfies the `AttackAdapter` Protocol at registration (the
   registry's `runtime_checkable` check passes).
3. `fgsm` and `pgd` produce `x_adv` inside the L-infinity eps ball and report
   `linf_norm_mean` / `l2_norm_mean`; `noise_control` stays inside the same ball
   with no gradient call.
4. FGSM flips at least one prediction on the brittle test model.
5. `eval.py` builds `Measurement` objects with the section-4 ids, correct
   accuracies, flip counts, per-class counts, and norms.
6. `score_run` reproduces the hackathon spec 8 math: five subscores with the
   0.35/0.25/0.20/0.10/0.10 weights, the correct MRI aggregate, and the A to F
   grade bands. With `expl_shift_mean=None`, `S_expl` is dropped and
   `Scoring.weights` holds the renormalized four-weight set.
7. `severity_for` returns `critical|high|medium|low` per the spec 8.5 rules.
8. `pytest` passes for `test_attacks.py`, `test_noise_control.py`,
   `test_eval.py`, `test_scoring.py`; `make check` stays green for P2 files.
9. No P0 frozen file is modified.

## 9. Effort estimate and special considerations

**Effort.** About 1.5 to 2 developer-days: half a day for the three adapters and
the registry, half a day for `eval.py`, and half a day for `scoring.py` plus
tests. The scoring math is the subtle part, not the attacks.

**CPU runtime.** FGSM is one gradient step and is fast. PGD at `max_iter=10`
over the default 200-image slice is the heaviest attack; on a laptop CPU expect
seconds, not minutes, with the small CNN from P1. Keep tests on tiny arrays so
the suite stays well under the design spec's 60-second budget.

**Wrapping the target.** Always get the ART estimator through
`target.art_classifier()`. Never build a `PyTorchClassifier` inside P2; that
coupling belongs to P1 so the attack code stays target-agnostic and works for
any future estimator.

**Eps grid sweep.** `S_acc` (worst-case) and `S_eps` (area under curve) both
need `acc_adv` at several eps values. P2 defines the sweep as: for each eps in
`eps_grid`, re-run the evasion attack and build one evasion measurement, then
pass the whole list to `score_run`. `reference_eps` (default 0.03) selects the
measurement used for `S_asr` and headline reporting. Decide with P4 whether the
sweep runs inside `run_pipeline` or inside a P2 helper the pipeline calls; the
scorer itself only consumes the resulting measurements, so it is agnostic. Keep
the grid small (for example `[0.01, 0.03, 0.1]`) to bound PGD cost.

**ASR denominator for severity.** `score_run` computes the aggregate `S_asr`
ASR exactly as `n_flipped_from_clean / m.clean.n_correct`, because it holds the
clean measurement. `severity_for` receives a single measurement (fixed
signature from master 6.3) and cannot see `m.clean`, so it uses the flip rate
over the evaluated slice, `n_flipped_from_clean / measurement.n`, as its ASR.
This is a documented, defensible proxy that differs from the aggregate ASR by
the clean-accuracy factor. If P0/P4 want the two figures identical, the clean
resolution is for `score_run` to assign `measurement.severity` after computing
the exact ASR, and for `severity_for` to stay the unit-testable threshold
mapper. Flag this in the P2 PR so the team confirms the choice.

**Renormalization is the coupling seam.** The single most important P2 behavior
is that `score_run` works and is fully tested with `expl_shift_mean=None` before
P3 lands. Keep the weight table in one place, renormalize by dividing by the
present-weight sum, and always write the applied weights into `Scoring.weights`
so a reader can see which formula produced the MRI.

**Determinism and provenance.** Seed numpy and torch before every attack, and
record any known nondeterminism (for example CPU float32 reductions) on
`AttackOutput.notes` so P4 can fold it into `Provenance.nondeterminism`.
