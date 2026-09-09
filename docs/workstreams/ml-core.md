# Workstream: ML core: targets, ART attacks, eps sweep, SHAP, MRI scoring, rules

Status: merged. PR #8 `feat/ml-core` landed on 2026-09-08 as `ce33d21`. The
pure modules were then completed by wave 1 of the completion plan
(`f8693c2..a99d9cc`) and wired to the worker and the API by PR #22 and wave 2
(`055bdee..bb43bd7`). Wave 3 (`7556b22..58461cc`) added the offline
`redsim ml attack` path, the `ml-campaign` adapter and the opt-in attack
plugin discovery around these modules, and `58461cc` admits PGD by surrogate
transfer on a tabular target at the API. State described here is `main` at
`58461cc`.

Implements the pure-Python ML vertical under `redsim/ml/` per spec sections 9,
12, 13, 14, 15 and 16:

- Targets (`redsim/ml/targets/`): the bundled image target (`vehicles_cnn`,
  `resnet18` or `small_cnn` from the asset manifest), the CIFAR-10 fixture
  target (`cifar10_smallcnn`, fixture only, never a demo target), the tabular
  tree target `url_trees` (alias `url_classifier`) with its build-time PGD
  surrogate, the uploaded-artifact loader (ONNX with onnx2torch conversion and
  recorded argmax agreement, `torch_state_dict`, `safetensors_state_dict`, a
  loader allowlist of `small_cnn` / `smallcnn` / `resnet18`) and the
  `endpoint_stub` that answers `not_implemented`.
- Attacks (`redsim/ml/attacks/`): `fgsm`, `pgd` (L-inf default, L2 option,
  surrogate transfer on tree ensembles with per-feature ε scaling and an ART
  mask for frozen features), `hopskipjump` (decision-based black box on
  tabular) and the `noise_control` control, in a registry that derives
  capability tags (`adversarial_ml`, `family:<family>`, `modality:<domain>`)
  from each adapter's `AttackInfo`.
- Eval and campaign (`eval.py`, `campaign.py`): the ε sweep with default
  grids (L-inf `0.01, 0.03, 0.1`, L2 `0.25, 0.5, 1.0`, reference `0.03`, at
  most three members), denominators on every rate, the binomial
  `control_preserves_accuracy` predicate, attacks that cannot run recorded
  `not_run` and removed from the scored set, the robustness curve JSON and
  PNG, dataset caveats and the `subject_centered` and surrogate-transfer
  limitations, and the shared `TinyTabularTarget` test double.
- Scoring (`scoring.py`): the MRI with the D9 constraints, `FamilyDelta` rows
  that render an absent cell as unavailable rather than zero, and a typed
  `IncompatibleCampaigns` refusal that also guards against mixing modalities.
- Explain (`explain/`): SHAP image and tabular explainers, the
  `PartitionExplainer` fallback for image targets without a torch module, the
  explanation cache, stability metrics and the text summary
  (`shap_summary.txt`).
- Recommend (`recommend/`): the deterministic interpretation rules I1 to I6
  and the recommendation rules, and the Pythia narrative writer that the
  worker parent calls.
- Reporting (`reporting.py`): the six-section Markdown report of spec 14.8
  with the MRI scorecard sub-block and the ΔMRI block, `report.json` as the
  `CampaignRecord` dump, and HTML produced through the shared escaping
  helpers.
- Sandbox (`sandbox.py`, `sandbox_worker.py`): the typed `MlSandboxConfig`
  from `REDSIM_ML_SANDBOX_*`, the per-job work directory, the credential-free
  child environment and the typed result envelope, with `SandboxTimeout`,
  `SandboxKilled` and `EnvelopeInvalid` distinct from a model refusal.
- Errors (`errors.py`): the spec 10.6 failure classes with stable codes.

Tests under `tests/ml/` with `TinyTarget`, `TinyTabularTarget` and the
committed fixtures, no network. The worker task, the admission services and
the routes that drive these modules are described in
[`docs/architecture/ml-vertical.md`](../architecture/ml-vertical.md) and
[`docs/api/v1.md`](../api/v1.md).

Open in this workstream after the completion pass: nothing blocking. The
accepted divergences from the spec (single job per campaign, task names,
report artifact kinds, `usage.{prompt,completion}`, the worker actor, the
inconclusive verify mapping) are recorded in the ML vertical page. Phase B
items (text and detection modalities, KernelSHAP for black-box targets,
adversarial training as an apply step) are excluded from this pass.

Source of truth: docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md.
