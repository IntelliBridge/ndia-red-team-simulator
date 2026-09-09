/**
 * Illustrative fixture records. These live under test/ (and back Storybook
 * stories) per spec §6. Every surface that renders them paints the
 * "FIXTURE — illustrative" ribbon. They are NEVER bundled into a production
 * build: the dev-fixtures path is compiled out when NEXT_PUBLIC_REDSIM_ENV=prod.
 *
 * All records are labelled with API-literal values (candidate / inferred /
 * heuristic / measured) and contain no banned words. [spec §6, §14.7, §15.8]
 */
import type {
  AttackInfo,
  Campaign,
  Capabilities,
  CandidateRecommendation,
  Comparison,
  DatasetInfo,
  DefenseInfo,
  Finding,
  Interpretation,
  Measurement,
  ModelTarget,
  MRIRecord,
  Observation,
  Project,
  Provenance,
  AuditVerifyResult,
  LogEntry,
  CostRecord,
  AuthProfile,
} from "@/lib/api-types"

export const DEFAULT_WEIGHTS = { acc: 0.35, asr: 0.25, eps: 0.2, conf: 0.1, expl: 0.1 }

export const capabilities: Capabilities = {
  worker_ml_extra: true,
  scoring_weights: DEFAULT_WEIGHTS,
  llm_narrative: { configured: true, model_id: "EleutherAI/pythia-1.4b" },
  modalities: { image: true, tabular: true, text: false, detection: false },
  phase_b_reasons: {
    carlini_wagner: "Phase B: high-iteration white-box attack not yet enabled on the worker.",
    endpoint: "Phase B: remote model endpoints are not yet supported.",
    pdf_report: "Phase B: PDF rendering pipeline not yet enabled.",
    export_dataset: "Phase B2: adversarial dataset export not implemented.",
    atlas: "Phase B2: ATLAS coverage mapping not implemented.",
  },
}

export const attacks: AttackInfo[] = [
  {
    id: "fgsm",
    name: "FGSM",
    phase: "A",
    modality: ["image"],
    box: "white",
    requires_gradients: true,
    description: "Fast Gradient Sign Method: single-step evasion along the loss gradient.",
    params_schema: [],
  },
  {
    id: "pgd",
    name: "PGD",
    phase: "A",
    modality: ["image", "tabular"],
    box: "white",
    requires_gradients: true,
    description: "Projected Gradient Descent: iterative bounded evasion.",
    params_schema: [
      { name: "steps", type: "int", default: 40, min: 1, max: 200, description: "Iteration count." },
      { name: "step_size", type: "float", default: 0.01, min: 0.001, max: 0.1, description: "Per-step magnitude." },
    ],
  },
  {
    id: "hopskipjump",
    name: "HopSkipJump",
    phase: "A",
    modality: ["tabular"],
    box: "black",
    requires_gradients: false,
    description: "Decision-based black-box evasion using boundary estimation.",
    params_schema: [
      { name: "max_iter", type: "int", default: 50, min: 1, max: 200, description: "Boundary refinement iterations." },
    ],
  },
  {
    id: "noise_control",
    name: "Benign noise control",
    phase: "A",
    modality: ["image", "tabular"],
    box: "black",
    requires_gradients: false,
    description: "Random noise at matched ε — a benign baseline to separate adversarial effect from noise.",
    params_schema: [],
  },
  {
    id: "carlini_wagner",
    name: "Carlini-Wagner L2",
    phase: "B",
    modality: ["image"],
    box: "white",
    requires_gradients: true,
    description: "Optimization-based minimal-perturbation attack.",
    params_schema: [],
    reason: "Phase B: high-iteration white-box attack not yet enabled on the worker.",
  },
]

export const defenses: DefenseInfo[] = [
  {
    id: "feature_squeezing",
    name: "Feature squeezing",
    phase: "A",
    art_link: "https://adversarial-robustness-toolbox.readthedocs.io/en/latest/modules/defences/preprocessor.html#feature-squeezing",
    params_schema: [{ name: "bit_depth", type: "int", default: 4, min: 1, max: 8, description: "Colour bit depth." }],
  },
  {
    id: "gaussian_augmentation",
    name: "Gaussian augmentation",
    phase: "A",
    art_link: "https://adversarial-robustness-toolbox.readthedocs.io/",
    params_schema: [{ name: "sigma", type: "float", default: 0.1, min: 0.01, max: 1, description: "Noise sigma." }],
  },
  {
    id: "adversarial_training",
    name: "Adversarial training",
    phase: "B",
    params_schema: [],
    reason: "Phase B: training-time defenses require the training worker, not yet enabled.",
  },
]

export const datasets: DatasetInfo[] = [
  {
    id: "vehicles-open-v1",
    name: "Open vehicle imagery",
    modality: "image",
    license: "CC BY 4.0",
    revision: "rev-8a1c4f",
    note: "Bundled demo dataset served by the API.",
  },
  {
    id: "malicious-urls-kaggle",
    name: "Malicious URLs (Kaggle)",
    modality: "tabular",
    license: "CC0 1.0",
    revision: "rev-33be90",
    note: "Bundled demo dataset served by the API.",
  },
  {
    id: "cifar10-ci",
    name: "CIFAR-10",
    modality: "image",
    license: "MIT",
    revision: "rev-ci",
    ci_fixture: true,
    note: "CI fixture — not the demo dataset.",
  },
]

export const models: ModelTarget[] = [
  {
    id: "m-veh-onnx",
    name: "vehicle-classifier-onnx",
    source: "bundled",
    modality: "image",
    format: "onnx",
    status: "available",
    manifest: {
      sha256: "sha256:9f2b7c41ad38e0c5b1aa42d9e77c0f13b8a6d5e4c3f2109876abcdef01234567",
      gradients: true,
      clean_accuracy: { n_correct: 471, n: 500 },
      architecture: "resnet18",
      library_versions: { art: "1.17.1", torch: "2.2.2", onnxruntime: "1.17.3" },
    },
    license_statement: "CC BY 4.0 — bundled sample.",
    dataset_id: "vehicles-open-v1",
    created_at: "2026-08-30T14:12:00Z",
  },
  {
    id: "m-url-torch",
    name: "url-classifier-statedict",
    source: "uploaded",
    modality: "tabular",
    format: "torch_state_dict",
    status: "available",
    manifest: {
      sha256: "sha256:44be90aa11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778",
      gradients: true,
      clean_accuracy: { n_correct: 442, n: 500 },
      architecture: "mlp-3",
      library_versions: { art: "1.17.1", torch: "2.2.2" },
    },
    license_statement: "CC0 1.0.",
    dataset_id: "malicious-urls-kaggle",
    created_at: "2026-09-02T09:40:00Z",
  },
  {
    id: "m-validating",
    name: "vehicle-classifier-v2",
    source: "uploaded",
    modality: "image",
    format: "safetensors_state_dict",
    status: "validating",
    ingest_job_id: "job-771a",
    dataset_id: "vehicles-open-v1",
    created_at: "2026-09-07T22:05:00Z",
  },
  {
    id: "m-refused",
    name: "legacy-pickle-model",
    source: "uploaded",
    modality: "image",
    format: null,
    status: "refused",
    refusal_reason: "pickle_refused: serialized pickle artifacts are not accepted for safety reasons.",
    created_at: "2026-09-05T11:20:00Z",
  },
]

export const campaign: Campaign = {
  run_id: "run-2f9a",
  model_id: "m-veh-onnx",
  model_name: "vehicle-classifier-onnx",
  project: "poc-open-data",
  scanner: "ml.campaign",
  status: "succeeded",
  completeness: "complete",
  settings_hash: "cfg-7c1e9a2b",
  reference_eps: 0.03,
  library_versions: { art: "1.17.1", torch: "2.2.2", shap: "0.45.1" },
  created_at: "2026-09-07T18:30:00Z",
  config: {
    attacks: ["fgsm", "pgd", "noise_control"],
    attack_params: { pgd: { steps: 40, step_size: 0.01 } },
    eps_grid: [0.01, 0.03, 0.1],
    reference_eps: 0.03,
    finding_asr_threshold: 0.2,
    dataset_id: "vehicles-open-v1",
    dataset_revision: "rev-8a1c4f",
    n: 200,
    seed: 1337,
    noise_control: true,
    explain_k: 6,
    llm_narrative: true,
    scoring_weights: DEFAULT_WEIGHTS,
  },
}

export const measurement: Measurement = {
  rows: [
    { family: "clean", n: 200, n_correct: 188, n_clean_correct: 188, n_flipped_from_clean: 0, mean_linf: null, mean_l2: null, wall_time_s: 2.1,
      per_class: [ { label: "car", n: 70, n_correct: 66 }, { label: "truck", n: 66, n_correct: 61 }, { label: "bus", n: 64, n_correct: 61 } ] },
    { family: "evasion", attack: "fgsm", eps: 0.01, n: 200, n_correct: 171, n_clean_correct: 188, n_flipped_from_clean: 17, mean_linf: 0.01, mean_l2: 0.42, wall_time_s: 3.4 },
    { family: "evasion", attack: "fgsm", eps: 0.03, n: 200, n_correct: 132, n_clean_correct: 188, n_flipped_from_clean: 56, mean_linf: 0.03, mean_l2: 1.21, wall_time_s: 3.5 },
    { family: "evasion", attack: "fgsm", eps: 0.1, n: 200, n_correct: 74, n_clean_correct: 188, n_flipped_from_clean: 114, mean_linf: 0.1, mean_l2: 3.9, wall_time_s: 3.6 },
    { family: "evasion", attack: "pgd", eps: 0.01, n: 200, n_correct: 158, n_clean_correct: 188, n_flipped_from_clean: 30, mean_linf: 0.01, mean_l2: 0.39, wall_time_s: 12.8 },
    { family: "evasion", attack: "pgd", eps: 0.03, n: 200, n_correct: 96, n_clean_correct: 188, n_flipped_from_clean: 92, mean_linf: 0.03, mean_l2: 1.11, wall_time_s: 13.1 },
    { family: "evasion", attack: "pgd", eps: 0.1, n: 200, n_correct: 38, n_clean_correct: 188, n_flipped_from_clean: 150, mean_linf: 0.1, mean_l2: 3.7, wall_time_s: 13.4 },
    { family: "control", attack: "noise_control", eps: 0.01, n: 200, n_correct: 186, n_clean_correct: 188, n_flipped_from_clean: 2, mean_linf: 0.01, mean_l2: 0.4, wall_time_s: 1.0 },
    { family: "control", attack: "noise_control", eps: 0.03, n: 200, n_correct: 183, n_clean_correct: 188, n_flipped_from_clean: 5, mean_linf: 0.03, mean_l2: 1.2, wall_time_s: 1.0 },
    { family: "control", attack: "noise_control", eps: 0.1, n: 200, n_correct: 176, n_clean_correct: 188, n_flipped_from_clean: 12, mean_linf: 0.1, mean_l2: 3.8, wall_time_s: 1.1 },
  ],
}

export const mri: MRIRecord = {
  value: 58,
  grade: "C",
  weights: DEFAULT_WEIGHTS,
  dimensions: [
    { key: "acc", label: "Accuracy retention", value: 62, weight: 0.35 },
    { key: "asr", label: "Attack resistance", value: 51, weight: 0.25 },
    { key: "eps", label: "Perturbation tolerance", value: 55, weight: 0.2 },
    { key: "conf", label: "Confidence stability", value: 64, weight: 0.1 },
    { key: "expl", label: "Explanation stability", value: 60, weight: 0.1 },
  ],
  limitations: [
    "Measured only over the declared attack set (fgsm, pgd) and ε grid {0.01, 0.03, 0.1}.",
    "Slice is 200 samples from vehicles-open-v1 rev-8a1c4f; not the full dataset.",
    "Black-box and Phase B attacks were not run and are not reflected in this score.",
  ],
  narrative:
    "Under the declared attack set, accuracy declines steadily as ε increases, with PGD reducing measured accuracy more than FGSM at each budget. The benign noise control remains near the clean baseline, which separates the adversarial effect from random noise.",
  narrative_model_id: "EleutherAI/pythia-1.4b",
}

export const observations: Observation[] = [
  {
    id: "obs-1",
    kind: "image",
    true_label: "truck",
    pred_clean: "truck",
    pred_adv: "car",
    conf_clean: 0.94,
    conf_adv: 0.71,
    center_mass_ratio_clean: 0.38,
    center_mass_ratio_adv: 0.61,
    metric_note: "center_mass_ratio is a heuristic on SHAP magnitude concentration, not a causal measure.",
  },
  {
    id: "obs-2",
    kind: "image",
    true_label: "bus",
    pred_clean: "bus",
    pred_adv: "bus",
    conf_clean: 0.88,
    conf_adv: 0.52,
    no_explanation_reason: "explain_k budget reached before this sample.",
  },
]

export const interpretations: Interpretation[] = [
  { id: "int-1", statement: "PGD crosses the finding threshold at a smaller ε than FGSM for this slice.", label: "inferred", basis: ["m-pgd-0.01", "m-fgsm-0.03"] },
  { id: "int-2", statement: "The benign noise control stays within its noise floor across the ε grid.", label: "inferred", basis: ["m-control-0.1"] },
]

export const recommendations: CandidateRecommendation[] = [
  { id: "rec-1", title: "Preprocessing defense: feature squeezing", detail: "Rule output triggered by evasion findings at reference ε.", label: "candidate", triggered_by: ["find-1"], defense_id: "feature_squeezing", art_link: defenses[0].art_link },
  { id: "rec-2", title: "Input noise augmentation", detail: "Rule output triggered by control-vs-evasion separation.", label: "candidate", triggered_by: ["find-1", "find-2"], defense_id: "gaussian_augmentation" },
]

export const provenance: Provenance = {
  library_versions: { art: "1.17.1", torch: "2.2.2", shap: "0.45.1", numpy: "1.26.4" },
  model_sha256: "sha256:9f2b7c41ad38e0c5b1aa42d9e77c0f13b8a6d5e4c3f2109876abcdef01234567",
  dataset_id: "vehicles-open-v1",
  dataset_revision: "rev-8a1c4f",
  seed: 1337,
  sample_indices_sha256: "sha256:aa11bb22cc33dd44",
  device: "cuda:0",
  hostname: "worker-ml-2",
  nondeterminism: ["cudnn.benchmark=true", "atomic reductions in conv backward"],
}

export const findings: Finding[] = [
  { id: "find-1", run_id: "run-2f9a", attack: "pgd", derived_severity: "high", eps_first_success: 0.01, asr_flipped: 92, asr_clean_correct: 188, status: "open", validation_state: undefined, title: "PGD evasion crosses threshold at ε=0.01", created_at: "2026-09-07T18:33:00Z", created_by: "scanner-a" },
  { id: "find-2", run_id: "run-2f9a", attack: "fgsm", derived_severity: "medium", eps_first_success: 0.03, asr_flipped: 56, asr_clean_correct: 188, status: "open", title: "FGSM evasion crosses threshold at ε=0.03", created_at: "2026-09-07T18:33:10Z", created_by: "scanner-a" },
]

export const comparison: Comparison = {
  kind: "verify",
  changed_variables: [{ name: "defense", a: "none", b: "feature_squeezing" }],
  unchanged_variables: ["dataset_id", "seed", "eps_grid", "attacks", "n"],
  per_dimension_delta: [
    { key: "acc", a: 62, b: 66, delta: 4 },
    { key: "asr", a: 51, b: 63, delta: 12 },
  ],
  per_family_delta: [{ family: "pgd", a_n: 188, b_n: 188, delta: -18 }],
}

export const projects: Project[] = [
  { slug: "poc-open-data", name: "PoC — Open Data", roster: [ { user: "scanner-a", role: "scanner" }, { user: "rem-b", role: "remediator" }, { user: "app-c", role: "approver" } ], daily_llm_budget_usd: 5 },
]

export const authProfiles: AuthProfile[] = [
  { id: "ap-1", name: "Default OIDC", kind: "keycloak" },
]

export const audit: AuditVerifyResult = {
  chain_id: "run:run-2f9a",
  verified: true,
  entries: [
    { seq: 1, ts: "2026-09-07T18:30:00Z", action: "campaign.created", actor: "scanner-a", prev_hash: "0000", hash: "a1b2" },
    { seq: 2, ts: "2026-09-07T18:33:00Z", action: "finding.created", actor: "worker-ml-2", prev_hash: "a1b2", hash: "c3d4" },
    { seq: 3, ts: "2026-09-07T18:34:00Z", action: "score.computed", actor: "worker-ml-2", prev_hash: "c3d4", hash: "e5f6" },
  ],
}

export const logs: LogEntry[] = [
  { ts: "2026-09-07T18:30:01Z", level: "INFO", message: "campaign queued", run_id: "run-2f9a" },
  { ts: "2026-09-07T18:30:05Z", level: "INFO", message: "worker picked up run", run_id: "run-2f9a" },
  { ts: "2026-09-07T18:34:02Z", level: "INFO", message: "score computed", run_id: "run-2f9a" },
]

export const cost: CostRecord = {
  org_id: "org-1",
  today_usd: 1.42,
  budget_usd: 5,
  by_run: [{ run_id: "run-2f9a", usd: 1.42 }],
}

export const runsList = [campaign]
