/**
 * Types mirroring the FastAPI OpenAPI contract. The API document is the source
 * of truth; there is no generated client. [spec §11 (no bundled rows), §17, §18.6]
 */

export type Role = "viewer" | "scanner" | "remediator" | "approver" | "admin"

export type Modality = "image" | "tabular" | "not_implemented"
export type ModelSource = "bundled" | "uploaded" | "endpoint"
export type ModelFormat = "onnx" | "torch_state_dict" | "safetensors_state_dict"
export type ModelStatus = "registered" | "validating" | "available" | "refused"

export type Phase = "A" | "B"
export type AttackId = "fgsm" | "pgd" | "hopskipjump" | "noise_control" | string

export type RunStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled"
export type Completeness = "complete" | "partial"
export type Severity = "critical" | "high" | "medium" | "low"
export type ValidationState = string // ML wording verbatim from API, e.g. "verified: attack no longer crosses threshold ..."

/** Params schema entry driving generated launcher inputs. [spec §18.2] */
export interface ParamSchemaField {
  name: string
  type: "int" | "float" | "bool" | "enum" | "string"
  default: number | string | boolean
  min?: number
  max?: number
  description: string
  choices?: (string | number)[]
}

export interface AttackInfo {
  id: AttackId
  name: string
  phase: Phase
  modality: ("image" | "tabular")[]
  box: "white" | "black"
  requires_gradients: boolean
  description: string
  params_schema: ParamSchemaField[]
  /** Present when phase === "B": why it is not yet available. */
  reason?: string
}

export interface DatasetInfo {
  id: string
  name: string
  modality: "image" | "tabular"
  license: string
  revision: string
  /** e.g. CIFAR-10 tagged "CI fixture — not the demo dataset". [spec §18.2] */
  ci_fixture?: boolean
  note?: string
}

export interface DefenseInfo {
  id: string
  name: string
  phase: Phase
  art_link?: string
  params_schema: ParamSchemaField[]
  reason?: string
}

export interface ScoringWeights {
  acc: number
  asr: number
  eps: number
  conf: number
  expl: number
}

export interface Capabilities {
  worker_ml_extra: boolean
  scoring_weights: ScoringWeights
  llm_narrative: { configured: boolean; model_id?: string }
  modalities: { image: boolean; tabular: boolean; text: boolean; detection: boolean }
  phase_b_reasons: Record<string, string>
}

export interface ModelManifest {
  sha256: string
  gradients: boolean
  clean_accuracy?: { n_correct: number; n: number }
  architecture?: string
  library_versions?: Record<string, string>
}

export interface ModelTarget {
  id: string
  name: string
  source: ModelSource
  modality: Modality
  format: ModelFormat | null
  status: ModelStatus
  refusal_reason?: string
  ingest_job_id?: string
  manifest?: ModelManifest
  license_statement?: string
  dataset_id?: string
  created_at: string
}

export interface CampaignConfig {
  attacks: AttackId[]
  attack_params: Record<string, Record<string, unknown>>
  eps_grid: number[]
  reference_eps: number
  finding_asr_threshold: number
  dataset_id: string
  dataset_revision: string
  n: number
  seed: number
  noise_control: boolean
  explain_k: number
  llm_narrative: boolean
  scoring_weights: ScoringWeights
}

export interface Campaign {
  run_id: string
  model_id: string
  model_name: string
  project: string
  scanner: "ml.campaign"
  config: CampaignConfig
  status: RunStatus
  completeness?: Completeness
  completeness_reason?: string
  settings_hash: string
  library_versions: Record<string, string>
  created_at: string
  reference_eps: number
}

export interface MeasurementRow {
  family: "clean" | "evasion" | "control"
  attack?: AttackId
  eps?: number
  n: number
  n_correct: number
  n_clean_correct: number
  n_flipped_from_clean: number
  mean_linf: number | null
  mean_l2: number | null
  wall_time_s: number | null
  per_class?: { label: string; n: number; n_correct: number }[]
}

export interface Measurement {
  rows: MeasurementRow[]
}

export interface Observation {
  id: string
  kind: "image" | "tabular"
  true_label: string
  pred_clean: string
  pred_adv: string
  conf_clean: number
  conf_adv: number
  clean_artifact_id?: string
  adv_artifact_id?: string
  shap_clean_artifact_id?: string
  shap_adv_artifact_id?: string
  shap_beeswarm_artifact_id?: string
  center_mass_ratio_clean?: number
  center_mass_ratio_adv?: number
  metric_note?: string
  feature_diff?: { feature: string; original: string; adversarial: string; delta: string; unit?: string }[]
  no_explanation_reason?: string
}

export interface Interpretation {
  id: string
  statement: string
  label: "inferred"
  basis: string[]
}

export interface CandidateRecommendation {
  id: string
  title: string
  detail: string
  label: "candidate"
  triggered_by: string[]
  art_link?: string
  defense_id?: string
  verify?: { validation_state: ValidationState; delta_mri: number; measured: true }
}

export interface MRIRecord {
  value: number
  grade: string
  dimensions: { key: keyof ScoringWeights; label: string; value: number; weight: number }[]
  weights: ScoringWeights
  delta?: { value: number; measured: true }
  reason_unavailable?: string
  limitations: string[]
  narrative?: string
  narrative_unavailable_reason?: string
  narrative_model_id?: string
}

export interface Finding {
  id: string
  run_id: string
  attack: AttackId
  derived_severity: Severity
  eps_first_success: number | null
  asr_flipped: number
  asr_clean_correct: number
  status: string
  validation_state?: ValidationState
  title: string
  created_at: string
  created_by?: string
}

export interface ArtifactRow {
  id: string
  kind: string
  content_type: string
  bytes: number
}

export interface Comparison {
  changed_variables: { name: string; a: string; b: string }[]
  unchanged_variables: string[]
  kind: "verify" | "same_settings_diff_model" | "generic"
  per_dimension_delta?: { key: string; a: number; b: number; delta: number }[]
  per_family_delta?: { family: string; a_n: number; b_n: number; delta: number }[]
  scorecards?: [MRIRecord, MRIRecord]
  incompatible?: { mismatched: string[] }
}

export interface Provenance {
  library_versions: Record<string, string>
  model_sha256: string
  dataset_id: string
  dataset_revision: string
  seed: number
  sample_indices_sha256: string
  device: string
  hostname: string
  nondeterminism: string[]
}

export interface StageFrame {
  type: "stage"
  name: string
  status: "pending" | "running" | "done" | "failed"
}

export interface MlErrorDetail {
  code: string
  message: string
  phase?: Phase
  field?: string
  reasons?: string[]
}

export interface Project {
  slug: string
  name: string
  roster: { user: string; role: Role }[]
  daily_llm_budget_usd: number
}

export interface AuthProfile {
  id: string
  name: string
  kind: string
}

export interface AuditVerifyResult {
  chain_id: string
  verified: boolean
  entries: { seq: number; ts: string; action: string; actor: string; prev_hash: string; hash: string }[]
  broken_at?: number
}

export interface LogEntry {
  ts: string
  level: string
  message: string
  run_id?: string
}

export interface CostRecord {
  org_id: string
  today_usd: number
  budget_usd: number
  by_run: { run_id: string; usd: number }[]
}
