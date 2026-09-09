// Phase B "LLM probe through Pythia" client (spec 11.6 / 17.4).
//
// Thin typed wrappers over the FastAPI routes in redsim/api/v1/llm.py and the
// LLM branch of POST /v1/models. Auth rides `api()` from "@/lib/api"; nothing
// here duplicates it.
//
// The scorecard types mirror redsim/ml/llm/scorecard.py (LLMProbeScorecard and
// its rows). A probe scorecard is its own record: it carries k / n hit counts
// per (probe, detector) row and NEVER an MRI, grade or subscore (D9).

import { api, ApiError, mlErrorDetail, type ModelTarget } from "@/lib/api";

// ── GET /v1/llm/models ─────────────────────────────────────────────

export type PythiaModel = {
  id: string;
  owned_by?: string;
  name?: string;
};

/** Always 200; `configured: false` with `models: []` when Pythia is not set. */
export type PythiaModelsResponse = {
  configured: boolean;
  gateway_url: string | null;
  gateway_host: string | null;
  persona: string | null;
  default_model: string | null;
  models: PythiaModel[];
  count: number;
  error?: string;
};

export function listPythiaModels(): Promise<PythiaModelsResponse> {
  return api<PythiaModelsResponse>("/v1/llm/models");
}

// ── GET /v1/llm/probes ─────────────────────────────────────────────

export type ProbeStatus = "offline" | "extended" | "excluded";

export type ProbeInfo = {
  id: string;
  module: string;
  short_id: string;
  family: string;
  /** garak tier; 9 marks probes garak itself leaves unranked. */
  tier: number | null;
  goal: string;
  primary_detector: string;
  extended_detectors: string[];
  detector_offline: boolean;
  data_files: string[];
  upstream_licence_note?: string;
  /** Set ids (e.g. "redsim-core") that include this probe. */
  sets: string[];
  status?: ProbeStatus;
  reason?: string;
};

export type ProbeSet = {
  id: string;
  probe_ids: string[];
  n_probes: number;
  n_offline: number;
  n_excluded: number;
};

export type ProbeCatalog = {
  garak_version: string;
  default_probe_set: string;
  hf_detectors_enabled: boolean;
  max_prompts_per_probe: number;
  sets: ProbeSet[];
  probes: ProbeInfo[];
  count: number;
  counts: { offline: number; extended: number; excluded: number };
  /** Status id -> human sentence describing what the status means. */
  statuses: Record<string, string>;
  launch_route: string;
  limitations: string[];
};

export function listProbeCatalog(): Promise<ProbeCatalog> {
  return api<ProbeCatalog>("/v1/llm/probes");
}

// ── POST /v1/models (endpoint_kind: "llm") ─────────────────────────

export type GuardrailMode = "permission_gate_only" | "content_filtered" | "unknown";

export const GUARDRAIL_MODES: readonly GuardrailMode[] = [
  "permission_gate_only",
  "content_filtered",
  "unknown",
] as const;

const GUARDRAIL_LABELS: Record<GuardrailMode, string> = {
  permission_gate_only: "Permission gate only (auth, entitlement, metering)",
  content_filtered: "Content filtered (gateway filters shape the results)",
  unknown: "Unknown (results cannot be attributed to the model alone)",
};

export function guardrailLabel(mode: GuardrailMode | string): string {
  return GUARDRAIL_LABELS[mode as GuardrailMode] ?? mode;
}

export type RegisterLlmTargetBody = {
  source: "endpoint";
  endpoint_kind: "llm";
  project_id: string;
  model_id: string;
  persona: string;
  guardrail_mode: GuardrailMode;
  auth_profile_id: string;
  name?: string;
  /** Defaults server-side to the configured Pythia gateway when omitted. */
  gateway_url?: string;
};

export type RegisterLlmTargetResponse = ModelTarget & Record<string, unknown>;

export function registerLlmTarget(
  body: RegisterLlmTargetBody,
): Promise<RegisterLlmTargetResponse> {
  return api<RegisterLlmTargetResponse>("/v1/models", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ── POST /v1/models/{id}/probes ────────────────────────────────────

export type DetectorMode = "offline" | "hf";

/**
 * All optional; extra keys are refused server-side. Send exactly one of
 * `probe_set` / `probe_ids`, or neither for the default set ("redsim-core").
 */
export type StartProbeRunBody = {
  probe_set?: string;
  probe_ids?: string[];
  /** 1..64, default 16. */
  max_prompts_per_probe?: number;
  seed?: number;
  detector_mode?: DetectorMode;
  /** 0..1 (exclusive of 0), default 0.2. */
  finding_hit_threshold?: number;
};

export type StartProbeRunResponse = {
  run_id: string;
  job_ids: string[];
  status_url: string;
  scorecard_url: string;
  kind: string;
  [key: string]: unknown;
};

export function startProbeRun(
  modelId: string,
  body: StartProbeRunBody = {},
): Promise<StartProbeRunResponse> {
  return api<StartProbeRunResponse>(
    `/v1/models/${encodeURIComponent(modelId)}/probes`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
}

// ── GET /v1/runs/{id}/llm-scorecard ────────────────────────────────

/** One (probe, detector) row: k hits / n evaluated outputs. */
export type LlmDetectorRow = {
  row_id: string;
  detector: string;
  status: "run" | "not_run";
  reason: string | null;
  offline: boolean | null;
  n_evaluated: number;
  /** garak `fails`: the detector fired. */
  n_hits: number;
  /** garak `passed`: the detector did not fire. */
  n_passed: number;
  /** Outputs the detector could not score. */
  n_none: number;
  /** n_hits / n_evaluated; null when n_evaluated == 0. */
  hit_rate: number | null;
  ci_method: string | null;
  ci_confidence: number | null;
  ci_lower: number | null;
  ci_upper: number | null;
};

/** One probe row; its detectors carry the k / n counts. */
export type LlmScorecardRow = {
  probe_id: string;
  short_id: string;
  family: string;
  goal: string;
  tier: number | null;
  tier_name: string | null;
  doc_uri: string | null;
  garak_docs_uri: string | null;
  status: "run" | "not_run" | "failed";
  reason: string | null;
  n_prompts_loaded: number | null;
  n_prompts_after_cap: number | null;
  /** Attempts completed. */
  n_prompts_sent: number;
  n_outputs: number;
  n_outputs_none: number;
  n_outputs_blocked: number;
  detectors: LlmDetectorRow[];
};

/** Probes of one garak module. Deliberately no family-level rate. */
export type LlmScorecardFamily = {
  family: string;
  probes: LlmScorecardRow[];
  n_probes_run: number;
  n_probes_not_run: number;
  n_probes_failed: number;
};

export type LlmUsageSummary = {
  requests?: number;
  responses_ok?: number;
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  responses_with_usage?: number;
  wall_time_s?: number;
  retries?: number;
  retry_after_honoured?: number;
  gateway_blocked?: number;
  http_errors?: Record<string, number>;
  transport_errors?: Record<string, number>;
  models_seen?: Record<string, number>;
  tls_mode?: string;
  cost_cents?: number | null;
  unpriced_model?: boolean | null;
  /** Live payload names (redsim/ml/llm/scorecard.py). */
  n_requests?: number;
  n_responses_ok?: number;
  note?: string | null;
};

/** Mirrors redsim.ml.llm.scorecard.LLMProbeScorecard. No MRI, ever. */
export type LlmScorecard = {
  schema_version: "llm-probe-scorecard-1";
  kind: "llm_probe";
  run_id: string;
  target_id: string;
  model_id: string;
  gateway_host: string | null;
  persona: string | null;
  guardrail_mode: GuardrailMode;
  garak_version: string | null;
  catalog_garak_version: string;
  catalog_sha256: string | null;
  redsim_version: string | null;
  probe_set: string | null;
  /** The live payload writes `probe_ids`; older artifacts wrote `probe_ids_requested`. */
  probe_ids?: string[];
  probe_ids_requested?: string[];
  seed: number;
  generations: 1;
  max_prompts_per_probe: number;
  detector_mode: DetectorMode;
  extended_detectors: boolean;
  eval_threshold: number;
  started_at: string | null;
  finished_at: string | null;
  status: "succeeded" | "failed" | "timed_out" | "cancelled";
  completeness: "complete" | "partial" | "none";
  error: string | null;
  families: LlmScorecardFamily[];
  /** The live payload writes `not_admitted`; older artifacts wrote `excluded_probes`. */
  not_admitted?: string[];
  excluded_probes?: string[];
  models_seen?: Record<string, number>;
  child_status?: string | null;
  expected_garak_version?: string | null;
  usage: LlmUsageSummary;
  limitations?: string[];
  /** name -> sha256 or artifact id; never content. */
  artifacts: Record<string, string>;
};

export type LlmScorecardArtifactMeta = {
  artifact_id: string;
  sha256: string;
  run_status: string;
};

export type LlmScorecardResponse = {
  run_id: string;
  kind: "llm_probe";
  scorecard: LlmScorecard;
  artifact: LlmScorecardArtifactMeta;
  status_url: string;
  artifacts_url: string;
};

export function getLlmScorecard(runId: string): Promise<LlmScorecardResponse> {
  return api<LlmScorecardResponse>(
    `/v1/runs/${encodeURIComponent(runId)}/llm-scorecard`,
  );
}

/** Every probe row across families, in catalog order. */
export function scorecardRows(scorecard: LlmScorecard): LlmScorecardRow[] {
  return scorecard.families.flatMap((f) => f.probes);
}

/** Rows where a detector actually fired at least once. */
export function scorecardHitRows(
  scorecard: LlmScorecard,
): Array<{ probe: LlmScorecardRow; detector: LlmDetectorRow }> {
  return scorecardRows(scorecard).flatMap((probe) =>
    probe.detectors
      .filter((d) => d.status === "run" && d.n_hits > 0)
      .map((detector) => ({ probe, detector })),
  );
}

/**
 * True when the scorecard route answered "not written yet" (409
 * `score_unavailable` while the run is queued/running). Anything else,
 * including 409 `llm_target_required` for a non-probe run, is a real error.
 */
export function isScorecardPending(error: unknown): boolean {
  if (!(error instanceof ApiError) || error.status !== 409) return false;
  return mlErrorDetail(error).code === "score_unavailable";
}

// ── Target classification ──────────────────────────────────────────

type MaybeLlm = {
  modality?: string;
  source?: string;
  detail?: unknown;
  manifest?: unknown;
} | null | undefined;

function _endpointKind(blob: unknown): string | undefined {
  if (!blob || typeof blob !== "object") return undefined;
  const kind = (blob as { endpoint_kind?: unknown }).endpoint_kind;
  return typeof kind === "string" ? kind : undefined;
}

/** True for a registered LLM target (modality "llm" or endpoint_kind "llm"). */
export function isLlmTarget(model: MaybeLlm): boolean {
  if (!model) return false;
  if (model.modality === "llm") return true;
  return (
    _endpointKind(model.detail) === "llm" ||
    _endpointKind(model.manifest) === "llm"
  );
}
