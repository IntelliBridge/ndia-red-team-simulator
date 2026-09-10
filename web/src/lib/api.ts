// Unified API client.
//
// Being replaced by the tRPC layer under web/src/server/trpc/. The response
// types below are the procedure output types and stay (R5); the fetch client
// and the SWR-era helpers go in U14 once every page reads its data through a
// procedure.
//
// A helper gains a marker naming its replacement as that procedure lands, so
// U14 can tell what is still in use from what is only still exported. Only
// upstreamError's counterpart mlErrorDetail carries one today, because runs is
// the only router U1 shipped; U8 adds the rest and marks the helpers it
// retires as it goes.
//
// Auth: the cookie session only. credentials: "include" so the httpOnly
// redsim_api_session rides along, and X-Redsim-CSRF is attached from the
// readable redsim_csrf cookie on every mutating request. Programmatic callers
// (the CLI, CI) talk to the API directly with a bearer and never through here.
//
// X-Redsim-Request-ID is auto-generated per call so the API +
// worker + scanner logs correlate.

import { env } from "@/env";
import type { UpstreamErrorBlock } from "@/lib/trpc/types";

const BASE = env.NEXT_PUBLIC_REDSIM_API_URL;

export const apiBase = BASE;
export const apiWsBase = BASE.replace(/^http/, "ws");

const CSRF_COOKIE = env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE;
const CSRF_HEADER = env.NEXT_PUBLIC_REDSIM_CSRF_HEADER;

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function readCookie(name: string): string | undefined {
  if (typeof document === "undefined") return undefined;
  for (const c of document.cookie.split(";")) {
    const trimmed = c.trim();
    if (trimmed.startsWith(`${name}=`)) {
      return decodeURIComponent(trimmed.slice(name.length + 1));
    }
  }
  return undefined;
}

export function hasCookie(name: string): boolean {
  return readCookie(name) !== undefined;
}

function _newRequestId(): string {
  // Reasonably unique correlation id without pulling in uuid.
  return `req-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string) {
    super(`API ${status}: ${body}`);
    this.status = status;
    this.body = body;
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Redsim-Request-ID": _newRequestId(),
    ...((init.headers as Record<string, string> | undefined) ?? {}),
  };
  // Cookie session only. The session cookie is httpOnly and rides along with
  // credentials: "include"; the csrf cookie is readable and is echoed as the
  // double-submit header on every mutation.
  if (MUTATING.has(method)) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers[CSRF_HEADER] = csrf;
  }
  const resp = await fetch(`${BASE}${path}`, {
    ...init,
    method,
    credentials: "include",
    headers,
  });
  // A 401 on the cookie path usually means the fifteen minute session expired
  // while the tab was idle. Renew it once through the refresh route and retry;
  // a second 401 is a real refusal and surfaces as ApiError.
  const retried = ((init.headers as Record<string, string> | undefined) ?? {})["X-Redsim-Retry"] === "1";
  if (resp.status === 401 && !retried) {
    const { refreshApiSession } = await import("@/components/session-keepalive");
    if (await refreshApiSession()) {
      return api<T>(path, {
        ...init,
        headers: { ...((init.headers as Record<string, string> | undefined) ?? {}), "X-Redsim-Retry": "1" },
      });
    }
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, await resp.text());
  }
  const text = await resp.text();
  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(resp.status, text);
  }
}

export type Run = {
  id: string;
  project_id: string;
  status: string;
  scanner: string | null;
  mode: string;
  created_at: string;
  created_by: string | null;
};

/**
 * One run as `GET /v1/runs/{id}` returns it.
 *
 * Not `Run` with two fields added. `redsim/api/v1/runs.py` builds both bodies
 * from one serializer with per-route switches: the detail route asks for
 * `completed_at` and `stage_table` and leaves `created_by` at its `False`
 * default, and only the list route asks for `created_by`. So the two shapes
 * overlap without one containing the other, and a single type for both would
 * either refuse a real detail body or stop describing the list.
 */
export type RunDetail = Omit<Run, "created_by"> & {
  completed_at: string | null;
  stage_table: Record<string, unknown>;
};

export type FindingSchemaBlob = {
  title?: string;
  description?: string;
  cve?: string;
  target?: string;
  /** The Target row id the finding is about (RedsimFinding.affected_component). */
  affected_component?: string;
  attack_id?: string;
  first_success_eps?: number;
  ml?: MLFindingDetail | null;
  /** LLM probe detail (redsim.services.ml_findings.project_llm_findings); ids and counts only. */
  llm?: { probe_id?: string; detector?: string; n_hits?: number; n_evaluated?: number; goal?: string | null } | null;
};
export type FindingReview = {
  state: "unreviewed" | "dismissed";
  reviewer: string | null;
  reason: string | null;
  at: string | null;
  notes: string | null;
};
export type DefenseConfig = {
  name: string;
  params: Record<string, number | boolean | string>;
};
export type MRIDelta = {
  baseline_run_id: string;
  mri_before: number;
  mri_after: number;
  delta: number;
  delta_subscores: Record<
    "S_acc" | "S_asr" | "S_eps" | "S_conf" | "S_expl",
    number | null
  >;
  delta_acc_clean: {
    before: { n_correct: number; n: number; accuracy: number | null };
    after: { n_correct: number; n: number; accuracy: number | null };
    delta: number | null;
  };
  delta_families: Array<{
    measurement_id: string;
    before: { n_correct: number; n: number; accuracy: number | null };
    after: { n_correct: number; n: number; accuracy: number | null };
    delta: number | null;
  }>;
};
export type MLFindingDetail = {
  attack_id: string;
  attack_name: string;
  family: "evasion";
  norm: "linf" | "l2";
  eps_grid: number[];
  reference_eps: number;
  first_success_eps: number | null;
  asr_at_reference: number;
  asr_by_eps: Record<string, number>;
  threshold: number;
  measurements: Measurement[];
  observations: Observation[];
  interpretation: Interpretation[];
  recommendations: CandidateRecommendation[];
  limitations: string[];
  artifacts: Record<string, string>;
  review: FindingReview;
  verify: {
    run_id: string;
    defense: DefenseConfig;
    outcome: "verified" | "still_vulnerable" | "inconclusive";
    delta: MRIDelta | null;
  } | null;
  explanation_unavailable_reason?: string | null;
  audit?: {
    state: "verified" | "broken" | "pending";
    events?: number;
    entries?: Array<{ id: string; action: string; at: string }>;
  };
};

export type Finding = {
  id: string;
  run_id: string;
  project_id: string;
  severity: string;
  status: string;
  source_tool: string | null;
  /** Verify outcome of a classifier finding; absent on LLM probe findings. */
  validation_state?: string | null;
  dedup_key: string | null;
  schema_blob: FindingSchemaBlob;
};

/**
 * The manifest's clean-accuracy block (`redsim.ml.schema.CleanAccuracy`): the
 * value with its denominator and split. Older records carried a bare number
 * with `clean_n` beside it, so both shapes are accepted.
 */
export type CleanAccuracy = { value: number; n?: number; split?: string };

/** Render a clean accuracy of either shape as text, never as a React child. */
export function formatCleanAccuracy(
  accuracy: number | CleanAccuracy | null | undefined,
  cleanN?: number | null,
): string {
  if (accuracy == null) return "—";
  if (typeof accuracy === "number") {
    return cleanN ? `${accuracy} (n=${cleanN})` : String(accuracy);
  }
  if (typeof accuracy.value !== "number") return "—";
  const parts = [accuracy.n != null ? `n=${accuracy.n}` : null, accuracy.split ?? null].filter(
    (part): part is string => part !== null,
  );
  const shown = Number(accuracy.value.toFixed(4));
  return parts.length ? `${shown} (${parts.join(", ")})` : String(shown);
}

export type TargetMetadata = {
  dataset_id?: string;
  dataset_revision?: string;
  class_names?: string[];
  clean_accuracy?: number | CleanAccuracy;
  clean_n?: number;
  framework_versions?: Record<string, string>;
  gradients?: boolean;
  manifest?: Record<string, unknown>;
  [key: string]: unknown;
};
/** Reading aid on the model card: means over the model's own scorecards (redsim.services.ml_scores). */
export type ScoreSummary =
  | {
      kind: "mri";
      n_campaigns: number;
      mri_mean: number | null;
      subscores_mean: Record<string, number | null>;
      note: string;
    }
  | {
      kind: "llm";
      n_runs: number;
      families: { family: string; n_hits: number; n_evaluated: number; hit_rate: number; n_probes: number }[];
      note: string;
    };

/**
 * The name to show for a model. LLM targets registered before 2026-09-09 were
 * named "<model> via <gateway> (<persona>)"; the gateway is shown as a badge
 * instead, so the suffix is stripped here and only the model id remains.
 */
export function modelDisplayName(m: { name: string; manifest?: Record<string, unknown> }): string {
  const fromManifest = m.manifest && typeof m.manifest.model_id === "string" ? m.manifest.model_id : null;
  const stripped = m.name.replace(/\s+via\s+\S+(\s+\([^)]*\))?\s*$/, "").trim();
  return stripped || fromManifest || m.name;
}

/** The gateway an LLM target is reached through (a host name), for the provider badge. */
export function modelGateway(m: { manifest?: Record<string, unknown> }): string | null {
  const host = m.manifest?.gateway_host;
  return typeof host === "string" && host ? host : null;
}

export type ModelTarget = {
  id: string;
  project_id: string;
  score_summary?: ScoreSummary | null;
  name: string;
  source: "bundled" | "upload" | "endpoint";
  modality: "image" | "tabular" | "llm";
  format:
    | "onnx"
    | "torch_state_dict"
    | "safetensors_state_dict"
    | "sklearn_joblib"
    | "xgboost_json"
    | "endpoint";
  sha256: string | null;
  manifest: TargetMetadata;
  status:
    "registered" | "validating" | "available" | "refused" | "not_implemented";
  refusal_reason?: string | null;
  last_run_id?: string | null;
  reason?: string | null;
  validation?: {
    detected_format?: string;
    input_shape?: number[];
    class_count?: number;
    gradients?: boolean;
    onnx_torch_argmax_agreement?: number | null;
    refusal_reason?: string | null;
    ingest_job_id?: string | null;
  } | null;
  campaign_history?: CampaignHistory[];
};
export type CampaignHistory = {
  run_id: string;
  attacks: string[];
  reference_eps: number;
  status: string;
  settings_hash: string;
  scorecard_available?: boolean;
  created_at: string;
};
export type ParamSpec = {
  name: string;
  type: "float" | "int" | "bool";
  default: number | boolean;
  min?: number;
  max?: number;
  description?: string;
};
export type AttackInfo = {
  id: string;
  name: string;
  domain: "image" | "tabular" | "llm" | "text" | "detection";
  family: "evasion" | "control";
  description: string;
  params_schema: ParamSpec[];
  references: string[];
  phase: "A" | "B";
  access: "white-box" | "black-box";
  requires_gradients: boolean;
  status: "available" | "not_implemented";
  reason?: string;
};
export type DatasetInfo = {
  id: string;
  name: string;
  license: string;
  source_url: string;
  classes: string[];
  size: number;
  format: string;
  revision: string;
  role: "demo" | "ci_fixture";
  reachability: string;
  compatible_modalities: Array<"image" | "tabular" | "llm">;
};
export type DefenseInfo = {
  id: string;
  name: string;
  art_class: string;
  params_schema: ParamSpec[];
  modalities: Array<"image" | "tabular">;
  phase: "A" | "B";
  status: "available" | "not_implemented";
  reason?: string;
};
export type Capabilities = {
  modalities: Record<
    "image" | "tabular" | "llm" | "text" | "detection",
    { status: "available" | "not_implemented"; reason?: string; phase: "A" | "B" }
  >;
  upload_formats: Array<
    "onnx" | "torch_state_dict" | "safetensors_state_dict"
  >;
  pickle_accepted: false;
  architectures: Array<{ id: string; name: string } | string>;
  explainers: Record<string, unknown>;
  defenses: string[];
  llm_narrative: {
    configured: boolean;
    gateway: "pythia";
    model: string | null;
    persona_set: boolean;
    reason?: string;
  };
  worker_ml_extra: boolean;
  sandbox_enabled: boolean;
  scoring_weights?: ScoringWeights;
  endpoint_connector?: {
    status: "available" | "not_implemented";
    reason?: string;
    phase: "A" | "B";
  };
  bundled_models?: Array<{ id: string; name: string; modality: string }>;
  [key: string]: unknown;
};
export type CampaignRequest = {
  attack_ids: string[];
  attack_params?: Record<string, Record<string, number | boolean>>;
  norm?: "linf" | "l2";
  eps_grid: number[];
  reference_eps: number;
  finding_asr_threshold?: number;
  dataset_id: string;
  dataset_revision?: string;
  n_samples?: number;
  seed?: number;
  include_control?: boolean;
  explain_k?: number;
  auto_recommend?: boolean;
  llm_narrative?: boolean;
};
export type ScoringWeights = {
  acc: number;
  asr: number;
  eps: number;
  conf: number;
  expl: number;
};
export type CampaignConfig = CampaignRequest & {
  target_id: string;
  modality: "image" | "tabular" | "llm";
  dataset_split?: string;
  scoring: {
    version: string;
    weights: ScoringWeights;
    severity?: Record<string, number>;
    confidence?: Record<string, number>;
    interpretation?: Record<string, number>;
  };
  defense?: DefenseConfig | null;
  target_snapshot?: Record<string, unknown>;
  attacks?: AttackInfo[];
};
export type Measurement = {
  id: string;
  family: "clean" | "evasion" | "control";
  attack_id?: string | null;
  params: Record<string, number | boolean>;
  n: number;
  n_correct: number;
  accuracy: number;
  n_flipped_from_clean?: number | null;
  n_clean_correct?: number | null;
  attack_success_rate?: number | null;
  pert_first_success_mean?: number | null;
  pert_first_success_n?: number | null;
  conf_gap_mean?: number | null;
  conf_gap_n?: number | null;
  expl_shift_mean?: number | null;
  expl_shift_n?: number | null;
  expl_shift_n_excluded?: number | null;
  expl_shift_noise_floor?: number | null;
  expl_shift_noise_floor_n?: number | null;
  queries_mean?: number | null;
  linf_norm_mean?: number | null;
  l2_norm_mean?: number | null;
  per_class: Record<string, { n: number; n_correct: number }>;
  wall_time_s: number;
  notes: string[];
};
export type Observation = {
  id: string;
  sample_index: number;
  true_label: string;
  pred_clean: string;
  pred_adv: string;
  flipped: boolean;
  confidence_clean: number;
  confidence_adv: number;
  artifacts: Record<string, string>;
  artifact_sha256: Record<string, string>;
  center_mass_ratio_clean?: number | null;
  center_mass_ratio_adv?: number | null;
  metric_kind: "heuristic";
  metric_note: string;
  expl_shift?: number | null;
  top_features_clean?: string[];
  top_features_adv?: string[];
  feature_values_clean?: Record<string, string | number | boolean | null>;
  feature_values_adv?: Record<string, string | number | boolean | null>;
  modality?: "image" | "tabular";
  linf_norm?: number | null;
  l2_norm?: number | null;
  control_pred?: string | null;
  control_confidence?: number | null;
  explanation_unavailable_reason?: string | null;
};
export type Interpretation = {
  id: string;
  statement: string;
  basis: string[];
  kind: "inferred";
};
export type CandidateRecommendation = {
  id: string;
  finding_id?: string;
  title: string;
  rationale: string;
  triggered_by: string[];
  status: "candidate";
  validation: "not evaluated" | "measured";
  measured?: {
    delta_mri?: number;
    delta_asr?: number;
    baseline_run_id?: string;
    verify_run_id?: string;
  } | null;
  references: string[];
  narrative?: string | null;
  narrative_source: "rules" | "llm";
};
export type MRIRecord = {
  run_id?: string;
  mri?: number;
  grade?: string;
  delta?: {
    baseline_run_id: string;
    mri_before: number;
    mri_after: number;
    delta: number;
    delta_acc_clean?: MRIDelta["delta_acc_clean"];
  } | null;
  subscores?: Record<
    "S_acc" | "S_asr" | "S_eps" | "S_conf" | "S_expl",
    number | null
  >;
  per_attack?: Record<string, number>;
  weights?: ScoringWeights;
  reading?: string;
  reference_eps?: number;
  eps_grid?: number[];
  attack_ids?: string[];
  measurements?: Measurement[];
  curve?: RobustnessSeries[];
};
export type CampaignCurvePoint = {
  eps: number;
  accuracy: number;
  n: number;
  n_correct: number;
  n_clean_correct?: number | null;
  n_flipped_from_clean?: number | null;
  asr?: number | null;
};
export type RobustnessSeries = {
  attack_id: string;
  norm: "linf" | "l2";
  eps_grid: number[];
  reference_eps: number;
  clean: Omit<CampaignCurvePoint, "eps">;
  points: CampaignCurvePoint[];
  control: CampaignCurvePoint[];
};
export type CampaignTarget = {
  id: string;
  name: string;
  domain: "image" | "tabular" | "llm";
  status: "available" | "not_implemented" | "refused";
  reason?: string | null;
  metadata: TargetMetadata;
};
export type Campaign = {
  run_id: string;
  project_id: string;
  status: string;
  stage?: string;
  stages_done: string[];
  error?: string | null;
  settings_hash?: string | null;
  config: CampaignConfig;
  target: CampaignTarget;
  attacks: AttackInfo[];
  provenance?: Record<string, unknown> | null;
  measurements: Measurement[];
  observations: Observation[];
  interpretation: Interpretation[];
  recommendations: CandidateRecommendation[];
  limitations: string[];
  reviewer_notes?: string | null;
  score?: MRIRecord | null;
  curve?: RobustnessSeries[];
  findings?: Finding[];
  completeness: "complete" | "partial";
  missing: string[];
  score_status?: { state: "pending" | "unavailable"; reason?: string };
  audit?: { state: "verified" | "broken" | "pending"; events?: number };
};
export type ArtifactRow = {
  id: string;
  sha256?: string;
  kind?: string;
  [key: string]: unknown;
};
export type Comparison = {
  compatible: true;
  mode: "verify_delta" | "side_by_side";
  delta_mri?: number | null;
  delta_dimensions?: Record<string, number>;
  delta_acc_clean?: MRIDelta["delta_acc_clean"];
  delta_families?: Array<{
    family: string;
    before: number | null;
    after: number | null;
    n_before: number;
    n_after: number;
    delta?: number | null;
  }>;
  delta?: null;
  scorecards?: MRIRecord[];
  changed_variables: string[];
  unchanged_variables: string[];
  caveats: string[];
};
export type MlErrorDetail = {
  code?: string;
  message?: string;
  phase?: string;
  field?: string;
  reasons?: string[];
};
export type JobHandle = {
  run_id: string;
  job_ids: string[];
  status_url: string;
};

/**
 * The spec 17.3 envelope carried by a tRPC error, or undefined when there is
 * none (KTD8, R4).
 *
 * Deliberately structural rather than `instanceof`: the same block has to be
 * readable from a live client error, whose data sits under `shape.data`, and
 * from a query the server prefetched and dehydrated, which crosses the RSC
 * boundary as a plain object with no prototype and no stack (KTD4). Every
 * honest state branches on `upstream.code`; nothing branches on message text.
 */
export function upstreamError(error: unknown): UpstreamErrorBlock | undefined {
  const candidate = error as
    | {
        data?: { upstream?: UpstreamErrorBlock };
        shape?: { data?: { upstream?: UpstreamErrorBlock } };
      }
    | null
    | undefined;
  return candidate?.data?.upstream ?? candidate?.shape?.data?.upstream;
}

/** Replaced by {@link upstreamError}; removed with the fetch client in U14. */
export function mlErrorDetail(error: unknown): MlErrorDetail {
  if (error instanceof ApiError) {
    try {
      const parsed = JSON.parse(error.body) as {
        detail?: MlErrorDetail | string;
      };
      return typeof parsed.detail === "object" && parsed.detail
        ? parsed.detail
        : { message: String(parsed.detail ?? error.body) };
    } catch {
      return { message: error.body };
    }
  }
  return { message: String(error) };
}
export function startCampaign(
  modelId: string,
  config: CampaignRequest,
): Promise<JobHandle> {
  return api<JobHandle>(`/v1/models/${encodeURIComponent(modelId)}/attacks`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}
export function deleteModel(modelId: string): Promise<void> {
  return api<void>(`/v1/models/${encodeURIComponent(modelId)}`, {
    method: "DELETE",
  });
}
export function explainFinding(id: string, body: Record<string, unknown> = {}) {
  return api(`/v1/findings/${encodeURIComponent(id)}/explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
export function hardenFinding(id: string, body: Record<string, unknown> = {}) {
  return api(`/v1/findings/${encodeURIComponent(id)}/harden`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
export function verifyFinding(
  id: string,
  defense: string,
  params: Record<string, unknown>,
  recommendationId: string,
) {
  return api(`/v1/findings/${encodeURIComponent(id)}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      defense,
      params,
      recommendation_id: recommendationId,
    }),
  });
}
export function dismissFinding(
  id: string,
  reason: string,
  expectedStatus: string,
) {
  return api(`/v1/findings/${encodeURIComponent(id)}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      status: "false_positive",
      reason,
      expected_status: expectedStatus,
    }),
  });
}
export function patchReviewerNotes(runId: string, notes: string) {
  return api(`/v1/runs/${encodeURIComponent(runId)}/reviewer-notes`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reviewer_notes: notes }),
  });
}
export function compareRuns(runId: string, withId: string) {
  return api<Comparison>(
    `/v1/runs/${encodeURIComponent(runId)}/compare?with=${encodeURIComponent(withId)}`,
  );
}
export function artifactUrl(id: string): string {
  return `${BASE}/v1/artifacts/${encodeURIComponent(id)}`;
}

export type ProjectMembership = {
  id: string;
  slug: string;
  name: string;
  org_id: string;
  daily_llm_budget_cents: number | null;
  role: string;
};

// ── Run cancellation ───────────────────────────────────────────────
// POST /v1/runs/{id}/cancel — admission service emits the audit row
// then flips the run + queued/running jobs to "cancelled". Returns
// {run_id, status, jobs_cancelled}; we don't surface the body to
// callers (the SWR refetch picks up the new status), hence Promise<void>.
export async function cancelRun(runId: string): Promise<void> {
  await api<{ run_id: string; status: string; jobs_cancelled: number }>(
    `/v1/runs/${encodeURIComponent(runId)}/cancel`,
    { method: "POST" },
  );
}

// Run statuses that the cancel endpoint can still act on. A terminal
// run (completed/failed/cancelled) has nothing to revoke, so the UI
// hides the control rather than POST a no-op.
const CANCELLABLE_RUN_STATUSES = new Set(["queued", "running", "pending"]);

export function isCancellable(status: string | undefined | null): boolean {
  return status != null && CANCELLABLE_RUN_STATUSES.has(status);
}

// ── Target deletion ────────────────────────────────────────────────
// DELETE /v1/targets/{id} — admin-gated; service writes the audit row
// before the DB row is removed. Returns {deleted: id}; void to callers.
export async function deleteTarget(targetId: string): Promise<void> {
  await api<{ deleted: string }>(
    `/v1/targets/${encodeURIComponent(targetId)}`,
    { method: "DELETE" },
  );
}

// ── Report downloads ───────────────────────────────────────────────
// These are plain authenticated GETs: the browser sends the
// redsim_api_session cookie (the API CSP-hardens HTML and serves
// json/md as nosniff downloads — see redsim/api/v1/reports.py). They
// mirror the existing HTML-report anchor (apiBase + path), so we expose
// URL builders rather than blob helpers.
/** The report formats of spec 14.8 and 17.1, in the order the UI lists them. */
export const REPORT_EXTS = ["md", "json", "html", "pdf"] as const;
export type ReportExt = (typeof REPORT_EXTS)[number];

export function reportUrl(runId: string, ext: ReportExt): string {
  return `${BASE}/v1/runs/${encodeURIComponent(runId)}/report.${ext}`;
}

/** The Croissant manifest of a run's adversarial dataset export (`GET /v1/datasets/{run_id}`, spec 27.1). */
export function datasetManifestUrl(runId: string): string {
  return `${BASE}/v1/datasets/${encodeURIComponent(runId)}`;
}

// ── Exports inventory (`GET /v1/exports`) ──────────────────────────
// One row per campaign or verify run with the state of its report formats
// and of its adversarial dataset export. Ids, digests, sizes and counts only;
// never a score (spec 15.7). Read through the tRPC `exports` router.

/** One report format as a content-addressed artifact row. */
export type ExportArtifactRef = {
  artifact_id: string;
  kind: string;
  sha256: string;
  size_bytes: number;
  /** `snapshot` when the newest non-archived snapshot names it, else `artifact`. */
  source: "snapshot" | "artifact";
  snapshot_version?: number;
};

export type ExportReports = {
  run_id: string;
  formats: Record<ReportExt, ExportArtifactRef | null>;
  available: ReportExt[];
  missing: ReportExt[];
  snapshot_count: number;
  latest_snapshot: {
    id: string;
    version: number;
    rendered_at: string | null;
    archived: boolean;
  } | null;
  render_in_flight: boolean;
};

export type ExportDatasetStatus = "not_exported" | "queued" | "running" | "exported" | "failed";
export type ExportDatasetBlocker = "not_terminal" | "run_failed" | "fixture_target" | "no_slices";

export type ExportDataset = {
  format: string;
  status: ExportDatasetStatus;
  manifest_artifact_id: string | null;
  manifest_sha256: string | null;
  files: number;
  bytes: number;
  card: boolean;
  job_id: string | null;
  follow_up_run_id: string | null;
  error: string | null;
  blockers: ExportDatasetBlocker[];
};

export type ExportRow = {
  run_id: string;
  project_id: string;
  kind: "campaign" | "verify";
  status: string;
  terminal: boolean;
  created_at: string | null;
  completed_at: string | null;
  model: {
    target_id: string | null;
    name: string | null;
    value: string | null;
    modality: string | null;
    fixture: boolean;
  };
  reports: ExportReports;
  dataset: ExportDataset;
};

export type ExportsList = {
  exports: ExportRow[];
  count: number;
  report_formats: string[];
  dataset_format: string;
  limit: number;
};

// --- Per-tenant cost (multi-tenancy) ---
// Mirrors GET /v1/orgs/{org_id}/cost?days=N. cents are integers throughout;
// format with centsToUsd() at the edge. budget caps/remaining are null when
// the org runs uncapped.
export type OrgBudget = {
  monthly_cap_cents: number | null;
  month_spent_cents: number;
  remaining_cents: number | null;
};

export type OrgCost = {
  org_id: string;
  total_cents: number;
  call_count: number;
  by_day: Record<string, number>;
  by_model: Record<string, number>;
  by_task: Record<string, number>;
  budget: OrgBudget;
};

/**
 * Fetch a single org's cost rollup over the trailing `days` window.
 * Auth rides the standard `api()` wrapper (cookie session). The API
 * answers 403 if the caller belongs to no project in the org, 404 if the
 * org is unknown — both surface as ApiError to the caller.
 */
export async function getOrgCost(orgId: string, days = 30): Promise<OrgCost> {
  return api<OrgCost>(
    `/v1/orgs/${encodeURIComponent(orgId)}/cost?days=${days}`,
  );
}

/**
 * Resolve the org id to show on the cost page from the caller's project
 * memberships (each ProjectMembership carries org_id). We take the first
 * project's org_id since a caller is typically scoped to one tenant.
 * Fallback: "default" when the list is empty (e.g. single-tenant dev), so
 * the page can still render against the default org.
 */
export function resolveOrgId(projects: ProjectMembership[]): string {
  return projects[0]?.org_id ?? "default";
}

/** Integer cents → "$1,234.56" USD string. */
export function centsToUsd(cents: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(cents / 100);
}

// --- DAST authentication profiles ---
//
// Secrets are write-only: POST accepts `secret`, but GET never returns
// it — `config` is the non-secret portion only.

export type AuthProfileKind = "form" | "bearer" | "header" | "cookie";

export type AuthProfile = {
  id: string;
  project_id: string;
  name: string;
  kind: AuthProfileKind;
  config: Record<string, string>;
  created_at: string;
};

export async function listAuthProfiles(
  projectId: string,
): Promise<AuthProfile[]> {
  // Tolerate both wire shapes: a bare array (the documented contract)
  // and the `{auth_profiles: [...]}` envelope the API also emits.
  const out = await api<AuthProfile[] | { auth_profiles?: AuthProfile[] }>(
    `/v1/auth-profiles?project=${encodeURIComponent(projectId)}`,
  );
  return Array.isArray(out) ? out : (out.auth_profiles ?? []);
}

export type CreateAuthProfileRequest = {
  project_id: string;
  name: string;
  kind: AuthProfileKind;
  config: Record<string, string>;
  secret: string;
};

export function createAuthProfile(
  req: CreateAuthProfileRequest,
): Promise<AuthProfile> {
  return api<AuthProfile>("/v1/auth-profiles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export function deleteAuthProfile(id: string): Promise<void> {
  return api<void>(`/v1/auth-profiles/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export type StartScanRequest = {
  target: string;
  scanner: string;
  project_id: string;
  /** Optional DAST auth profile to scan as an authenticated user. */
  auth_profile_id?: string;
};

export function startScan(req: StartScanRequest): Promise<{ run_id: string }> {
  // JSON.stringify drops undefined keys, so an unset auth_profile_id
  // never reaches the wire.
  return api<{ run_id: string }>("/v1/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export type ScannerInfo = {
  name: string;
  /** Capability vocabulary from redsim.scanners.registry (e.g. "dast"). */
  capabilities: string[];
};

/**
 * The registered scanner / attack adapter roster (GET /v1/scanners).
 *
 * Drives the scanner picker so the UI never hardcodes adapter names: the
 * pentest built-ins were removed with the pentest domain, and until an ML
 * attack adapter (redsim.ml.attacks) or a signed plugin registers, the roster
 * is empty. POST /v1/scans rejects any name not in this list with 400, so an
 * empty roster must render as "no adapter registered", never as a scan that
 * can be started.
 */
export function listScanners(): Promise<ScannerInfo[]> {
  return api<{ scanners: ScannerInfo[]; count: number }>("/v1/scanners").then(
    (r) => (Array.isArray(r.scanners) ? r.scanners : []),
  );
}
