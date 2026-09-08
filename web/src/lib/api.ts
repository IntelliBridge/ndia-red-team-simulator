// Unified API client (Phase 4 v0.4.0 F18).
//
// Auth modes:
//   - Cookie (browser): credentials: "include" so redsim_api_session
//     rides along; X-Redsim-CSRF auto-attached from the redsim_csrf
//     cookie on every mutating request.
//   - Bearer (CLI / programmatic): set window.localStorage.redsim_token
//     and we'll attach Authorization: Bearer ... (bearer wins server
//     side, see redsim/api/auth.py).
//
// X-Redsim-Request-ID is auto-generated per call so the API +
// worker + scanner logs correlate.

const BASE = process.env.NEXT_PUBLIC_REDSIM_API_URL ?? "http://localhost:8000";

export const apiBase = BASE;
export const apiWsBase = BASE.replace(/^http/, "ws");

const SESSION_COOKIE =
  process.env.NEXT_PUBLIC_REDSIM_API_SESSION_COOKIE ?? "redsim_api_session";
const CSRF_COOKIE = process.env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE ?? "redsim_csrf";
const CSRF_HEADER =
  process.env.NEXT_PUBLIC_REDSIM_CSRF_HEADER ?? "X-Redsim-CSRF";

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function _bearerFromStorage(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("redsim_token") ?? undefined;
}

/**
 * The bearer token a programmatic caller has stashed in localStorage, or
 * undefined for the cookie (browser) path. Exposed so non-fetch transports
 * (e.g. the WebSocket subprotocol channel) can mirror the same auth choice
 * the `api()` helper makes.
 */
export function bearerToken(): string | undefined {
  return _bearerFromStorage();
}

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

export async function api<T>(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Redsim-Request-ID": _newRequestId(),
    ...((init.headers as Record<string, string> | undefined) ?? {}),
  };

  // Bearer wins when explicitly supplied or available in localStorage;
  // otherwise the cookie rides via credentials: "include".
  const bearer = init.token ?? _bearerFromStorage();
  if (bearer) {
    headers["Authorization"] = `Bearer ${bearer}`;
  }

  // CSRF: cookie-authed mutations must echo the cookie via the header.
  if (!bearer && MUTATING.has(method) && hasCookie(SESSION_COOKIE)) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers[CSRF_HEADER] = csrf;
  }

  const resp = await fetch(`${BASE}${path}`, {
    ...init,
    method,
    credentials: bearer ? "omit" : "include",
    headers,
  });
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

export type FindingSchemaBlob = {
  title?: string;
  description?: string;
  cve?: string;
  target?: string;
  attack_id?: string;
  first_success_eps?: number;
  ml?: MLFindingDetail | null;
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
/** A fraction with its denominator; `accuracy` is null when `n` is 0. */
export type AccuracyPoint = {
  n: number;
  n_correct: number;
  accuracy?: number | null;
};
/** The five MRI dimensions on a 0 to 100 scale; also used for deltas. */
export type MRISubscores = Record<
  "S_acc" | "S_asr" | "S_eps" | "S_conf" | "S_expl",
  number | null
>;
export type CleanAccuracyDelta = {
  before: AccuracyPoint;
  after: AccuracyPoint;
  delta?: number | null;
};
export type FamilyDelta = {
  measurement_id: string;
  before: AccuracyPoint;
  after: AccuracyPoint;
  delta?: number | null;
};
// Mirrors redsim.ml.schema.MRIDelta (spec 15.6): a verify run's ΔMRI against
// its baseline. Per-dimension deltas live in `delta_subscores` and per-family
// accuracy deltas (with denominators) in `delta_families`.
export type MRIDelta = {
  baseline_run_id: string;
  mri_before: number;
  mri_after: number;
  delta: number;
  delta_subscores?: Partial<MRISubscores>;
  delta_acc_clean?: CleanAccuracyDelta;
  delta_families?: FamilyDelta[];
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
  validation_state: string;
  dedup_key: string | null;
  schema_blob: FindingSchemaBlob;
};

export type TargetMetadata = {
  dataset_id?: string;
  dataset_revision?: string;
  class_names?: string[];
  clean_accuracy?: number;
  clean_n?: number;
  framework_versions?: Record<string, string>;
  gradients?: boolean;
  manifest?: Record<string, unknown>;
  [key: string]: unknown;
};
export type ModelTarget = {
  id: string;
  project_id: string;
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
  acc_clean: number;
  acc_adv: number;
  asr: number;
  conf_gap: number;
  expl_shift: number;
};
export type CampaignConfig = CampaignRequest & {
  scoring_weights: ScoringWeights;
  settings_hash?: string;
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
  delta?: MRIDelta | null;
  subscores?: MRISubscores;
  per_attack?: Record<string, number>;
  weights?: ScoringWeights;
  reading?: string;
  reference_eps?: number;
  eps_grid?: number[];
  attack_ids?: string[];
  measurements?: Measurement[];
  curve?: CampaignCurvePoint[];
};
export type CampaignCurvePoint = {
  attack_id?: string;
  family: "clean" | "evasion" | "control";
  eps: number;
  accuracy: number;
  n: number;
  n_correct: number;
};
export type Campaign = {
  run_id: string;
  status: string;
  stage?: string;
  stages_done: string[];
  error?: string | null;
  config: CampaignConfig;
  target: ModelTarget;
  attacks: AttackInfo[];
  provenance?: Record<string, unknown> | null;
  measurements: Measurement[];
  observations: Observation[];
  interpretation: Interpretation[];
  recommendations: CandidateRecommendation[];
  limitations: string[];
  reviewer_notes?: string | null;
  score?: MRIRecord | null;
  curve?: CampaignCurvePoint[];
  findings?: Finding[];
  completeness: { status: "complete" | "partial"; missing: string[] };
  score_status?: { status: "pending" | "unavailable"; reason?: string };
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
  delta_acc_clean?: number;
  delta_families?: Array<{
    family: string;
    before: number;
    after: number;
    n_before: number;
    n_after: number;
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
  params: Record<string, unknown> = {},
) {
  return api(`/v1/findings/${encodeURIComponent(id)}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ defense, params }),
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
export type ReportExt = "html" | "json" | "md";

export function reportUrl(runId: string, ext: ReportExt): string {
  return `${BASE}/v1/runs/${encodeURIComponent(runId)}/report.${ext}`;
}

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
 * Auth rides the standard `api()` wrapper (cookie or bearer). The API
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

// --- DAST authentication profiles (feat/authenticated-dast) ---
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
