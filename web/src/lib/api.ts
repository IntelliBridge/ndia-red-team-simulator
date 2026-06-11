// Unified API client (Phase 4 v0.4.0 F18).
//
// Auth modes:
//   - Cookie (browser): credentials: "include" so aegis_api_session
//     rides along; X-Aegis-CSRF auto-attached from the aegis_csrf
//     cookie on every mutating request.
//   - Bearer (CLI / programmatic): set window.localStorage.aegis_token
//     and we'll attach Authorization: Bearer ... (bearer wins server
//     side, see aegis/api/auth.py).
//
// X-Aegis-Request-ID is auto-generated per call so the API +
// worker + scanner logs correlate.

const BASE = process.env.NEXT_PUBLIC_AEGIS_API_URL ?? "http://localhost:8000";

export const apiBase = BASE;
export const apiWsBase = BASE.replace(/^http/, "ws");

const SESSION_COOKIE =
  process.env.NEXT_PUBLIC_AEGIS_API_SESSION_COOKIE ?? "aegis_api_session";
const CSRF_COOKIE =
  process.env.NEXT_PUBLIC_AEGIS_CSRF_COOKIE ?? "aegis_csrf";
const CSRF_HEADER =
  process.env.NEXT_PUBLIC_AEGIS_CSRF_HEADER ?? "X-Aegis-CSRF";

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function _bearerFromStorage(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("aegis_token") ?? undefined;
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
    "X-Aegis-Request-ID": _newRequestId(),
    ...(init.headers as Record<string, string> | undefined ?? {}),
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

export type ProjectMembership = {
  id: string;
  slug: string;
  name: string;
  org_id: string;
  daily_llm_budget_cents: number | null;
  role: string;
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
 * Auth rides the standard `api()` wrapper (cookie or bearer). The API
 * answers 403 if the caller belongs to no project in the org, 404 if the
 * org is unknown — both surface as ApiError to the caller.
 */
export async function getOrgCost(
  orgId: string,
  days = 30,
): Promise<OrgCost> {
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
