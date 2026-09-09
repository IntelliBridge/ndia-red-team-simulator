import { API_URL, DEV_FIXTURES } from "./env"
import type {
  DefenseInfo,
  MlErrorDetail,
} from "./api-types"
import { fixtureFetch } from "./fixtures"

/** Thrown for any non-2xx ML response. Carries the structured detail verbatim. [spec §17.3] */
export class ApiError extends Error {
  status: number
  detail: MlErrorDetail
  constructor(status: number, detail: MlErrorDetail) {
    super(detail.message || `HTTP ${status}`)
    this.status = status
    this.detail = detail
  }
}

function requestId(): string {
  return (globalThis.crypto?.randomUUID?.() ?? `req-${Date.now()}-${Math.random().toString(16).slice(2)}`)
}

function csrfToken(): string | null {
  if (typeof document === "undefined") return null
  const m = document.cookie.match(/(?:^|;\s*)redsim_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : null
}

export interface ApiOptions extends Omit<RequestInit, "body"> {
  body?: unknown
  /** bearer token when not using cookie auth */
  token?: string
}

/**
 * Single typed fetch wrapper. Sends cookie or bearer auth, an X-Redsim-CSRF
 * header on mutations, and an X-Request-Id. Parses `{detail:{code,message,...}}`
 * error bodies into ApiError. When DEV_FIXTURES is on, requests are served from
 * bundled fixtures instead. [spec §3, §6, §17.3]
 */
export async function api<T>(path: string, opts: ApiOptions = {}): Promise<T> {
  const { body, token, headers, method = "GET", ...rest } = opts

  if (DEV_FIXTURES) {
    return fixtureFetch<T>(path, method, body)
  }

  const h = new Headers(headers)
  h.set("Accept", "application/json")
  h.set("X-Request-Id", requestId())
  if (token) h.set("Authorization", `Bearer ${token}`)
  if (method !== "GET" && method !== "HEAD") {
    h.set("Content-Type", "application/json")
    const csrf = csrfToken()
    if (csrf) h.set("X-Redsim-CSRF", csrf)
  }

  let res: Response
  try {
    res = await fetch(`${API_URL}${path}`, {
      ...rest,
      method,
      headers: h,
      credentials: "include",
      body: body != null ? JSON.stringify(body) : undefined,
    })
  } catch (e) {
    // Network / server unreachable -> surface as a 503-style unavailable state. [spec §6]
    throw new ApiError(503, {
      code: "service_unavailable",
      message: "Cannot reach the redsim API. The queue or worker may be unavailable.",
    })
  }

  if (res.status === 204) return undefined as T

  const text = await res.text()
  const json = text ? JSON.parse(text) : null

  if (!res.ok) {
    const detail: MlErrorDetail = json?.detail ?? {
      code: `http_${res.status}`,
      message: res.statusText || "Request failed",
    }
    throw new ApiError(res.status, detail)
  }
  return json as T
}

/** Absolute URL for an artifact (SHAP PNG, adversarial image, etc.). [spec §17.3] */
export function artifactUrl(id: string): string {
  return `${API_URL}/v1/artifacts/${id}`
}

/** Report download URL in the given format. PDF is Phase B (disabled in UI). [spec §14.8] */
export function reportUrl(runId: string, format: "md" | "json" | "html"): string {
  return `${API_URL}/v1/runs/${runId}/report.${format}`
}

/* ---- mutation helpers (thin wrappers over api()) [spec §17.3] ---- */

export function startCampaign(modelId: string, config: unknown, token?: string) {
  return api<{ run_id: string }>(`/v1/models/${modelId}/attacks`, { method: "POST", body: config, token })
}

export function explainFinding(findingId: string, token?: string) {
  return api<{ ok: true }>(`/v1/findings/${findingId}/explain`, { method: "POST", token })
}

export function hardenFinding(findingId: string, token?: string) {
  return api<{ ok: true }>(`/v1/findings/${findingId}/harden`, { method: "POST", token })
}

export function verifyFinding(findingId: string, defense: DefenseInfo["id"], params: Record<string, unknown>, token?: string) {
  return api<{ run_id: string }>(`/v1/findings/${findingId}/verify`, {
    method: "POST",
    body: { defense, params },
    token,
  })
}

export function dismissFinding(findingId: string, reason: string, token?: string) {
  return api<{ ok: true }>(`/v1/findings/${findingId}/dismiss`, { method: "POST", body: { reason }, token })
}

export function compareRuns(runId: string, otherRunId: string) {
  return api(`/v1/runs/${runId}/compare?other=${encodeURIComponent(otherRunId)}`)
}

export function patchReviewerNotes(runId: string, notes: string, token?: string) {
  return api<{ ok: true }>(`/v1/runs/${runId}/reviewer-notes`, { method: "PATCH", body: { notes }, token })
}

export function cancelRun(runId: string, token?: string) {
  return api<{ ok: true }>(`/v1/runs/${runId}/cancel`, { method: "POST", token })
}

export function deleteTarget(modelId: string, token?: string) {
  return api<{ ok: true }>(`/v1/models/${modelId}`, { method: "DELETE", token })
}

/** SWR fetcher bound to api(). */
export const swrFetcher = <T,>(path: string) => api<T>(path)
