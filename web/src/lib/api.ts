// Minimal API client for the redsim backend (FastAPI, no auth).
// Wire types for targets / attacks / runs are added as the backend lands;
// see docs/superpowers/specs/2026-09-08-redsim-design.md sections 3–4.

const BASE = process.env.NEXT_PUBLIC_REDSIM_API_URL ?? "http://localhost:8000";

export const apiBase = BASE;

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
    ...((init.headers as Record<string, string> | undefined) ?? {}),
  };
  if (init.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";

  const resp = await fetch(`${BASE}${path}`, { ...init, method, headers });
  if (!resp.ok) throw new ApiError(resp.status, await resp.text());
  const text = await resp.text();
  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(resp.status, text);
  }
}

/** URL of a rendered report for a run. */
export function reportUrl(runId: string, ext: "md" | "json" | "html"): string {
  return `${BASE}/v1/runs/${encodeURIComponent(runId)}/report.${ext}`;
}

/** URL of a run artifact (PNG / JSON) by its run-relative path. */
export function artifactUrl(runId: string, relPath: string): string {
  return `${BASE}/v1/runs/${encodeURIComponent(runId)}/artifacts/${relPath}`;
}
