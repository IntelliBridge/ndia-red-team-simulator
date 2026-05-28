// Thin client for the Aegis API.

const BASE = process.env.NEXT_PUBLIC_AEGIS_API_URL ?? "http://localhost:8000";

function _tokenFromStorage(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("aegis_token") ?? undefined;
}

export async function api<T>(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Accept": "application/json",
    ...(init.headers as Record<string, string> | undefined ?? {}),
  };
  const token = init.token ?? _tokenFromStorage();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const resp = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!resp.ok) {
    throw new Error(`${resp.status} ${resp.statusText}: ${await resp.text()}`);
  }
  return (await resp.json()) as T;
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

export type Finding = {
  id: string;
  run_id: string;
  project_id: string;
  severity: string;
  status: string;
  source_tool: string | null;
  validation_state: string;
  dedup_key: string | null;
  schema_blob: Record<string, unknown>;
};
