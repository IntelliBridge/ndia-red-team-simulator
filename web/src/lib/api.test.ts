import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  api,
  centsToUsd,
  createAuthProfile,
  deleteAuthProfile,
  getOrgCost,
  listAuthProfiles,
  resolveOrgId,
  startScan,
  type ProjectMembership,
} from "./api";

const fetchMock = vi.fn();

function ok(body = ""): { ok: boolean; status: number; text: () => Promise<string> } {
  return { ok: true, status: 200, text: async () => body };
}

function notOk(status: number, body: string) {
  return { ok: false, status, text: async () => body };
}

function lastInit(): RequestInit {
  const call = fetchMock.mock.calls.at(-1);
  return (call?.[1] ?? {}) as RequestInit;
}

function lastUrl(): string {
  const call = fetchMock.mock.calls.at(-1);
  return (call?.[0] ?? "") as string;
}

function headerOf(init: RequestInit, name: string): string | undefined {
  return (init.headers as Record<string, string>)[name];
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  localStorage.clear();
  for (const c of document.cookie.split(";")) {
    const n = c.split("=")[0]?.trim();
    if (n) document.cookie = `${n}=;expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api() request shaping", () => {
  it("sends Accept + a correlation id and defaults GET to cookie credentials", async () => {
    fetchMock.mockResolvedValue(ok(JSON.stringify({ hi: 1 })));
    const out = await api<{ hi: number }>("/v1/x");
    expect(out).toEqual({ hi: 1 });
    expect(lastUrl()).toBe("http://localhost:8000/v1/x");
    const init = lastInit();
    expect(headerOf(init, "Accept")).toBe("application/json");
    expect(headerOf(init, "X-Aegis-Request-ID")).toMatch(/^req-/);
    expect(init.credentials).toBe("include");
    expect(headerOf(init, "Authorization")).toBeUndefined();
  });

  it("uses an explicit bearer token and omits cookie credentials", async () => {
    fetchMock.mockResolvedValue(ok("{}"));
    await api("/v1/x", { token: "T" });
    const init = lastInit();
    expect(headerOf(init, "Authorization")).toBe("Bearer T");
    expect(init.credentials).toBe("omit");
  });

  it("falls back to a localStorage bearer token and never attaches CSRF", async () => {
    fetchMock.mockResolvedValue(ok("{}"));
    localStorage.setItem("aegis_token", "LS");
    await api("/v1/x", { method: "POST" });
    const init = lastInit();
    expect(headerOf(init, "Authorization")).toBe("Bearer LS");
    expect(init.credentials).toBe("omit");
    expect(headerOf(init, "X-Aegis-CSRF")).toBeUndefined();
  });

  it("echoes the CSRF cookie header on cookie-authed mutations", async () => {
    fetchMock.mockResolvedValue(ok("{}"));
    document.cookie = "aegis_api_session=opaque";
    document.cookie = "aegis_csrf=csrf123";
    await api("/v1/x", { method: "POST" });
    const init = lastInit();
    expect(headerOf(init, "X-Aegis-CSRF")).toBe("csrf123");
    expect(init.credentials).toBe("include");
  });

  it("omits CSRF when there is no session cookie to protect", async () => {
    fetchMock.mockResolvedValue(ok("{}"));
    document.cookie = "aegis_csrf=csrf123";
    await api("/v1/x", { method: "DELETE" });
    expect(headerOf(lastInit(), "X-Aegis-CSRF")).toBeUndefined();
  });

  it("does not attach CSRF on non-mutating cookie requests", async () => {
    fetchMock.mockResolvedValue(ok("{}"));
    document.cookie = "aegis_api_session=opaque";
    document.cookie = "aegis_csrf=csrf123";
    await api("/v1/x");
    expect(headerOf(lastInit(), "X-Aegis-CSRF")).toBeUndefined();
  });

  it("throws ApiError carrying status + body on a non-ok response", async () => {
    fetchMock.mockResolvedValue(notOk(403, "forbidden"));
    const err = (await api("/v1/x").catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(err.body).toBe("forbidden");
  });

  it("returns {} for an empty response body", async () => {
    fetchMock.mockResolvedValue(ok(""));
    expect(await api("/v1/empty")).toEqual({});
  });
});

describe("centsToUsd", () => {
  it("formats whole and fractional dollars", () => {
    expect(centsToUsd(0)).toBe("$0.00");
    expect(centsToUsd(500)).toBe("$5.00");
    expect(centsToUsd(12345)).toBe("$123.45");
  });

  it("groups thousands and renders negatives", () => {
    expect(centsToUsd(123456789)).toBe("$1,234,567.89");
    expect(centsToUsd(-2000)).toBe("-$20.00");
  });
});

describe("resolveOrgId", () => {
  const p = (org_id: string): ProjectMembership => ({
    id: "p",
    slug: "p",
    name: "P",
    org_id,
    daily_llm_budget_cents: null,
    role: "viewer",
  });

  it("takes the first project's org_id", () => {
    expect(resolveOrgId([p("org-a"), p("org-b")])).toBe("org-a");
  });

  it("falls back to 'default' when there are no projects", () => {
    expect(resolveOrgId([])).toBe("default");
  });
});

describe("getOrgCost", () => {
  it("requests the org cost endpoint with an encoded id and days", async () => {
    fetchMock.mockResolvedValue(ok(JSON.stringify({ org_id: "o", total_cents: 0 })));
    await getOrgCost("o rg/1", 7);
    expect(lastUrl()).toBe("http://localhost:8000/v1/orgs/o%20rg%2F1/cost?days=7");
  });

  it("defaults to a 30-day window", async () => {
    fetchMock.mockResolvedValue(ok(JSON.stringify({ org_id: "o" })));
    await getOrgCost("o");
    expect(lastUrl()).toBe("http://localhost:8000/v1/orgs/o/cost?days=30");
  });
});

describe("auth profile + scan helpers", () => {
  it("listAuthProfiles GETs /v1/auth-profiles scoped to the project", async () => {
    const profiles = [
      {
        id: "ap-1",
        project_id: "p one",
        name: "Staging",
        kind: "form",
        config: { login_url: "https://t.example/login" },
        created_at: "2026-06-01T00:00:00Z",
      },
    ];
    fetchMock.mockResolvedValue(ok(JSON.stringify(profiles)));
    const out = await listAuthProfiles("p one");
    expect(lastUrl()).toBe("http://localhost:8000/v1/auth-profiles?project=p%20one");
    expect((lastInit().method ?? "GET").toUpperCase()).toBe("GET");
    expect(out).toEqual(profiles);
  });

  it("listAuthProfiles unwraps the {auth_profiles: [...]} envelope shape", async () => {
    const profiles = [{ id: "ap-2", name: "Env" }];
    fetchMock.mockResolvedValue(
      ok(JSON.stringify({ auth_profiles: profiles, count: 1 })),
    );
    expect(await listAuthProfiles("p1")).toEqual(profiles);
  });

  it("createAuthProfile POSTs the full body including the write-only secret", async () => {
    fetchMock.mockResolvedValue(ok("{}"));
    await createAuthProfile({
      project_id: "p1",
      name: "API key",
      kind: "header",
      config: { header_name: "X-Api-Key" },
      secret: "shh",
    });
    expect(lastUrl()).toBe("http://localhost:8000/v1/auth-profiles");
    const init = lastInit();
    expect(init.method).toBe("POST");
    expect(headerOf(init, "Content-Type")).toBe("application/json");
    expect(init.body).toBe(
      JSON.stringify({
        project_id: "p1",
        name: "API key",
        kind: "header",
        config: { header_name: "X-Api-Key" },
        secret: "shh",
      }),
    );
  });

  it("deleteAuthProfile DELETEs /v1/auth-profiles/{id}", async () => {
    fetchMock.mockResolvedValue(ok(""));
    await deleteAuthProfile("ap-9");
    expect(lastUrl()).toBe("http://localhost:8000/v1/auth-profiles/ap-9");
    expect(lastInit().method).toBe("DELETE");
  });

  it("startScan includes auth_profile_id when provided", async () => {
    fetchMock.mockResolvedValue(ok(JSON.stringify({ run_id: "r1" })));
    await startScan({
      target: "https://t.example",
      scanner: "zap",
      project_id: "p1",
      auth_profile_id: "ap-1",
    });
    expect(lastUrl()).toBe("http://localhost:8000/v1/scans");
    expect(lastInit().body).toBe(
      JSON.stringify({
        target: "https://t.example",
        scanner: "zap",
        project_id: "p1",
        auth_profile_id: "ap-1",
      }),
    );
  });

  it("startScan omits auth_profile_id from the wire body when unset", async () => {
    fetchMock.mockResolvedValue(ok(JSON.stringify({ run_id: "r2" })));
    const out = await startScan({
      target: "https://t.example",
      scanner: "trivy",
      project_id: "p1",
    });
    expect(out).toEqual({ run_id: "r2" });
    expect(lastInit().body).toBe(
      JSON.stringify({
        target: "https://t.example",
        scanner: "trivy",
        project_id: "p1",
      }),
    );
  });
});
