import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api } from "./api";

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
