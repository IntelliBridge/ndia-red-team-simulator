// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loginMock = vi.hoisted(() => vi.fn());
vi.mock("@/server/identity", async () => {
  const actual = await vi.importActual<typeof import("@/server/identity")>("@/server/identity");
  return { ...actual, loginWithPassword: loginMock };
});

const setSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy, get: () => undefined }) }));

const mintMock = vi.hoisted(() => vi.fn(async () => "signed-session-jwt"));
vi.mock("@/server/redsim-session", () => ({
  csrfCookieName: "redsim_csrf",
  sessionCookieName: "redsim_api_session",
  sessionTtlSeconds: 900,
  mintRedsimSessionJwt: mintMock,
  newCsrfToken: () => "csrf-token",
}));

const savedEnv = { ...process.env };

import { POST } from "./route";

const URL_ = "http://localhost:3000/api/auth/login";

function post(body: unknown, headers: HeadersInit = { "sec-fetch-site": "same-origin" }): Request {
  return new Request(URL_, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const CLAIMS = { sub: "kc-1", email: "a@b.c", name: "A", projectMemberships: {} };

beforeEach(() => {
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
  } as NodeJS.ProcessEnv;
  loginMock.mockReset();
  setSpy.mockClear();
  mintMock.mockClear();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  process.env = { ...savedEnv };
  vi.restoreAllMocks();
});

describe("POST /api/auth/login", () => {
  it("signs in: forwards the trimmed email and the password once, sets all three cookies", async () => {
    loginMock.mockResolvedValue({ ok: true, claims: CLAIMS, refreshToken: "rt-1", refreshExpiresIn: 1800 });

    const res = await POST(post({ email: "  a@b.c ", password: "pw" }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true, expires_in: 900 });
    expect(loginMock).toHaveBeenCalledWith("a@b.c", "pw");
    const names = setSpy.mock.calls.map((call) => call[0]);
    expect(names).toEqual(["redsim_api_session", "redsim_csrf", "redsim_refresh"]);
    expect(setSpy.mock.calls[0]?.[1]).toBe("signed-session-jwt");
    expect(setSpy.mock.calls[0]?.[2]).toMatchObject({ httpOnly: true, path: "/", maxAge: 900 });
    expect(setSpy.mock.calls[1]?.[2]).toMatchObject({ httpOnly: false, path: "/", maxAge: 900 });
    const refresh = setSpy.mock.calls[2];
    expect(refresh?.[1]).not.toContain("rt-1");
    expect(refresh?.[2]).toMatchObject({ httpOnly: true, path: "/api/auth", maxAge: 1800 });
  });

  it("sets only the session pair when the realm issued no refresh token", async () => {
    loginMock.mockResolvedValue({ ok: true, claims: CLAIMS, refreshToken: undefined, refreshExpiresIn: undefined });
    const res = await POST(post({ email: "a@b.c", password: "pw" }));
    expect(res.status).toBe(200);
    expect(setSpy.mock.calls.map((call) => call[0])).toEqual(["redsim_api_session", "redsim_csrf"]);
  });

  it("answers 401 with the code for a refused credential and sets nothing", async () => {
    for (const code of ["invalid_credentials", "account_disabled", "account_locked"]) {
      loginMock.mockResolvedValue({ ok: false, code, detail: "realm said so" });
      const res = await POST(post({ email: "a@b.c", password: "wrong" }));
      expect(res.status).toBe(401);
      await expect(res.json()).resolves.toEqual({ error: code });
    }
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("answers 503 with Retry-After when the realm is unavailable or not configured", async () => {
    for (const code of ["unavailable", "not_configured"]) {
      loginMock.mockResolvedValue({ ok: false, code, detail: "down" });
      const res = await POST(post({ email: "a@b.c", password: "pw" }));
      expect(res.status).toBe(503);
      expect(res.headers.get("retry-after")).toBe("10");
      await expect(res.json()).resolves.toEqual({ error: code });
    }
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("refuses a malformed body before touching the realm", async () => {
    const bodies: unknown[] = [
      "not json",
      {},
      { email: "a@b.c" },
      { email: "", password: "pw" },
      { email: "a@b.c", password: "" },
      { email: 42, password: "pw" },
      { email: "a@b.c", password: "x".repeat(1025) },
      { email: `${"a".repeat(251)}@b.c`, password: "pw" },
    ];
    for (const body of bodies) {
      const res = await POST(post(body));
      expect(res.status, JSON.stringify(body).slice(0, 40)).toBe(400);
      await expect(res.json()).resolves.toEqual({ error: "invalid_request" });
    }
    expect(loginMock).not.toHaveBeenCalled();
  });

  it("refuses a cross-site or foreign-origin post without reading the body", async () => {
    const cross = await POST(post({ email: "a@b.c", password: "pw" }, { "sec-fetch-site": "cross-site" }));
    expect(cross.status).toBe(403);
    const foreign = await POST(post({ email: "a@b.c", password: "pw" }, { origin: "https://evil.test" }));
    expect(foreign.status).toBe(403);
    expect(loginMock).not.toHaveBeenCalled();
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("answers 503 when the session cannot be minted after a successful login", async () => {
    loginMock.mockResolvedValue({ ok: true, claims: CLAIMS, refreshToken: "rt", refreshExpiresIn: 60 });
    mintMock.mockRejectedValueOnce(new Error("no key"));
    const res = await POST(post({ email: "a@b.c", password: "pw" }));
    expect(res.status).toBe(503);
    await expect(res.json()).resolves.toEqual({ error: "unavailable" });
  });
});
