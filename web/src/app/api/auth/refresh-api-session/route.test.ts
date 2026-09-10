// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const refreshMock = vi.hoisted(() => vi.fn());
vi.mock("@/server/identity", async () => {
  const actual = await vi.importActual<typeof import("@/server/identity")>("@/server/identity");
  return { ...actual, refreshWithToken: refreshMock };
});

const setSpy = vi.hoisted(() => vi.fn());
const getSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy, get: getSpy }) }));

const mintMock = vi.hoisted(() => vi.fn(async () => "signed-session-jwt"));
vi.mock("@/server/redsim-session", () => ({
  csrfCookieName: "redsim_csrf",
  sessionCookieName: "redsim_api_session",
  sessionTtlSeconds: 900,
  mintRedsimSessionJwt: mintMock,
  newCsrfToken: () => "csrf-token",
}));

const savedEnv = { ...process.env };
const CLAIMS = { sub: "kc-1", email: "a@b.c", name: "A", projectMemberships: { default: "admin" } };

async function loadRoute() {
  vi.resetModules();
  return import("./route");
}

/** A jar holding a sealed refresh cookie for `token`, or nothing. */
async function jarWith(token: string | undefined) {
  if (token === undefined) {
    getSpy.mockReturnValue(undefined);
    return;
  }
  const { sealRefreshToken } = await import("@/server/refresh-cookie");
  const sealed = await sealRefreshToken(token, 3600);
  getSpy.mockImplementation((name: string) => (name === "redsim_refresh" ? { value: sealed } : undefined));
}

beforeEach(() => {
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
  } as NodeJS.ProcessEnv;
  refreshMock.mockReset();
  setSpy.mockClear();
  getSpy.mockReset();
  mintMock.mockClear();
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  process.env = { ...savedEnv };
  vi.restoreAllMocks();
});

describe("POST /api/auth/refresh-api-session", () => {
  it("returns 401 and touches nothing without a refresh cookie", async () => {
    await jarWith(undefined);
    const { POST } = await loadRoute();
    const res = await POST();
    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({ error: "not signed in" });
    expect(refreshMock).not.toHaveBeenCalled();
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("returns 401 for a cookie it cannot open, without calling the realm", async () => {
    getSpy.mockImplementation((name: string) =>
      name === "redsim_refresh" ? { value: "not-a-sealed-cookie" } : undefined,
    );
    const { POST } = await loadRoute();
    const res = await POST();
    expect(res.status).toBe(401);
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("trades the refresh token for a new pair and rotates the refresh cookie", async () => {
    await jarWith("rt-1");
    refreshMock.mockResolvedValue({ ok: true, claims: CLAIMS, refreshToken: "rt-2", refreshExpiresIn: 1700 });
    const { POST } = await loadRoute();

    const res = await POST();

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ refreshed: true, expires_in: 900 });
    expect(refreshMock).toHaveBeenCalledWith("rt-1");
    expect(mintMock).toHaveBeenCalledWith(CLAIMS);
    expect(setSpy.mock.calls.map((call) => call[0])).toEqual([
      "redsim_api_session",
      "redsim_csrf",
      "redsim_refresh",
    ]);
    const refresh = setSpy.mock.calls[2];
    expect(refresh?.[1]).not.toContain("rt-2");
    expect(refresh?.[2]).toMatchObject({ httpOnly: true, path: "/api/auth", maxAge: 1700 });
    const { openRefreshToken } = await import("@/server/refresh-cookie");
    expect(await openRefreshToken(refresh?.[1] as string)).toBe("rt-2");
  });

  it("keeps the old refresh cookie when the realm did not rotate it", async () => {
    await jarWith("rt-1");
    refreshMock.mockResolvedValue({ ok: true, claims: CLAIMS, refreshToken: undefined, refreshExpiresIn: undefined });
    const { POST } = await loadRoute();
    const res = await POST();
    expect(res.status).toBe(200);
    expect(setSpy.mock.calls.map((call) => call[0])).toEqual(["redsim_api_session", "redsim_csrf"]);
  });

  it("clears every credential and answers 401 when the upstream session has ended", async () => {
    await jarWith("rt-old");
    refreshMock.mockResolvedValue({ ok: false, code: "session_ended", detail: "Session not active" });
    const { POST } = await loadRoute();

    const res = await POST();

    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({ error: "session_ended" });
    expect(setSpy.mock.calls.map((call) => [call[0], call[1], call[2].maxAge])).toEqual([
      ["redsim_api_session", "", 0],
      ["redsim_csrf", "", 0],
      ["redsim_refresh", "", 0],
    ]);
    expect(mintMock).not.toHaveBeenCalled();
  });

  it("answers 503 and keeps the cookies when the realm is unavailable", async () => {
    await jarWith("rt-1");
    refreshMock.mockResolvedValue({ ok: false, code: "unavailable", detail: "down" });
    const { POST } = await loadRoute();
    const res = await POST();
    expect(res.status).toBe(503);
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("returns 500 'mint failed' when the session cannot be signed", async () => {
    await jarWith("rt-1");
    refreshMock.mockResolvedValue({ ok: true, claims: CLAIMS, refreshToken: "rt-2", refreshExpiresIn: 60 });
    mintMock.mockRejectedValueOnce(new Error("no key"));
    const { POST } = await loadRoute();
    const res = await POST();
    expect(res.status).toBe(500);
    await expect(res.json()).resolves.toEqual({ error: "mint failed" });
  });
});
