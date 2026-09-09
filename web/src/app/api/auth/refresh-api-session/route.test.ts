// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const getSessionMock = vi.hoisted(() => vi.fn());
vi.mock("@/server/better-auth", () => ({ getSession: getSessionMock }));

const setSpy = vi.hoisted(() => vi.fn());
const getSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({
  cookies: () => ({ set: setSpy, get: getSpy }),
}));

const mintMock = vi.hoisted(() => vi.fn());
vi.mock("@/server/redsim-session", () => ({
  csrfCookieName: "redsim_csrf",
  sessionCookieName: "redsim_api_session",
  sessionTtlSeconds: 900,
  mintRedsimSessionJwt: mintMock,
  newCsrfToken: () => "csrf-token",
}));

import { POST } from "./route";

const OWN_CLAIMS = {
  sub: "u1",
  email: "u@e.com",
  name: "U",
  projectMemberships: { p1: "admin" },
};

beforeEach(() => {
  getSessionMock.mockReset();
  mintMock.mockReset();
  setSpy.mockClear();
  getSpy.mockReset();
  getSpy.mockReturnValue({ value: "existing-cookie" });
  process.env.REDSIM_API_SESSION_PRIVATE_KEY = "";
});

describe("POST /api/auth/refresh-api-session", () => {
  it("returns 401 and sets no cookies when there is no Better Auth session", async () => {
    getSessionMock.mockResolvedValue(null);

    const res = await POST();

    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({ error: "not signed in" });
    expect(setSpy).not.toHaveBeenCalled();
    expect(mintMock).not.toHaveBeenCalled();
  });

  it("returns 401 without re-minting when the existing cookie fails verification", async () => {
    getSessionMock.mockResolvedValue({ user: { email: "u@e.com" } });
    // No signing key is configured, so verifyOwnSessionCookie returns nothing.
    const res = await POST();

    expect(res.status).toBe(401);
    expect(mintMock).not.toHaveBeenCalled();
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("returns 401 when no redsim cookie is present at all", async () => {
    getSessionMock.mockResolvedValue({ user: { email: "u@e.com" } });
    getSpy.mockReturnValue(undefined);

    const res = await POST();

    expect(res.status).toBe(401);
    expect(mintMock).not.toHaveBeenCalled();
  });
});

describe("POST /api/auth/refresh-api-session with a verified own cookie", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  /** Load the route with verifyOwnSessionCookie stubbed to a known result. */
  async function loadRoute(claims: typeof OWN_CLAIMS | undefined) {
    vi.doMock("@/server/redsim-cookies", async () => {
      const actual = await vi.importActual<
        typeof import("@/server/redsim-cookies")
      >("@/server/redsim-cookies");
      return { ...actual, verifyOwnSessionCookie: vi.fn().mockResolvedValue(claims) };
    });
    return import("./route");
  }

  it("re-mints both cookies from the verified claims and returns expires_in", async () => {
    getSessionMock.mockResolvedValue({ user: { email: "u@e.com" } });
    mintMock.mockResolvedValue("jwt");
    const { POST: post } = await loadRoute(OWN_CLAIMS);

    const res = await post();

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      refreshed: true,
      expires_in: 900,
    });
    expect(mintMock).toHaveBeenCalledWith(
      expect.objectContaining(OWN_CLAIMS),
    );
    expect(setSpy).toHaveBeenCalledTimes(2);
  });

  it("returns 500 'mint failed' and warns when minting throws", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    getSessionMock.mockResolvedValue({ user: { email: "u@e.com" } });
    mintMock.mockRejectedValue(new Error("no key"));
    const { POST: post } = await loadRoute(OWN_CLAIMS);

    const res = await post();

    expect(res.status).toBe(500);
    await expect(res.json()).resolves.toEqual({ error: "mint failed" });
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("returns 401 when the cookie is authentic but bound to another user", async () => {
    // verifyOwnSessionCookie is what enforces the binding, so a rejection is
    // the shape a foreign-but-valid cookie produces at this call site.
    getSessionMock.mockResolvedValue({ user: { email: "a@e.com" } });
    const { POST: post } = await loadRoute(undefined);

    const res = await post();

    expect(res.status).toBe(401);
    expect(mintMock).not.toHaveBeenCalled();
    expect(setSpy).not.toHaveBeenCalled();
  });
});
