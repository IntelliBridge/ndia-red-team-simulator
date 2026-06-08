// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const getServerSessionMock = vi.hoisted(() => vi.fn());
vi.mock("next-auth", () => ({ getServerSession: getServerSessionMock }));

vi.mock("@/server/auth-options", () => ({ authOptions: {} }));

const setSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy }) }));

const mintMock = vi.hoisted(() => vi.fn());
vi.mock("@/server/aegis-session", () => ({
  csrfCookieName: "aegis_csrf",
  sessionCookieName: "aegis_api_session",
  sessionTtlSeconds: 900,
  mintAegisSessionJwt: mintMock,
  newCsrfToken: () => "csrf-token",
}));

import { POST } from "./route";

beforeEach(() => {
  getServerSessionMock.mockReset();
  mintMock.mockReset();
  setSpy.mockClear();
});

describe("POST /api/auth/refresh-api-session", () => {
  it("returns 401 and sets no cookies when there is no session user", async () => {
    getServerSessionMock.mockResolvedValue(null);

    const res = await POST();

    expect(res.status).toBe(401);
    await expect(res.json()).resolves.toEqual({ error: "not signed in" });
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("re-mints both cookies from the session claims and returns expires_in", async () => {
    getServerSessionMock.mockResolvedValue({
      user: {
        sub: "u1",
        email: "u@e.com",
        name: "U",
        aegis_project_roles: { p1: "admin" },
      },
    });
    mintMock.mockResolvedValue("jwt");

    const res = await POST();

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      refreshed: true,
      expires_in: 900,
    });
    expect(setSpy).toHaveBeenCalledTimes(2);
    expect(mintMock).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: "u1",
        email: "u@e.com",
        name: "U",
        projectMemberships: { p1: "admin" },
      }),
    );
  });

  it("returns 500 'mint failed' and warns when minting throws", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    getServerSessionMock.mockResolvedValue({ user: { sub: "u1" } });
    mintMock.mockRejectedValue(new Error("no key"));

    const res = await POST();

    expect(res.status).toBe(500);
    await expect(res.json()).resolves.toEqual({ error: "mint failed" });
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});
