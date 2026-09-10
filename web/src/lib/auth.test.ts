import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { isAuthenticated, loginPath, logout, requireAuth, signInWithPassword } from "./auth";

function clearCookies(): void {
  for (const c of document.cookie.split(";")) {
    const name = c.split("=")[0]?.trim();
    if (name) {
      document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT`;
    }
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("auth client helpers", () => {
  beforeEach(() => {
    clearCookies();
    window.history.replaceState(null, "", "/");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("signInWithPassword posts the credentials to the login route and reports success", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(signInWithPassword("a@b.c", "pw")).resolves.toEqual({ ok: true });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/auth/login");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(JSON.parse(String(init.body))).toEqual({ email: "a@b.c", password: "pw" });
  });

  it("signInWithPassword returns the route's code on a refusal", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(401, { error: "invalid_credentials" })));
    await expect(signInWithPassword("a@b.c", "pw")).resolves.toEqual({
      ok: false,
      code: "invalid_credentials",
    });
  });

  it("signInWithPassword reads a non-JSON refusal as unknown and a network failure as unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>", { status: 502 })));
    await expect(signInWithPassword("a@b.c", "pw")).resolves.toEqual({ ok: false, code: "unknown" });

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    await expect(signInWithPassword("a@b.c", "pw")).resolves.toEqual({ ok: false, code: "unavailable" });
  });

  it("isAuthenticated reads the non-httpOnly csrf cookie, the only visible half of the session", () => {
    expect(isAuthenticated()).toBe(false);
    document.cookie = "redsim_csrf=csrf-value";
    expect(isAuthenticated()).toBe(true);
  });

  it("logout posts to the sign-out route and resolves even when that fails", async () => {
    const fetchMock = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("fetch", fetchMock);
    await logout();
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/signout-redsim", { method: "POST" });

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    await expect(logout()).resolves.toBeUndefined();
  });

  it("loginPath carries the current location as next, except from the root and the login page", () => {
    window.history.replaceState(null, "", "/runs/abc?tab=curve");
    expect(loginPath()).toBe(`/login?next=${encodeURIComponent("/runs/abc?tab=curve")}`);
    window.history.replaceState(null, "", "/");
    expect(loginPath()).toBe("/login");
    window.history.replaceState(null, "", "/login?reason=rejected");
    expect(loginPath()).toBe("/login");
  });

  it("requireAuth passes a cookie session without redirecting", () => {
    document.cookie = "redsim_csrf=csrf-value";
    const router = { push: vi.fn() };
    expect(requireAuth(router)).toBe(true);
    expect(router.push).not.toHaveBeenCalled();
  });

  it("requireAuth redirects to /login with the return path when unauthenticated", () => {
    window.history.replaceState(null, "", "/findings");
    const router = { push: vi.fn() };
    expect(requireAuth(router)).toBe(false);
    expect(router.push).toHaveBeenCalledWith("/login?next=%2Ffindings");
  });
});
