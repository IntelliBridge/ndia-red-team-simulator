import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Better Auth browser client, stubbed at the module boundary: importing it
// for real would build a client against no server, and the assertion here is
// that logout() calls sign-out at all, which nothing checked before.
const signOutMock = vi.hoisted(() => vi.fn().mockResolvedValue({ data: null }));
vi.mock("./auth-client", () => ({ signOut: signOutMock }));

import { getEmail, getToken, logout, requireAuth } from "./auth";

function clearCookies(): void {
  for (const c of document.cookie.split(";")) {
    const name = c.split("=")[0]?.trim();
    if (name) {
      document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT`;
    }
  }
}

describe("auth client helpers", () => {
  beforeEach(() => {
    localStorage.clear();
    clearCookies();
    signOutMock.mockClear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("getToken / getEmail read from localStorage", () => {
    expect(getToken()).toBeUndefined();
    expect(getEmail()).toBeUndefined();
    localStorage.setItem("redsim_token", "tok");
    localStorage.setItem("redsim_email", "a@b.c");
    expect(getToken()).toBe("tok");
    expect(getEmail()).toBe("a@b.c");
  });

  it("logout clears storage and pings the signout endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("fetch", fetchMock);
    localStorage.setItem("redsim_token", "tok");
    localStorage.setItem("redsim_email", "a@b.c");

    await logout();

    expect(localStorage.getItem("redsim_token")).toBeNull();
    expect(localStorage.getItem("redsim_email")).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/signout-redsim", {
      method: "POST",
    });
  });

  it("logout signs out of Better Auth, not only the redsim cookies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(undefined));

    await logout();

    // Without this call the Better Auth cookie and the Keycloak SSO session
    // both survive, and /login re-authenticates the same user on one click.
    expect(signOutMock).toHaveBeenCalledTimes(1);
  });

  it("logout resolves even when Better Auth sign-out rejects", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    signOutMock.mockRejectedValueOnce(new Error("idp unreachable"));
    localStorage.setItem("redsim_token", "tok");

    await expect(logout()).resolves.toBeUndefined();

    // The local credentials go regardless, so a failing sign-out cannot leave
    // the user stranded on an authenticated page.
    expect(localStorage.getItem("redsim_token")).toBeNull();
  });

  it("requireAuth returns the token when present, without redirecting", () => {
    localStorage.setItem("redsim_token", "tok");
    const router = { push: vi.fn() };
    expect(requireAuth(router)).toBe("tok");
    expect(router.push).not.toHaveBeenCalled();
  });

  it("requireAuth accepts a cookie session via the non-httpOnly csrf cookie", () => {
    document.cookie = "redsim_csrf=csrf-value";
    const router = { push: vi.fn() };
    expect(requireAuth(router)).toBe("(cookie)");
    expect(router.push).not.toHaveBeenCalled();
  });

  it("requireAuth redirects to /login when unauthenticated", () => {
    const router = { push: vi.fn() };
    expect(requireAuth(router)).toBeUndefined();
    expect(router.push).toHaveBeenCalledWith("/login");
  });
});
