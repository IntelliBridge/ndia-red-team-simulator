import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

  it("logout clears storage and pings the signout endpoint", () => {
    const fetchMock = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("fetch", fetchMock);
    localStorage.setItem("redsim_token", "tok");
    localStorage.setItem("redsim_email", "a@b.c");

    logout();

    expect(localStorage.getItem("redsim_token")).toBeNull();
    expect(localStorage.getItem("redsim_email")).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/signout-redsim", {
      method: "POST",
    });
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
