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
    localStorage.setItem("aegis_token", "tok");
    localStorage.setItem("aegis_email", "a@b.c");
    expect(getToken()).toBe("tok");
    expect(getEmail()).toBe("a@b.c");
  });

  it("logout clears storage and pings the signout endpoint", () => {
    const fetchMock = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("fetch", fetchMock);
    localStorage.setItem("aegis_token", "tok");
    localStorage.setItem("aegis_email", "a@b.c");

    logout();

    expect(localStorage.getItem("aegis_token")).toBeNull();
    expect(localStorage.getItem("aegis_email")).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/signout-aegis", {
      method: "POST",
    });
  });

  it("requireAuth returns the token when present, without redirecting", () => {
    localStorage.setItem("aegis_token", "tok");
    const router = { push: vi.fn() };
    expect(requireAuth(router)).toBe("tok");
    expect(router.push).not.toHaveBeenCalled();
  });

  it("requireAuth accepts a cookie session via the non-httpOnly csrf cookie", () => {
    document.cookie = "aegis_csrf=csrf-value";
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
