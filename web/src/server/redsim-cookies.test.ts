// @vitest-environment node
//
// The cookie attribute builder and the sign-out clear. These are the pieces
// every auth route depends on to set and clear the same three names.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportPKCS8, generateKeyPair } from "jose";

const savedEnv = { ...process.env };

async function load() {
  vi.resetModules();
  return import("./redsim-cookies");
}

beforeEach(() => {
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
    REDSIM_API_SESSION_KEY_ID: "kid-test",
    REDSIM_API_SESSION_TTL_SECONDS: "900",
    REDSIM_ENV: "dev",
  } as NodeJS.ProcessEnv;
});

afterEach(() => {
  process.env = { ...savedEnv };
});

describe("redsim cookie attributes", () => {
  it("makes the session and refresh cookies httpOnly and the csrf cookie readable", async () => {
    const { redsimCookieOptions } = await load();
    expect(redsimCookieOptions("session")).toMatchObject({
      httpOnly: true,
      path: "/",
      sameSite: "lax",
      maxAge: 900,
    });
    expect(redsimCookieOptions("csrf")).toMatchObject({ httpOnly: false, path: "/", maxAge: 900 });
    // The refresh cookie is sent to the auth routes only; nothing else reads it.
    expect(redsimCookieOptions("refresh", 3600)).toMatchObject({
      httpOnly: true,
      path: "/api/auth",
      maxAge: 3600,
    });
  });

  it("marks every cookie Secure only under REDSIM_ENV=prod", async () => {
    let mod = await load();
    for (const kind of ["session", "csrf", "refresh"] as const) {
      expect(mod.redsimCookieOptions(kind).secure).toBe(false);
    }
    process.env.REDSIM_ENV = "prod";
    mod = await load();
    for (const kind of ["session", "csrf", "refresh"] as const) {
      expect(mod.redsimCookieOptions(kind).secure).toBe(true);
    }
  });

  it("names the three cookies from the env, with the refresh default", async () => {
    const { redsimCookieNames } = await load();
    expect(redsimCookieNames).toEqual({
      session: "redsim_api_session",
      csrf: "redsim_csrf",
      refresh: "redsim_refresh",
    });
  });
});

describe("setRedsimCookies", () => {
  it("mints the session JWT and a fresh csrf value with the session TTL", async () => {
    const { privateKey } = await generateKeyPair("RS256", { extractable: true });
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = await exportPKCS8(privateKey);
    const { setRedsimCookies } = await load();
    const set = vi.fn();

    const maxAge = await setRedsimCookies(
      { sub: "kc-sub", email: "a@b.c", name: "A", projectMemberships: { default: "viewer" } },
      set,
    );

    expect(maxAge).toBe(900);
    expect(set).toHaveBeenCalledTimes(2);
    expect(set.mock.calls[0]?.[0]).toBe("redsim_api_session");
    expect(String(set.mock.calls[0]?.[1]).split(".")).toHaveLength(3);
    expect(set.mock.calls[0]?.[2]).toMatchObject({ httpOnly: true, maxAge: 900 });
    expect(set.mock.calls[1]?.[0]).toBe("redsim_csrf");
    expect(set.mock.calls[1]?.[2]).toMatchObject({ httpOnly: false, maxAge: 900 });
  });
});

describe("clearRedsimCookies", () => {
  it("clears every credential cookie with maxAge 0, the refresh cookie on its own path", async () => {
    const { clearRedsimCookies } = await load();
    const set = vi.fn();
    clearRedsimCookies(set);
    expect(set).toHaveBeenCalledTimes(3);
    expect(set.mock.calls.map((call) => call[0])).toEqual([
      "redsim_api_session",
      "redsim_csrf",
      "redsim_refresh",
    ]);
    for (const call of set.mock.calls) {
      expect(call[1]).toBe("");
      expect(call[2]).toMatchObject({ maxAge: 0 });
    }
    expect(set.mock.calls[0]?.[2]).toMatchObject({ path: "/", httpOnly: true });
    expect(set.mock.calls[1]?.[2]).toMatchObject({ path: "/", httpOnly: false });
    // A clear has to match the path the cookie was set on, or the browser
    // keeps the original.
    expect(set.mock.calls[2]?.[2]).toMatchObject({ path: "/api/auth", httpOnly: true });
  });
});
