// @vitest-environment node
//
// The env module validates once per module graph, so every case re-imports it
// through vi.resetModules() with process.env rebuilt from scratch. Node rather
// than jsdom because @t3-oss/env-nextjs skips the server schema entirely when
// a window object is present, which would make the required-variable cases
// pass for the wrong reason.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };

/** Replace process.env wholesale so no ambient value leaks into a case. */
function setEnv(values: Record<string, string>) {
  process.env = { ...values } as NodeJS.ProcessEnv;
}

async function importEnv() {
  vi.resetModules();
  return (await import("./env.js")).env;
}

const VALID_SECRET = "test-not-a-real-secret-change-me-0123456789";

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  process.env = { ...savedEnv };
});

describe("web env schema", () => {
  it("throws naming the variable when a required server name is missing", async () => {
    setEnv({ REDSIM_WEB_ORIGIN: "http://localhost:3000" });
    await expect(importEnv()).rejects.toThrow(/REDSIM_WEB_SESSION_SECRET/);
  });

  it("rejects a REDSIM_WEB_SESSION_SECRET shorter than 32 characters", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: "20-characters-here!!",
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
    });
    await expect(importEnv()).rejects.toThrow(/REDSIM_WEB_SESSION_SECRET/);
  });

  it("applies every client default when only the two required names are set", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
    });
    const env = await importEnv();
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("http://localhost:8000");
    expect(env.NEXT_PUBLIC_REDSIM_ENV).toBe("dev");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE).toBe("redsim_csrf");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_HEADER).toBe("X-Redsim-CSRF");
    expect(env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES).toBe(false);
    expect(env.REDSIM_ENV).toBe("dev");
  });

  it("no longer exposes the httpOnly session cookie name to the client", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
      NEXT_PUBLIC_REDSIM_API_SESSION_COOKIE: "redsim_api_session",
    });
    const env = await importEnv();
    expect("NEXT_PUBLIC_REDSIM_API_SESSION_COOKIE" in env).toBe(false);
  });

  it("defaults the three server-side cookie names and the API base", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
    });
    const env = await importEnv();
    expect(env.REDSIM_API_SESSION_COOKIE).toBe("redsim_api_session");
    expect(env.REDSIM_CSRF_COOKIE).toBe("redsim_csrf");
    expect(env.REDSIM_REFRESH_COOKIE).toBe("redsim_refresh");
    expect(env.REDSIM_API_URL).toBe("http://localhost:8000");
    expect(env.REDSIM_DEV_FIXTURES).toBe(false);
  });

  it("rejects a malformed REDSIM_API_URL by name", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
      REDSIM_API_URL: "not-a-url",
    });
    await expect(importEnv()).rejects.toThrow(/REDSIM_API_URL/);
  });

  it("reads the fixture flags as booleans from the spellings an operator writes", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
      REDSIM_ENV: "test",
      REDSIM_DEV_FIXTURES: "1",
      NEXT_PUBLIC_REDSIM_DEV_FIXTURES: "TRUE",
    });
    const env = await importEnv();
    expect(env.REDSIM_DEV_FIXTURES).toBe(true);
    expect(env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES).toBe(true);
  });

  it("refuses the server fixture flag outside the dev or test allowlist", async () => {
    for (const redsimEnv of ["prod", "staging"]) {
      setEnv({
        REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
        REDSIM_WEB_ORIGIN: "http://localhost:3000",
        REDSIM_ENV: redsimEnv,
        REDSIM_DEV_FIXTURES: "1",
      });
      await expect(importEnv()).rejects.toThrow(/REDSIM_DEV_FIXTURES/);
    }
  });

  it("refuses the public fixture flag in prod, naming both variables", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
      REDSIM_ENV: "prod",
      REDSIM_DEV_FIXTURES: "1",
      NEXT_PUBLIC_REDSIM_DEV_FIXTURES: "1",
    });
    const error = await importEnv().catch((e: unknown) => e as Error);
    expect(String(error)).toMatch(/REDSIM_DEV_FIXTURES/);
    expect(String(error)).toMatch(/NEXT_PUBLIC_REDSIM_DEV_FIXTURES/);
  });

  it("honours fixture mode when REDSIM_ENV is unset, because the default is dev", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
      REDSIM_DEV_FIXTURES: "1",
    });
    const env = await importEnv();
    expect(env.REDSIM_DEV_FIXTURES).toBe(true);
  });

  it("keeps the fixture refinement live under SKIP_ENV_VALIDATION", async () => {
    setEnv({
      SKIP_ENV_VALIDATION: "1",
      REDSIM_ENV: "prod",
      NEXT_PUBLIC_REDSIM_DEV_FIXTURES: "1",
    });
    await expect(importEnv()).rejects.toThrow(/NEXT_PUBLIC_REDSIM_DEV_FIXTURES/);
  });

  it("leaves the optional Keycloak and session names undefined", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
    });
    const env = await importEnv();
    expect(env.KEYCLOAK_ISSUER).toBeUndefined();
    expect(env.KEYCLOAK_CLIENT_ID).toBeUndefined();
    expect(env.KEYCLOAK_CLIENT_SECRET).toBeUndefined();
    expect(env.REDSIM_API_SESSION_PRIVATE_KEY).toBeUndefined();
  });

  it("relaxes only the required server names under SKIP_ENV_VALIDATION", async () => {
    setEnv({ SKIP_ENV_VALIDATION: "1" });
    const env = await importEnv();
    expect(env.REDSIM_WEB_SESSION_SECRET).toBeUndefined();
    expect(env.REDSIM_WEB_ORIGIN).toBeUndefined();
    // The client schema still runs. Next inlines these at build time, so a
    // hatch that switched them off would bake undefined into the image.
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("http://localhost:8000");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_HEADER).toBe("X-Redsim-CSRF");
    expect(env.REDSIM_ENV).toBe("dev");
    expect(env.REDSIM_API_URL).toBe("http://localhost:8000");
  });

  it("still rejects a malformed client value under SKIP_ENV_VALIDATION", async () => {
    setEnv({ SKIP_ENV_VALIDATION: "1", NEXT_PUBLIC_REDSIM_API_URL: "not-a-url" });
    await expect(importEnv()).rejects.toThrow(/NEXT_PUBLIC_REDSIM_API_URL/);
  });

  it("treats an empty string as unset so the default applies", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "http://localhost:3000",
      NEXT_PUBLIC_REDSIM_API_URL: "",
    });
    const env = await importEnv();
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("http://localhost:8000");
  });

  it("passes explicit values through unchanged", async () => {
    setEnv({
      REDSIM_WEB_SESSION_SECRET: VALID_SECRET,
      REDSIM_WEB_ORIGIN: "https://redsim.example",
      REDSIM_ENV: "prod",
      KEYCLOAK_ISSUER: "http://keycloak:8080/realms/redsim",
      KEYCLOAK_CLIENT_ID: "redsim-web",
      NEXT_PUBLIC_REDSIM_API_URL: "https://api.redsim.example",
      NEXT_PUBLIC_REDSIM_CSRF_HEADER: "X-Other",
    });
    const env = await importEnv();
    expect(env.REDSIM_ENV).toBe("prod");
    expect(env.KEYCLOAK_ISSUER).toBe("http://keycloak:8080/realms/redsim");
    expect(env.KEYCLOAK_CLIENT_ID).toBe("redsim-web");
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("https://api.redsim.example");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_HEADER).toBe("X-Other");
  });
});
