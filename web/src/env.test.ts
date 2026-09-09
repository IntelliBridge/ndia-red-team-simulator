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
    setEnv({ BETTER_AUTH_URL: "http://localhost:3000" });
    await expect(importEnv()).rejects.toThrow(/BETTER_AUTH_SECRET/);
  });

  it("rejects a BETTER_AUTH_SECRET shorter than 32 characters", async () => {
    setEnv({
      BETTER_AUTH_SECRET: "20-characters-here!!",
      BETTER_AUTH_URL: "http://localhost:3000",
    });
    await expect(importEnv()).rejects.toThrow(/BETTER_AUTH_SECRET/);
  });

  it("applies every client default when only the two required names are set", async () => {
    setEnv({
      BETTER_AUTH_SECRET: VALID_SECRET,
      BETTER_AUTH_URL: "http://localhost:3000",
    });
    const env = await importEnv();
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("http://localhost:8000");
    expect(env.NEXT_PUBLIC_REDSIM_ENV).toBe("dev");
    expect(env.NEXT_PUBLIC_REDSIM_API_SESSION_COOKIE).toBe("redsim_api_session");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE).toBe("redsim_csrf");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_HEADER).toBe("X-Redsim-CSRF");
    expect(env.REDSIM_ENV).toBe("dev");
  });

  it("leaves the optional Keycloak and session names undefined", async () => {
    setEnv({
      BETTER_AUTH_SECRET: VALID_SECRET,
      BETTER_AUTH_URL: "http://localhost:3000",
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
    expect(env.BETTER_AUTH_SECRET).toBeUndefined();
    expect(env.BETTER_AUTH_URL).toBeUndefined();
    // The client schema still runs. Next inlines these at build time, so a
    // hatch that switched them off would bake undefined into the image.
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("http://localhost:8000");
    expect(env.NEXT_PUBLIC_REDSIM_CSRF_HEADER).toBe("X-Redsim-CSRF");
    expect(env.REDSIM_ENV).toBe("dev");
  });

  it("still rejects a malformed client value under SKIP_ENV_VALIDATION", async () => {
    setEnv({ SKIP_ENV_VALIDATION: "1", NEXT_PUBLIC_REDSIM_API_URL: "not-a-url" });
    await expect(importEnv()).rejects.toThrow(/NEXT_PUBLIC_REDSIM_API_URL/);
  });

  it("treats an empty string as unset so the default applies", async () => {
    setEnv({
      BETTER_AUTH_SECRET: VALID_SECRET,
      BETTER_AUTH_URL: "http://localhost:3000",
      NEXT_PUBLIC_REDSIM_API_URL: "",
    });
    const env = await importEnv();
    expect(env.NEXT_PUBLIC_REDSIM_API_URL).toBe("http://localhost:8000");
  });

  it("passes explicit values through unchanged", async () => {
    setEnv({
      BETTER_AUTH_SECRET: VALID_SECRET,
      BETTER_AUTH_URL: "https://redsim.example",
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
