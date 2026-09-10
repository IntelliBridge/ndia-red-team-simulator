// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };

async function load() {
  vi.resetModules();
  return import("./refresh-cookie");
}

beforeEach(() => {
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
  } as NodeJS.ProcessEnv;
});

afterEach(() => {
  process.env = { ...savedEnv };
  vi.useRealTimers();
});

describe("the sealed refresh cookie", () => {
  it("round-trips a refresh token and never carries it in the clear", async () => {
    const { sealRefreshToken, openRefreshToken } = await load();
    const sealed = await sealRefreshToken("refresh-token-value", 900);
    expect(sealed).not.toContain("refresh-token-value");
    expect(sealed.split(".")).toHaveLength(5);
    expect(await openRefreshToken(sealed)).toBe("refresh-token-value");
  });

  it("opens to nothing for a missing, tampered or foreign-key cookie", async () => {
    const { sealRefreshToken, openRefreshToken } = await load();
    const sealed = await sealRefreshToken("rt", 900);
    expect(await openRefreshToken(undefined)).toBeUndefined();
    expect(await openRefreshToken("")).toBeUndefined();
    expect(await openRefreshToken(`${sealed.slice(0, -4)}AAAA`)).toBeUndefined();

    process.env.REDSIM_WEB_SESSION_SECRET = "a-different-secret-rotated-in-0123456789";
    const rotated = await load();
    expect(await rotated.openRefreshToken(sealed)).toBeUndefined();
  });

  it("expires with the ttl it was sealed for", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-09T12:00:00Z"));
    const { sealRefreshToken, openRefreshToken } = await load();
    const sealed = await sealRefreshToken("rt", 60);
    vi.setSystemTime(new Date("2026-09-09T12:02:00Z"));
    expect(await openRefreshToken(sealed)).toBeUndefined();
  });

  it("clamps the realm's lifetime into the cookie lifetime", async () => {
    const { refreshTtlSeconds, DEFAULT_REFRESH_TTL_SECONDS, MAX_REFRESH_TTL_SECONDS } = await load();
    expect(refreshTtlSeconds(undefined)).toBe(DEFAULT_REFRESH_TTL_SECONDS);
    expect(refreshTtlSeconds(0)).toBe(DEFAULT_REFRESH_TTL_SECONDS);
    expect(refreshTtlSeconds(-5)).toBe(DEFAULT_REFRESH_TTL_SECONDS);
    expect(refreshTtlSeconds(1800.7)).toBe(1800);
    expect(refreshTtlSeconds(10 * 24 * 3600)).toBe(MAX_REFRESH_TTL_SECONDS);
  });

  it("refuses to seal without the web secret", async () => {
    delete process.env.REDSIM_WEB_SESSION_SECRET;
    process.env.SKIP_ENV_VALIDATION = "1";
    const { sealRefreshToken } = await load();
    await expect(sealRefreshToken("rt", 60)).rejects.toThrow(/REDSIM_WEB_SESSION_SECRET/);
  });
});
