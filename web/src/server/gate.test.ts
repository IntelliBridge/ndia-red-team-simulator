// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };
const BASE_ENV: Record<string, string> = {
  BETTER_AUTH_SECRET: "test-not-a-real-secret-change-me-0123456789",
  BETTER_AUTH_URL: "http://localhost:3000",
};

function setEnv(values: Record<string, string> = {}) {
  const merged: Record<string, string> = { ...BASE_ENV, ...values };
  process.env = merged as NodeJS.ProcessEnv;
}

async function loadGate() {
  vi.resetModules();
  return import("./gate");
}

/** Obviously fake, and never a value this repo mints. */
const FAKE_SECRET = "hop-test-key-not-a-real-secret-0123456789";
const FAKE_COOKIE = "fake-session-cookie-value";

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  process.env = { ...savedEnv };
});

describe("gateDecision", () => {
  it("passes an app route that carries the session cookie", async () => {
    setEnv();
    const { gateDecision } = await loadGate();
    expect(
      gateDecision({ pathname: "/runs", hasSessionCookie: true, hasDevTokenCookie: false }),
    ).toEqual({ action: "pass" });
  });

  it("redirects an app route with no cookie to /login", async () => {
    setEnv();
    const { gateDecision } = await loadGate();
    expect(
      gateDecision({ pathname: "/runs", hasSessionCookie: false, hasDevTokenCookie: false }),
    ).toEqual({ action: "redirect", to: "/login" });
  });

  it("redirects an authenticated /login to /dashboard and passes it otherwise", async () => {
    setEnv();
    const { gateDecision } = await loadGate();
    expect(
      gateDecision({ pathname: "/login", hasSessionCookie: true, hasDevTokenCookie: false }),
    ).toEqual({ action: "redirect", to: "/dashboard" });
    expect(
      gateDecision({ pathname: "/login", hasSessionCookie: false, hasDevTokenCookie: false }),
    ).toEqual({ action: "pass" });
  });

  it("accepts the dev cookie as a pass only inside the dev or test allowlist", async () => {
    setEnv({ REDSIM_ENV: "dev" });
    const dev = await loadGate();
    expect(
      dev.gateDecision({ pathname: "/runs", hasSessionCookie: false, hasDevTokenCookie: true }),
    ).toEqual({ action: "pass" });

    setEnv({ REDSIM_ENV: "staging" });
    const staging = await loadGate();
    expect(
      staging.gateDecision({ pathname: "/runs", hasSessionCookie: false, hasDevTokenCookie: true }),
    ).toEqual({ action: "redirect", to: "/login" });
  });

  it("passes every route in fixture mode", async () => {
    setEnv({ REDSIM_ENV: "test", REDSIM_DEV_FIXTURES: "1" });
    const { gateDecision } = await loadGate();
    expect(
      gateDecision({ pathname: "/runs", hasSessionCookie: false, hasDevTokenCookie: false }),
    ).toEqual({ action: "pass" });
  });
});

describe("hop token", () => {
  it("round-trips for the credential it was minted against", async () => {
    setEnv();
    const { mintHopToken, verifyHopToken } = await loadGate();
    const token = await mintHopToken(FAKE_SECRET, FAKE_COOKIE, 1_000);
    expect(await verifyHopToken(FAKE_SECRET, token, FAKE_COOKIE, 1_000)).toBe(true);
    expect(await verifyHopToken(FAKE_SECRET, token, FAKE_COOKIE, 1_030)).toBe(true);
  });

  it("refuses a token minted for a different cookie value", async () => {
    setEnv();
    const { mintHopToken, verifyHopToken } = await loadGate();
    const token = await mintHopToken(FAKE_SECRET, FAKE_COOKIE, 1_000);
    expect(await verifyHopToken(FAKE_SECRET, token, "some-other-value", 1_000)).toBe(false);
  });

  it("refuses an expired token, a future token and a token under another key", async () => {
    setEnv();
    const { HOP_TOKEN_TTL_SECONDS, mintHopToken, verifyHopToken } = await loadGate();
    const token = await mintHopToken(FAKE_SECRET, FAKE_COOKIE, 1_000);
    expect(
      await verifyHopToken(FAKE_SECRET, token, FAKE_COOKIE, 1_000 + HOP_TOKEN_TTL_SECONDS + 1),
    ).toBe(false);
    expect(await verifyHopToken(FAKE_SECRET, token, FAKE_COOKIE, 900)).toBe(false);
    expect(await verifyHopToken("a-different-fake-key-0123456789ab", token, FAKE_COOKIE, 1_000)).toBe(
      false,
    );
  });

  it("refuses a malformed token and a request that carries no credential", async () => {
    setEnv();
    const { mintHopToken, verifyHopToken } = await loadGate();
    const token = await mintHopToken(FAKE_SECRET, FAKE_COOKIE, 1_000);
    expect(await verifyHopToken(FAKE_SECRET, "", FAKE_COOKIE, 1_000)).toBe(false);
    expect(await verifyHopToken(FAKE_SECRET, "no-dot", FAKE_COOKIE, 1_000)).toBe(false);
    expect(await verifyHopToken(FAKE_SECRET, ".abc", FAKE_COOKIE, 1_000)).toBe(false);
    expect(await verifyHopToken(FAKE_SECRET, token, undefined, 1_000)).toBe(false);
  });
});
