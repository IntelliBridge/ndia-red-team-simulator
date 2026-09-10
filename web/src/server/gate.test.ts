// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };
const BASE_ENV: Record<string, string> = {
  REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
  REDSIM_WEB_ORIGIN: "http://localhost:3000",
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
