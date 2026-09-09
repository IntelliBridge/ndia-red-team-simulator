// @vitest-environment node
//
// The carry-forward verifier and the cookie attribute builder. These are the
// pieces the refresh route depends on for the property R22 names: a cookie
// that is authentic but belongs to someone else must be rejected.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportPKCS8, generateKeyPair, SignJWT } from "jose";

const savedEnv = { ...process.env };

async function keypair() {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  return exportPKCS8(privateKey);
}

/** Mint a redsim_api_session-shaped token with the given key and overrides. */
async function mint(
  pem: string,
  overrides: {
    sub?: string;
    email?: string;
    issuer?: string;
    audience?: string;
    expired?: boolean;
  } = {},
) {
  const { importPKCS8 } = await import("jose");
  const key = await importPKCS8(pem, "RS256");
  const jwt = new SignJWT({
    email: overrides.email ?? "user@redsim.local",
    name: "Test User",
    redsim_project_roles: { default: "approver" },
  })
    .setProtectedHeader({ alg: "RS256", kid: "kid-test" })
    .setIssuer(overrides.issuer ?? "redsim-api-session")
    .setAudience(overrides.audience ?? "redsim-api")
    .setSubject(overrides.sub ?? "kc-sub-123")
    .setIssuedAt();
  return overrides.expired
    ? jwt.setExpirationTime("-1h").sign(key)
    : jwt.setExpirationTime("900s").sign(key);
}

async function load() {
  vi.resetModules();
  return import("./redsim-cookies");
}

beforeEach(() => {
  process.env = {
    ...savedEnv,
    BETTER_AUTH_SECRET: "test-not-a-real-secret-change-me-0123456789",
    BETTER_AUTH_URL: "http://localhost:3000",
    REDSIM_API_SESSION_KEY_ID: "kid-test",
    REDSIM_API_SESSION_TTL_SECONDS: "900",
    REDSIM_ENV: "dev",
  } as NodeJS.ProcessEnv;
});

afterEach(() => {
  process.env = { ...savedEnv };
});

describe("redsim cookie attributes", () => {
  it("makes the session cookie httpOnly and the csrf cookie readable", async () => {
    const { redsimCookieOptions } = await load();
    expect(redsimCookieOptions("session")).toMatchObject({
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 900,
      secure: false,
    });
    expect(redsimCookieOptions("csrf")).toMatchObject({ httpOnly: false });
  });

  it("marks both Secure only under REDSIM_ENV=prod", async () => {
    process.env.REDSIM_ENV = "prod";
    const { redsimCookieOptions } = await load();
    expect(redsimCookieOptions("session").secure).toBe(true);
    expect(redsimCookieOptions("csrf").secure).toBe(true);
  });

  it("clears both cookies with maxAge 0", async () => {
    const { clearRedsimCookies } = await load();
    const set = vi.fn();
    clearRedsimCookies(set);
    expect(set).toHaveBeenCalledTimes(2);
    for (const call of set.mock.calls) {
      expect(call[1]).toBe("");
      expect(call[2]).toMatchObject({ maxAge: 0, path: "/" });
    }
  });
});

describe("claims read from the linked account", () => {
  it("takes the Keycloak sub from accountId and the roles from the id_token", async () => {
    const { claimsFromAccount } = await load();
    const idToken = [
      "e30",
      Buffer.from(
        JSON.stringify({
          email: "user@redsim.local",
          name: "Test User",
          redsim_project_roles: { default: "approver" },
        }),
      ).toString("base64url"),
      "sig",
    ].join(".");
    expect(
      claimsFromAccount({ accountId: "kc-sub-123", idToken }),
    ).toEqual({
      sub: "kc-sub-123",
      email: "user@redsim.local",
      name: "Test User",
      projectMemberships: { default: "approver" },
    });
  });

  it("returns an empty roles map rather than throwing on a missing id_token", async () => {
    const { claimsFromAccount } = await load();
    expect(
      claimsFromAccount(
        { accountId: "kc-sub-123" },
        { email: "fallback@redsim.local", name: "Fallback" },
      ),
    ).toEqual({
      sub: "kc-sub-123",
      email: "fallback@redsim.local",
      name: "Fallback",
      projectMemberships: {},
    });
  });
});

describe("carry-forward verification binds to the caller", () => {
  it("returns the claims for a valid cookie belonging to the caller", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem);
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toEqual({
      sub: "kc-sub-123",
      email: "user@redsim.local",
      name: "Test User",
      projectMemberships: { default: "approver" },
    });
  });

  it("matches the email case-insensitively", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem, { email: "User@Redsim.Local" });
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toMatchObject({ sub: "kc-sub-123" });
  });

  it("rejects an authentic cookie minted for a different user", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    // Correctly signed, correct issuer and audience, wrong owner. Re-minting
    // from this would hand user A user B's roles.
    const token = await mint(pem, { sub: "kc-sub-999", email: "b@redsim.local" });
    await expect(
      verifyOwnSessionCookie(token, "a@redsim.local"),
    ).resolves.toBeUndefined();
  });

  it("rejects a cookie signed by another key", async () => {
    const pem = await keypair();
    const foreign = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(foreign);
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toBeUndefined();
  });

  it("rejects a foreign audience", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem, { audience: "some-other-api" });
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toBeUndefined();
  });

  it("rejects a foreign issuer", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem, { issuer: "someone-elses-issuer" });
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toBeUndefined();
  });

  it("rejects an expired cookie", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem, { expired: true });
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toBeUndefined();
  });

  it("returns nothing when the cookie or the caller email is missing", async () => {
    const pem = await keypair();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = pem;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem);
    await expect(
      verifyOwnSessionCookie(undefined, "user@redsim.local"),
    ).resolves.toBeUndefined();
    await expect(verifyOwnSessionCookie(token, undefined)).resolves.toBeUndefined();
  });

  it("returns nothing when the signing key is unset", async () => {
    const pem = await keypair();
    delete process.env.REDSIM_API_SESSION_PRIVATE_KEY;
    const { verifyOwnSessionCookie } = await load();
    const token = await mint(pem);
    await expect(
      verifyOwnSessionCookie(token, "user@redsim.local"),
    ).resolves.toBeUndefined();
  });
});
