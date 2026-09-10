// @vitest-environment node
//
// The identity module against a fake realm: a JWKS document and a token
// endpoint served by a stubbed fetch, with an RS256 key generated per file.
// Every case re-imports the module so the realm it caches is the one the case
// configured.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const ISSUER = "http://idp.internal.test/realms/redsim";
const PUBLIC_ISSUER = "https://app.test/auth/realms/redsim";
const CLIENT_ID = "redsim-web";
const savedEnv = { ...process.env };

let privateKey: CryptoKey;
let jwks: { keys: unknown[] };

async function idToken(claims: Record<string, unknown>, opts: { issuer?: string; audience?: string; expired?: boolean } = {}) {
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? CLIENT_ID)
    .setSubject(typeof claims.sub === "string" ? claims.sub : "kc-sub-1")
    .setIssuedAt();
  return (opts.expired ? jwt.setExpirationTime("-5m") : jwt.setExpirationTime("5m")).sign(privateKey);
}

type TokenAnswer = { status: number; body: unknown } | "unreachable";

/** A fetch that serves the JWKS and answers the token and logout endpoints as told. */
function fakeRealm(tokenAnswer: TokenAnswer, logoutStatus = 204) {
  const calls: { url: string; body: URLSearchParams }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/certs")) return Response.json(jwks);
    const body = new URLSearchParams(String(init?.body ?? ""));
    calls.push({ url, body });
    if (url.endsWith("/logout")) return new Response(null, { status: logoutStatus });
    if (url.endsWith("/token")) {
      if (tokenAnswer === "unreachable") throw new TypeError("fetch failed");
      return Response.json(tokenAnswer.body, { status: tokenAnswer.status });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  return { fetchImpl, calls };
}

async function load() {
  vi.resetModules();
  return import("./identity");
}

beforeEach(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
    KEYCLOAK_ISSUER: ISSUER,
    KEYCLOAK_PUBLIC_ISSUER: PUBLIC_ISSUER,
    KEYCLOAK_CLIENT_ID: CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET: "fake-client-secret-not-real",
  } as NodeJS.ProcessEnv;
});

afterEach(() => {
  process.env = { ...savedEnv };
  vi.unstubAllGlobals();
});

const CLAIMS = {
  sub: "kc-sub-1",
  email: "Alice@Redsim.Local",
  name: "Alice",
  redsim_project_roles: { default: "approver" },
};

describe("loginWithPassword", () => {
  it("posts the password grant with the client credentials and returns the verified claims", async () => {
    const realm = fakeRealm({
      status: 200,
      body: { id_token: await idToken(CLAIMS), refresh_token: "rt-1", refresh_expires_in: 1800 },
    });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { loginWithPassword } = await load();

    const result = await loginWithPassword("alice@redsim.local", "correct horse", realm.fetchImpl);

    expect(result).toEqual({
      ok: true,
      claims: {
        sub: "kc-sub-1",
        email: "Alice@Redsim.Local",
        name: "Alice",
        projectMemberships: { default: "approver" },
      },
      refreshToken: "rt-1",
      refreshExpiresIn: 1800,
    });
    const [call] = realm.calls;
    expect(call?.url).toBe(`${ISSUER}/protocol/openid-connect/token`);
    expect(Object.fromEntries(call!.body)).toEqual({
      grant_type: "password",
      client_id: CLIENT_ID,
      client_secret: "fake-client-secret-not-real",
      username: "alice@redsim.local",
      password: "correct horse",
      scope: "openid",
    });
  });

  it("sends no client_secret for a public client", async () => {
    delete process.env.KEYCLOAK_CLIENT_SECRET;
    const realm = fakeRealm({ status: 200, body: { id_token: await idToken(CLAIMS) } });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { loginWithPassword } = await load();

    const result = await loginWithPassword("a@b.c", "pw", realm.fetchImpl);

    expect(result.ok).toBe(true);
    expect(realm.calls[0]!.body.has("client_secret")).toBe(false);
    if (result.ok) expect(result.refreshToken).toBeUndefined();
  });

  it("accepts an id_token stamped with the public issuer", async () => {
    const realm = fakeRealm({
      status: 200,
      body: { id_token: await idToken(CLAIMS, { issuer: PUBLIC_ISSUER }) },
    });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { loginWithPassword } = await load();
    expect((await loginWithPassword("a@b.c", "pw", realm.fetchImpl)).ok).toBe(true);
  });

  it("maps the realm's refusals to codes without leaking its wording", async () => {
    const cases: [unknown, string][] = [
      [{ error: "invalid_grant", error_description: "Invalid user credentials" }, "invalid_credentials"],
      [{ error: "invalid_grant", error_description: "Account disabled" }, "account_disabled"],
      [{ error: "invalid_grant", error_description: "Account is not fully set up" }, "account_disabled"],
      [{ error: "invalid_grant", error_description: "Account temporarily disabled" }, "account_locked"],
      [{ error: "unauthorized_client", error_description: "Client not allowed for direct access grants" }, "not_configured"],
      [{ error: "invalid_client" }, "not_configured"],
      [{}, "invalid_credentials"],
    ];
    for (const [body, code] of cases) {
      const realm = fakeRealm({ status: 401, body });
      vi.stubGlobal("fetch", realm.fetchImpl);
      const { loginWithPassword } = await load();
      const result = await loginWithPassword("a@b.c", "pw", realm.fetchImpl);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code, JSON.stringify(body)).toBe(code);
    }
  });

  it("reads an unreachable realm and a 5xx as unavailable", async () => {
    for (const answer of ["unreachable", { status: 502, body: "bad gateway" }] as TokenAnswer[]) {
      const realm = fakeRealm(answer);
      vi.stubGlobal("fetch", realm.fetchImpl);
      const { loginWithPassword } = await load();
      const result = await loginWithPassword("a@b.c", "pw", realm.fetchImpl);
      expect(result).toMatchObject({ ok: false, code: "unavailable" });
    }
  });

  it("refuses an id_token it cannot verify: wrong key, wrong audience, expired, foreign issuer", async () => {
    const other = await generateKeyPair("RS256");
    const forged = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setSubject("kc-sub-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(other.privateKey);
    const tokens: [string, string][] = [
      [forged, "unavailable"],
      [await idToken(CLAIMS, { audience: "someone-else" }), "unavailable"],
      [await idToken(CLAIMS, { expired: true }), "unavailable"],
      [await idToken(CLAIMS, { issuer: "http://evil.test/realms/redsim" }), "not_configured"],
    ];
    for (const [token, code] of tokens) {
      const realm = fakeRealm({ status: 200, body: { id_token: token } });
      vi.stubGlobal("fetch", realm.fetchImpl);
      const { loginWithPassword } = await load();
      const result = await loginWithPassword("a@b.c", "pw", realm.fetchImpl);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(code);
    }
  });

  it("is not_configured when the realm issued no id_token or no realm is configured", async () => {
    const realm = fakeRealm({ status: 200, body: { access_token: "only" } });
    vi.stubGlobal("fetch", realm.fetchImpl);
    let mod = await load();
    expect(await mod.loginWithPassword("a@b.c", "pw", realm.fetchImpl)).toMatchObject({
      ok: false,
      code: "not_configured",
    });

    delete process.env.KEYCLOAK_ISSUER;
    mod = await load();
    expect(await mod.loginWithPassword("a@b.c", "pw", realm.fetchImpl)).toMatchObject({
      ok: false,
      code: "not_configured",
    });
    expect(realm.calls).toHaveLength(1);
  });

  it("drops roles that are not an object", async () => {
    const realm = fakeRealm({
      status: 200,
      body: { id_token: await idToken({ ...CLAIMS, redsim_project_roles: ["admin"] }) },
    });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { loginWithPassword } = await load();
    const result = await loginWithPassword("a@b.c", "pw", realm.fetchImpl);
    if (result.ok) expect(result.claims.projectMemberships).toEqual({});
    else throw new Error(result.code);
  });
});

describe("refreshWithToken", () => {
  it("posts the refresh grant and returns rotated tokens", async () => {
    const realm = fakeRealm({
      status: 200,
      body: { id_token: await idToken(CLAIMS), refresh_token: "rt-2", refresh_expires_in: 1700 },
    });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { refreshWithToken } = await load();

    const result = await refreshWithToken("rt-1", realm.fetchImpl);

    expect(result).toMatchObject({ ok: true, refreshToken: "rt-2", refreshExpiresIn: 1700 });
    expect(Object.fromEntries(realm.calls[0]!.body)).toMatchObject({
      grant_type: "refresh_token",
      refresh_token: "rt-1",
    });
  });

  it("reads a refused refresh token as session_ended", async () => {
    const realm = fakeRealm({
      status: 400,
      body: { error: "invalid_grant", error_description: "Session not active" },
    });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { refreshWithToken } = await load();
    expect(await refreshWithToken("rt-old", realm.fetchImpl)).toMatchObject({
      ok: false,
      code: "session_ended",
    });
  });
});

describe("revokeRefreshToken", () => {
  it("posts the token to the logout endpoint with the client credentials", async () => {
    const realm = fakeRealm({ status: 200, body: {} });
    vi.stubGlobal("fetch", realm.fetchImpl);
    const { revokeRefreshToken } = await load();

    expect(await revokeRefreshToken("rt-1", realm.fetchImpl)).toBe(true);
    expect(realm.calls[0]!.url).toBe(`${ISSUER}/protocol/openid-connect/logout`);
    expect(Object.fromEntries(realm.calls[0]!.body)).toEqual({
      client_id: CLIENT_ID,
      client_secret: "fake-client-secret-not-real",
      refresh_token: "rt-1",
    });
  });

  it("swallows an unreachable realm and a refusal", async () => {
    const unreachable = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    const { revokeRefreshToken } = await load();
    expect(await revokeRefreshToken("rt-1", unreachable)).toBe(false);
    const refused = fakeRealm({ status: 200, body: {} }, 400);
    expect(await revokeRefreshToken("rt-1", refused.fetchImpl)).toBe(false);
  });
});

describe("statusForFailure", () => {
  it("answers 401 for a refused credential and 503 for a realm problem", async () => {
    const { statusForFailure } = await load();
    expect(statusForFailure("invalid_credentials")).toBe(401);
    expect(statusForFailure("account_disabled")).toBe(401);
    expect(statusForFailure("account_locked")).toBe(401);
    expect(statusForFailure("session_ended")).toBe(401);
    expect(statusForFailure("not_configured")).toBe(503);
    expect(statusForFailure("unavailable")).toBe(503);
  });
});
