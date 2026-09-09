// @vitest-environment node
//
// The Better Auth instance driven end to end against a mock OIDC IdP: no live
// Keycloak, no network. Discovery, JWKS, authorize, the PKCE token exchange
// and userinfo are all served from an in-process fetch stub, and every request
// goes through auth.handler with real Request objects, so what these cases
// assert is the response the browser would actually receive.
//
// Every case re-imports the module graph, because config.ts, redsim-cookies.ts
// and the frozen redsim-session.ts all read process.env at module load.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  exportPKCS8,
  exportJWK,
  generateKeyPair,
  importSPKI,
  jwtVerify,
  decodeProtectedHeader,
  SignJWT,
} from "jose";
import { createPublicKey } from "node:crypto";

const ISSUER = "http://mock-idp.test/realms/redsim";
const BASE_URL = "http://localhost:3000";
const SECRET = "test-not-a-real-secret-change-me-0123456789";
const KID = "kid-test";

const savedEnv = { ...process.env };

type IdpClaims = Record<string, unknown>;

/** A mock realm: discovery, JWKS, token and userinfo over a fetch stub. */
async function mockIdp(claims: IdpClaims, opts: { reachable?: boolean } = {}) {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: "mock-kid",
    alg: "RS256",
    use: "sig",
  };
  let nonce: string | undefined;

  const idToken = (extra: IdpClaims = {}) =>
    new SignJWT({ ...claims, ...extra })
      .setProtectedHeader({ alg: "RS256", kid: "mock-kid" })
      .setIssuer(ISSUER)
      .setAudience("redsim-web")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    if (opts.reachable === false) throw new TypeError("fetch failed");
    if (url.endsWith("/.well-known/openid-configuration")) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
        token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
        userinfo_endpoint: `${ISSUER}/protocol/openid-connect/userinfo`,
        jwks_uri: `${ISSUER}/protocol/openid-connect/certs`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (url.endsWith("/certs")) return Response.json({ keys: [jwk] });
    if (url.endsWith("/token")) {
      return Response.json({
        access_token: "mock-access-token",
        refresh_token: "mock-refresh-token",
        id_token: await idToken({ nonce }),
        token_type: "Bearer",
        expires_in: 300,
      });
    }
    if (url.endsWith("/userinfo")) return Response.json(claims);
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof fetch;

  return {
    fetchImpl,
    setNonce: (value: string | undefined) => {
      nonce = value;
    },
  };
}

/** An RSA keypair standing in for the operator-supplied signing key. */
async function signingKey() {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  return { pem: await exportPKCS8(privateKey), publicKey };
}

/** Run a full sign-in and callback, returning the callback response. */
async function login(auth: {
  handler: (req: Request) => Promise<Response>;
}, setNonce: (value: string | undefined) => void) {
  const signIn = await auth.handler(
    new Request(`${BASE_URL}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE_URL },
      body: JSON.stringify({ provider: "keycloak", callbackURL: "/dashboard" }),
    }),
  );
  const body = (await signIn.json()) as { url?: string };
  const authorize = new URL(body.url ?? "");
  setNonce(authorize.searchParams.get("nonce") ?? undefined);
  const state = authorize.searchParams.get("state") ?? "";
  return auth.handler(
    new Request(
      `${BASE_URL}/api/auth/callback/keycloak?code=mock-code&state=${encodeURIComponent(state)}`,
      { headers: { cookie: signIn.headers.getSetCookie().join("; ") } },
    ),
  );
}

/** Parse Set-Cookie headers into name -> raw header string. */
function cookieMap(res: Response): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of res.headers.getSetCookie()) {
    out.set(raw.slice(0, raw.indexOf("=")), raw);
  }
  return out;
}

function cookieValue(raw: string): string {
  return decodeURIComponent(raw.slice(raw.indexOf("=") + 1, raw.indexOf(";")));
}

async function buildAuth() {
  vi.resetModules();
  const { createAuth } = await import("./config");
  return createAuth();
}

const KEYCLOAK_CLAIMS = {
  sub: "kc-sub-123",
  email: "User@Redsim.Local",
  name: "Test User",
  email_verified: true,
  redsim_project_roles: { default: "approver", other: "viewer" },
};

beforeEach(() => {
  process.env = {
    ...savedEnv,
    BETTER_AUTH_SECRET: SECRET,
    BETTER_AUTH_URL: BASE_URL,
    KEYCLOAK_ISSUER: ISSUER,
    KEYCLOAK_CLIENT_ID: "redsim-web",
    KEYCLOAK_CLIENT_SECRET: "",
    REDSIM_API_SESSION_KEY_ID: KID,
    REDSIM_API_SESSION_TTL_SECONDS: "900",
    REDSIM_ENV: "dev",
  } as NodeJS.ProcessEnv;
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  process.env = { ...savedEnv };
});

describe("Better Auth Keycloak login mints the FastAPI cookie", () => {
  it("sets redsim_api_session httpOnly and redsim_csrf readable, both Lax and 900s", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const res = await login(await buildAuth(), idp.setNonce);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard");

    const cookies = cookieMap(res);
    const session = cookies.get("redsim_api_session");
    const csrf = cookies.get("redsim_csrf");
    expect(session).toBeDefined();
    expect(csrf).toBeDefined();
    expect(session).toMatch(/HttpOnly/i);
    expect(csrf).not.toMatch(/HttpOnly/i);
    for (const raw of [session!, csrf!]) {
      expect(raw).toMatch(/SameSite=Lax/i);
      expect(raw).toMatch(/Path=\//i);
      expect(raw).toMatch(/Max-Age=900/i);
      // REDSIM_ENV is dev here.
      expect(raw).not.toMatch(/Secure/i);
    }
  });

  it("signs the Keycloak sub, not Better Auth's per-login user id", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const res = await login(await buildAuth(), idp.setNonce);
    const token = cookieValue(cookieMap(res).get("redsim_api_session")!);

    expect(decodeProtectedHeader(token)).toMatchObject({
      alg: "RS256",
      kid: KID,
    });
    const spki = createPublicKey(key.pem)
      .export({ type: "spki", format: "pem" })
      .toString();
    const { payload } = await jwtVerify(token, await importSPKI(spki, "RS256"), {
      issuer: "redsim-api-session",
      audience: "redsim-api",
    });
    expect(payload.sub).toBe("kc-sub-123");
    expect(payload["email"]).toBe("User@Redsim.Local");
    expect(payload["name"]).toBe("Test User");
    expect(payload["redsim_project_roles"]).toEqual({
      default: "approver",
      other: "viewer",
    });
    expect(payload.jti).toMatch(/^[0-9a-f]{32}$/);
  });

  it("keeps the same sub across two logins while the session identity differs", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;

    const subs: string[] = [];
    const sessionCookies: string[] = [];
    for (let i = 0; i < 2; i += 1) {
      const idp = await mockIdp(KEYCLOAK_CLAIMS);
      vi.stubGlobal("fetch", idp.fetchImpl);
      const res = await login(await buildAuth(), idp.setNonce);
      const cookies = cookieMap(res);
      subs.push(
        JSON.parse(
          Buffer.from(
            cookieValue(cookies.get("redsim_api_session")!).split(".")[1]!,
            "base64url",
          ).toString(),
        ).sub as string,
      );
      sessionCookies.push(
        cookieValue(cookies.get("better-auth.session_token")!),
      );
    }
    expect(subs[0]).toBe("kc-sub-123");
    expect(subs[1]).toBe("kc-sub-123");
    // Two separate instances, two separate memory adapters: the Better Auth
    // session identity is fresh each time, which is exactly why it must not
    // reach the sub claim.
    expect(sessionCookies[0]).not.toBe(sessionCookies[1]);
  });

  it("completes the login and sets no redsim cookies when the signing key is unset", async () => {
    delete process.env.REDSIM_API_SESSION_PRIVATE_KEY;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const res = await login(await buildAuth(), idp.setNonce);
    expect(res.status).toBe(302);
    const cookies = cookieMap(res);
    expect(cookies.has("redsim_api_session")).toBe(false);
    expect(cookies.has("redsim_csrf")).toBe(false);
    // The Better Auth session still exists, so the user sees the UI shell and
    // API calls surface 401.
    expect(cookies.has("better-auth.session_token")).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it("marks every cookie Secure under REDSIM_ENV=prod, not only the redsim pair", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    process.env.REDSIM_ENV = "prod";
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const res = await login(await buildAuth(), idp.setNonce);
    const raws = res.headers.getSetCookie();
    expect(raws.length).toBeGreaterThan(0);
    for (const raw of raws) expect(raw).toMatch(/Secure/i);
  });

  it("completes the PKCE exchange with an empty client secret", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    process.env.KEYCLOAK_CLIENT_SECRET = "";
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    const seen: string[] = [];
    vi.stubGlobal("fetch", (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(typeof input === "string" ? input : input.toString());
      return idp.fetchImpl(input, init);
    }) as typeof fetch);

    const auth = await buildAuth();
    const signIn = await auth.handler(
      new Request(`${BASE_URL}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE_URL },
        body: JSON.stringify({ provider: "keycloak", callbackURL: "/dashboard" }),
      }),
    );
    const body = (await signIn.json()) as { url?: string };
    const authorize = new URL(body.url ?? "");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorize.searchParams.get("code_challenge")).toBeTruthy();
    expect(authorize.searchParams.get("nonce")).toBeTruthy();

    idp.setNonce(authorize.searchParams.get("nonce") ?? undefined);
    const res = await auth.handler(
      new Request(
        `${BASE_URL}/api/auth/callback/keycloak?code=mock-code&state=${encodeURIComponent(
          authorize.searchParams.get("state") ?? "",
        )}`,
        { headers: { cookie: signIn.headers.getSetCookie().join("; ") } },
      ),
    );
    expect(res.status).toBe(302);
    expect(seen.some((url) => url.endsWith("/token"))).toBe(true);
  });

  it("stores no account cookie, so the id_token never reaches the browser", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const res = await login(await buildAuth(), idp.setNonce);
    for (const name of cookieMap(res).keys()) {
      expect(name).not.toMatch(/account_data/);
    }
  });

  it("serves no Keycloak provider when discovery cannot reach the issuer", async () => {
    const idp = await mockIdp(KEYCLOAK_CLAIMS, { reachable: false });
    vi.stubGlobal("fetch", idp.fetchImpl);
    vi.spyOn(console, "error").mockImplementation(() => {});

    const auth = await buildAuth();
    const signIn = await auth.handler(
      new Request(`${BASE_URL}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE_URL },
        body: JSON.stringify({ provider: "keycloak", callbackURL: "/dashboard" }),
      }),
    );
    // Asserted on the provider's absence rather than on the log line, because
    // discovery is asynchronous and the line is not deterministic. This is the
    // failure the compose Keycloak healthcheck and the chart's readiness gate
    // exist to prevent.
    expect(signIn.status).toBeGreaterThanOrEqual(400);
  });

  it("serves no Keycloak provider when KEYCLOAK_ISSUER is unset", async () => {
    delete process.env.KEYCLOAK_ISSUER;
    const auth = await buildAuth();
    const signIn = await auth.handler(
      new Request(`${BASE_URL}/api/auth/sign-in/social`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE_URL },
        body: JSON.stringify({ provider: "keycloak", callbackURL: "/dashboard" }),
      }),
    );
    expect(signIn.status).toBeGreaterThanOrEqual(400);
  });

  it("resolves the session from the cookie cache with no database", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const auth = await buildAuth();
    const res = await login(auth, idp.setNonce);
    const cookie = res.headers.getSetCookie().join("; ");

    const session = await auth.api.getSession({
      headers: new Headers({ cookie }),
    });
    // Better Auth normalizes the email to lower case in its own store while
    // the minted cookie carries the id_token's original casing. That mismatch
    // is exactly why the carry-forward binding compares case-insensitively.
    expect(session?.user.email).toBe("user@redsim.local");
  });

  it("refuses to move the email the refresh route binds on", async () => {
    const key = await signingKey();
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = key.pem;
    const idp = await mockIdp(KEYCLOAK_CLAIMS);
    vi.stubGlobal("fetch", idp.fetchImpl);

    const auth = await buildAuth();
    const res = await login(auth, idp.setNonce);
    const cookie = res.headers.getSetCookie().join("; ");

    const changed = await auth.handler(
      new Request(`${BASE_URL}/api/auth/change-email`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          origin: BASE_URL,
        },
        body: JSON.stringify({ newEmail: "attacker@redsim.local" }),
      }),
    );
    expect(changed.status).toBeGreaterThanOrEqual(400);

    const session = await auth.api.getSession({
      headers: new Headers({ cookie }),
    });
    expect(session?.user.email).toBe("user@redsim.local");
  });
});
