// @vitest-environment node
//
// The lazy instance: nothing is cached while Keycloak's discovery document is
// unreachable, and the first request after it answers builds the instance.
// Every case re-imports the module graph because server.ts holds the cache in
// module state and config.ts reads process.env at load.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ISSUER = "http://mock-idp.test/realms/redsim";
const DISCOVERY = `${ISSUER}/.well-known/openid-configuration`;
const savedEnv = { ...process.env };

vi.mock("next/headers", () => ({ headers: () => new Headers() }));

function discoveryDoc() {
  return Response.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
    token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
    userinfo_endpoint: `${ISSUER}/protocol/openid-connect/userinfo`,
    jwks_uri: `${ISSUER}/protocol/openid-connect/certs`,
    end_session_endpoint: `${ISSUER}/protocol/openid-connect/logout`,
    id_token_signing_alg_values_supported: ["RS256"],
  });
}

async function load() {
  vi.resetModules();
  return import("./server");
}

describe("getAuth", () => {
  beforeEach(() => {
    process.env.BETTER_AUTH_URL = "http://localhost:3000";
    process.env.BETTER_AUTH_SECRET = "test-not-a-real-secret-change-me-0123456789";
    process.env.KEYCLOAK_ISSUER = ISSUER;
    process.env.KEYCLOAK_CLIENT_ID = "redsim-web";
    process.env.REDSIM_ENV = "prod";
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    process.env = { ...savedEnv };
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("rejects with IdentityUnavailableError and caches nothing while discovery is unreachable, then recovers", async () => {
    let reachable = false;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (!reachable) throw new TypeError("fetch failed");
      const url = typeof input === "string" ? input : input.toString();
      if (url === DISCOVERY) return discoveryDoc();
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const mod = await load();

    await expect(mod.getAuth()).rejects.toBeInstanceOf(mod.IdentityUnavailableError);
    await expect(mod.getAuth()).rejects.toBeInstanceOf(mod.IdentityUnavailableError);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    reachable = true;
    const auth = await mod.getAuth();
    expect(auth).toBeDefined();
    expect(await mod.getAuth()).toBe(auth);
    expect(fetchMock.mock.calls.map((c) => String(c[0]))).toEqual([DISCOVERY, DISCOVERY, DISCOVERY]);
  });

  it("treats a non-2xx discovery answer as unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("bad gateway", { status: 502 })));
    const mod = await load();
    await expect(mod.getAuth()).rejects.toThrow(/returned 502/);
  });

  it("shares one build between concurrent callers", async () => {
    const fetchMock = vi.fn(async () => discoveryDoc());
    vi.stubGlobal("fetch", fetchMock);
    const mod = await load();
    const [a, b] = await Promise.all([mod.getAuth(), mod.getAuth()]);
    expect(a).toBe(b);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("skips the probe when no realm is configured", async () => {
    delete process.env.KEYCLOAK_ISSUER;
    process.env.REDSIM_ENV = "dev";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const mod = await load();
    await expect(mod.getAuth()).resolves.toBeDefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("getSession reads as signed out while the identity provider is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("fetch failed"); }));
    const mod = await load();
    await expect(mod.getSession()).resolves.toBeNull();
  });
});
