// @vitest-environment node
import { generateKeyPairSync } from "node:crypto";

import { decodeProtectedHeader, importSPKI, jwtVerify } from "jose";
import { afterEach, describe, expect, it } from "vitest";

import {
  csrfCookieName,
  mintRedsimSessionJwt,
  newCsrfToken,
  sessionCookieName,
  sessionTtlSeconds,
} from "./redsim-session";

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const savedEnv = { ...process.env };
afterEach(() => {
  process.env = { ...savedEnv };
});

describe("mintRedsimSessionJwt", () => {
  it("throws when the signing key is absent", async () => {
    delete process.env.REDSIM_API_SESSION_PRIVATE_KEY;
    await expect(
      mintRedsimSessionJwt({ sub: "u1", email: "u@x.io" }),
    ).rejects.toThrow(/REDSIM_API_SESSION_PRIVATE_KEY/);
  });

  it("mints an RS256 JWT with the expected claims, issuer, audience and kid", async () => {
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = privateKey;
    process.env.REDSIM_API_SESSION_KEY_ID = "kid-test";
    process.env.REDSIM_API_SESSION_TTL_SECONDS = "900";

    const jwt = await mintRedsimSessionJwt({
      sub: "user-123",
      email: "user@example.com",
      name: "User",
      projectMemberships: { p1: "admin" },
    });

    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBe("RS256");
    expect(header.kid).toBe("kid-test");

    const pub = await importSPKI(publicKey, "RS256");
    const { payload } = await jwtVerify(jwt, pub, {
      issuer: "redsim-api-session",
      audience: "redsim-api",
    });
    expect(payload.sub).toBe("user-123");
    expect(payload.email).toBe("user@example.com");
    expect(payload.name).toBe("User");
    expect(payload.redsim_project_roles).toEqual({ p1: "admin" });
    expect(payload.jti).toMatch(/^[0-9a-f]{32}$/);
    const ttl = (payload.exp as number) - (payload.iat as number);
    expect(ttl).toBeGreaterThanOrEqual(899);
    expect(ttl).toBeLessThanOrEqual(901);
  });

  it("defaults name to empty and roles to {} when omitted", async () => {
    process.env.REDSIM_API_SESSION_PRIVATE_KEY = privateKey;
    const jwt = await mintRedsimSessionJwt({ sub: "s", email: "e@e.io" });
    const pub = await importSPKI(publicKey, "RS256");
    const { payload } = await jwtVerify(jwt, pub);
    expect(payload.name).toBe("");
    expect(payload.redsim_project_roles).toEqual({});
  });
});

describe("csrf token + config exports", () => {
  it("newCsrfToken returns distinct url-safe tokens", () => {
    const a = newCsrfToken();
    const b = newCsrfToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.length).toBeGreaterThanOrEqual(32);
  });

  it("exposes default cookie names and ttl", () => {
    expect(sessionCookieName).toBe("redsim_api_session");
    expect(csrfCookieName).toBe("redsim_csrf");
    expect(sessionTtlSeconds).toBe(900);
  });
});
