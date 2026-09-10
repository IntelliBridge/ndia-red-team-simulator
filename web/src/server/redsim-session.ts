// Server-side helpers that mint Redsim cookies after NextAuth completes
// the Keycloak code flow. Lives in /server/ so it never gets bundled
// into the client — the RSA private key would otherwise ship to the
// browser.

import { importPKCS8, jwtVerify, SignJWT } from "jose";
import { createPublicKey, randomBytes } from "node:crypto";

/** Who the session cookie says is signed in. */
export type SessionIdentity = { sub: string; email: string; name: string };

/**
 * Mint the redsim_api_session JWT cookie that FastAPI verifies.
 *
 * RS256, signed with REDSIM_API_SESSION_PRIVATE_KEY (PKCS8 PEM).
 * iss="redsim-api-session", aud="redsim-api". The kid header carries
 * the configured key id so we can rotate without breaking in-flight
 * sessions.
 */
export async function mintRedsimSessionJwt(claims: {
  sub: string;
  email: string;
  name?: string;
  projectMemberships?: Record<string, string>;
}): Promise<string> {
  const privatePem = process.env.REDSIM_API_SESSION_PRIVATE_KEY;
  if (!privatePem) {
    throw new Error(
      "REDSIM_API_SESSION_PRIVATE_KEY is not set in the web environment.",
    );
  }
  const kid = process.env.REDSIM_API_SESSION_KEY_ID ?? "redsim-api-session-v1";
  const ttl = Number(process.env.REDSIM_API_SESSION_TTL_SECONDS ?? "900");
  const key = await importPKCS8(privatePem, "RS256");

  return await new SignJWT({
    email: claims.email,
    name: claims.name ?? "",
    redsim_project_roles: claims.projectMemberships ?? {},
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("redsim-api-session")
    .setAudience("redsim-api")
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setJti(randomBytes(16).toString("hex"))
    .sign(key);
}

/**
 * Opaque token used as the CSRF double-submit value. Issued alongside
 * the session cookie; the SPA reads it from the non-httpOnly cookie
 * and attaches it as X-Redsim-CSRF on every mutating request.
 */
export function newCsrfToken(): string {
  return randomBytes(24).toString("base64url");
}

export const sessionCookieName =
  process.env.REDSIM_API_SESSION_COOKIE ?? "redsim_api_session";
export const csrfCookieName = process.env.REDSIM_CSRF_COOKIE ?? "redsim_csrf";

/** Seconds-from-now expiry for both cookies. */
export const sessionTtlSeconds = Number(
  process.env.REDSIM_API_SESSION_TTL_SECONDS ?? "900",
);

/**
 * The identity inside a redsim_api_session cookie, or undefined.
 *
 * Verified rather than merely decoded. This server minted the token, so a
 * forgery is far-fetched, but the signature check keeps the rule that nothing
 * arriving in a request header is trusted on its shape alone. The public key
 * comes from the signing key: the web process holds the private PEM and no
 * separate public one is configured.
 */
export async function readRedsimSessionClaims(
  token: string | undefined,
): Promise<SessionIdentity | undefined> {
  if (!token) return undefined;
  const privatePem = process.env.REDSIM_API_SESSION_PRIVATE_KEY;
  if (!privatePem) return undefined;
  try {
    const publicKey = createPublicKey({ key: privatePem, format: "pem" });
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: "redsim-api-session",
      audience: "redsim-api",
    });
    const email = typeof payload.email === "string" ? payload.email : "";
    const name = typeof payload.name === "string" ? payload.name : "";
    if (!payload.sub) return undefined;
    return { sub: payload.sub, email, name };
  } catch {
    // Expired, rotated out or malformed. The caller reads it as signed out.
    return undefined;
  }
}
