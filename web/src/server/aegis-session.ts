// Server-side helpers that mint Aegis cookies after NextAuth completes
// the Keycloak code flow. Lives in /server/ so it never gets bundled
// into the client — the RSA private key would otherwise ship to the
// browser.

import { importPKCS8, SignJWT } from "jose";
import { randomBytes } from "node:crypto";

/**
 * Mint the aegis_api_session JWT cookie that FastAPI verifies.
 *
 * RS256, signed with AEGIS_API_SESSION_PRIVATE_KEY (PKCS8 PEM).
 * iss="aegis-api-session", aud="aegis-api". The kid header carries
 * the configured key id so we can rotate without breaking in-flight
 * sessions.
 */
export async function mintAegisSessionJwt(claims: {
  sub: string;
  email: string;
  name?: string;
  projectMemberships?: Record<string, string>;
}): Promise<string> {
  const privatePem = process.env.AEGIS_API_SESSION_PRIVATE_KEY;
  if (!privatePem) {
    throw new Error(
      "AEGIS_API_SESSION_PRIVATE_KEY is not set in the web environment.",
    );
  }
  const kid = process.env.AEGIS_API_SESSION_KEY_ID ?? "aegis-api-session-v1";
  const ttl = Number(process.env.AEGIS_API_SESSION_TTL_SECONDS ?? "900");
  const key = await importPKCS8(privatePem, "RS256");

  return await new SignJWT({
    email: claims.email,
    name: claims.name ?? "",
    aegis_project_roles: claims.projectMemberships ?? {},
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer("aegis-api-session")
    .setAudience("aegis-api")
    .setSubject(claims.sub)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setJti(randomBytes(16).toString("hex"))
    .sign(key);
}

/**
 * Opaque token used as the CSRF double-submit value. Issued alongside
 * the session cookie; the SPA reads it from the non-httpOnly cookie
 * and attaches it as X-Aegis-CSRF on every mutating request.
 */
export function newCsrfToken(): string {
  return randomBytes(24).toString("base64url");
}

export const sessionCookieName =
  process.env.AEGIS_API_SESSION_COOKIE ?? "aegis_api_session";
export const csrfCookieName = process.env.AEGIS_CSRF_COOKIE ?? "aegis_csrf";

/** Seconds-from-now expiry for both cookies. */
export const sessionTtlSeconds = Number(
  process.env.AEGIS_API_SESSION_TTL_SECONDS ?? "900",
);
