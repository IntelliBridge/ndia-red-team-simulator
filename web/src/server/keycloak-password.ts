import "server-only";

// The password grant against the Keycloak realm.
//
// The branded login page posts a username and password to this app, and this
// module exchanges them with Keycloak's token endpoint (OAuth 2.0 resource
// owner password credentials, "direct access grants" in Keycloak's admin
// console). Keycloak stays the identity store: users, passwords, the
// redsim_project_roles attribute and brute-force lockout all live in the
// realm. What changes is that the user never leaves this app for Keycloak's
// hosted form.
//
// Lives under server/ because the password and the client secret pass through
// here. Nothing in this module may be imported from a client component, and
// nothing here logs a request body.

import { createRemoteJWKSet, jwtVerify } from "jose";

import { env } from "@/env";

import { claimsFromAccount, type RedsimClaims } from "./redsim-cookies";

/**
 * Why a sign-in was refused.
 *
 * `invalid_credentials` covers an unknown user, a wrong password, a disabled
 * account and a brute-force lockout alike. Keycloak reports them all as
 * `invalid_grant`, and splitting them here would turn the login page into a
 * user-enumeration oracle.
 */
export type PasswordGrantFailure =
  | "invalid_credentials"
  | "identity_unavailable"
  | "identity_misconfigured";

/** The password grant refused or could not complete. */
export class PasswordGrantError extends Error {
  readonly reason: PasswordGrantFailure;

  constructor(reason: PasswordGrantFailure, message: string) {
    super(message);
    this.name = "PasswordGrantError";
    this.reason = reason;
  }
}

/** How long one round trip to Keycloak may take. */
const TOKEN_TIMEOUT_MS = 10_000;

/** Keycloak's endpoint paths are fixed under a realm's issuer URL. */
function endpoints(issuer: string) {
  const base = `${issuer.replace(/\/$/, "")}/protocol/openid-connect`;
  return { token: `${base}/token`, jwks: `${base}/certs` };
}

/**
 * The issuers an id_token may name.
 *
 * Keycloak writes the URL it was reached on, or `KC_HOSTNAME` when that is
 * set. On the compose stack the server-to-server call reaches the realm on
 * the service name, so the claim carries `KEYCLOAK_ISSUER`; on the EC2 host
 * `KC_HOSTNAME` is the public origin, so it carries `KEYCLOAK_PUBLIC_ISSUER`.
 * Accepting exactly these two, and nothing else, covers both without a
 * per-deployment switch.
 */
function acceptedIssuers(issuer: string, publicIssuer: string | undefined): string[] {
  const seen = new Set<string>();
  for (const value of [issuer, publicIssuer]) {
    if (value) seen.add(value.replace(/\/$/, ""));
  }
  return [...seen];
}

type JwksLookup = ReturnType<typeof createRemoteJWKSet>;

/**
 * One JWKS fetcher per issuer for the life of the process. jose caches the
 * key set and refetches on an unknown `kid`, so a Keycloak key rotation is
 * picked up without a restart.
 */
const jwksByIssuer = new Map<string, JwksLookup>();

function jwksFor(issuer: string): JwksLookup {
  let lookup = jwksByIssuer.get(issuer);
  if (!lookup) {
    lookup = createRemoteJWKSet(new URL(endpoints(issuer).jwks), {
      timeoutDuration: TOKEN_TIMEOUT_MS,
    });
    jwksByIssuer.set(issuer, lookup);
  }
  return lookup;
}

/** Drop the cached JWKS fetchers. Test seam. */
export function resetJwksCache(): void {
  jwksByIssuer.clear();
}

/** The realm settings this module needs, or undefined when no realm is set. */
export function keycloakSettings():
  | { issuer: string; clientId: string; clientSecret: string | undefined; issuers: string[] }
  | undefined {
  if (!env.KEYCLOAK_ISSUER || !env.KEYCLOAK_CLIENT_ID) return undefined;
  return {
    issuer: env.KEYCLOAK_ISSUER,
    clientId: env.KEYCLOAK_CLIENT_ID,
    clientSecret: env.KEYCLOAK_CLIENT_SECRET,
    issuers: acceptedIssuers(env.KEYCLOAK_ISSUER, env.KEYCLOAK_PUBLIC_ISSUER),
  };
}

/**
 * Exchange a username and password for the caller's redsim claims.
 *
 * The id_token Keycloak returns is verified against the realm's JWKS, with
 * the issuer and the audience checked, before any claim is read. The access
 * and refresh tokens in the same response are discarded: FastAPI verifies
 * the redsim_api_session cookie, never a Keycloak token, so there is nothing
 * to keep them for.
 *
 * @param username - The Keycloak username or email.
 * @param password - The password. Sent to Keycloak once, never stored or logged.
 * @returns The claims the redsim cookie pair is minted from.
 * @throws PasswordGrantError with `invalid_credentials` for any refusal of
 *   the credentials, `identity_unavailable` when Keycloak cannot be reached
 *   or answers with something other than a token response, and
 *   `identity_misconfigured` when no realm is configured or Keycloak refuses
 *   the client itself.
 */
export async function passwordGrant(username: string, password: string): Promise<RedsimClaims> {
  const settings = keycloakSettings();
  if (!settings) {
    throw new PasswordGrantError(
      "identity_misconfigured",
      "KEYCLOAK_ISSUER and KEYCLOAK_CLIENT_ID are not set",
    );
  }

  const body = new URLSearchParams({
    grant_type: "password",
    client_id: settings.clientId,
    scope: "openid",
    username,
    password,
  });
  if (settings.clientSecret) body.set("client_secret", settings.clientSecret);

  let response: Response;
  try {
    response = await fetch(endpoints(settings.issuer).token, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    });
  } catch (err) {
    throw new PasswordGrantError(
      "identity_unavailable",
      `token endpoint unreachable: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const payload = await readJson(response);

  if (!response.ok) {
    const error = typeof payload?.error === "string" ? payload.error : "";
    // invalid_grant is Keycloak's answer for a wrong password, an unknown
    // user, a disabled account and a temporary lockout. One reason for all
    // of them, deliberately.
    if (response.status === 400 || response.status === 401) {
      if (error === "invalid_grant") {
        throw new PasswordGrantError("invalid_credentials", "keycloak refused the credentials");
      }
      if (error === "invalid_client" || error === "unauthorized_client") {
        throw new PasswordGrantError(
          "identity_misconfigured",
          `keycloak refused the client: ${error}`,
        );
      }
    }
    throw new PasswordGrantError(
      "identity_unavailable",
      `token endpoint answered ${response.status}${error ? ` ${error}` : ""}`,
    );
  }

  const idToken = payload?.id_token;
  if (typeof idToken !== "string" || !idToken) {
    throw new PasswordGrantError(
      "identity_unavailable",
      "token response carried no id_token; is the openid scope enabled on the client?",
    );
  }

  let sub: string;
  try {
    const { payload: claims } = await jwtVerify(idToken, jwksFor(settings.issuer), {
      issuer: settings.issuers,
      audience: settings.clientId,
    });
    sub = String(claims.sub ?? "");
  } catch (err) {
    throw new PasswordGrantError(
      "identity_unavailable",
      `id_token failed verification: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!sub) {
    throw new PasswordGrantError("identity_unavailable", "id_token carried no sub");
  }

  // The same projection the code flow's after-hook uses, so the two paths
  // mint identical claims: sub from the token subject, email, name and the
  // project roles map from the id_token.
  return claimsFromAccount({ accountId: sub, idToken });
}

/** The response body as JSON, or undefined when it is not JSON. */
async function readJson(response: Response): Promise<Record<string, unknown> | undefined> {
  try {
    const parsed: unknown = await response.json();
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
