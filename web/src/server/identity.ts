import "server-only";

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import { env } from "@/env";
import type { RedsimClaims } from "./redsim-cookies";

/**
 * The identity provider behind the login page.
 *
 * The browser never sees the provider. The login route posts the email and
 * password it received to the realm's token endpoint (the OAuth 2 password
 * grant, "direct access grants" on the client), verifies the ID token that
 * comes back against the realm's signing keys, and hands the claims to the
 * cookie minter. The refresh route does the same with the refresh token the
 * login stored in a sealed cookie, and sign-out revokes that token upstream.
 *
 * Every outcome is a typed code. No provider error text reaches the browser,
 * and no password is ever logged: the only things this module logs are codes.
 */

export type IdentityFailure =
  /** The realm is not configured on this web process. */
  | "not_configured"
  /** The realm refused the email and password. */
  | "invalid_credentials"
  /** The account exists and is disabled or not fully set up. */
  | "account_disabled"
  /** Brute-force protection has locked the account for a while. */
  | "account_locked"
  /** The refresh token is no longer valid: signed out, expired or revoked. */
  | "session_ended"
  /** The realm could not be reached or answered with a server error. */
  | "unavailable";

export type IdentityResult =
  | {
      ok: true;
      claims: RedsimClaims;
      /** The refresh token to seal into the cookie, when the realm issued one. */
      refreshToken: string | undefined;
      /** Seconds the refresh token lives, when the realm said. */
      refreshExpiresIn: number | undefined;
    }
  | { ok: false; code: IdentityFailure; detail: string };

/** How long a single call to the realm may take. */
const REQUEST_TIMEOUT_MS = 10_000;

type Realm = {
  issuer: string;
  /** Issuers a token may carry: the internal one and the browser-facing one. */
  acceptedIssuers: Set<string>;
  clientId: string;
  clientSecret: string | undefined;
  tokenEndpoint: string;
  logoutEndpoint: string;
  jwks: ReturnType<typeof createRemoteJWKSet>;
};

let cached: Realm | null = null;

function trimSlash(url: string): string {
  return url.replace(/\/$/, "");
}

/**
 * The realm this process is configured against, or null when it is not.
 *
 * Built once per process. The JWKS fetcher caches the realm's keys and refetches
 * them on an unknown key id, so a key rotation upstream needs no restart.
 */
export function configuredRealm(): Realm | null {
  if (cached) return cached;
  if (!env.KEYCLOAK_ISSUER || !env.KEYCLOAK_CLIENT_ID) return null;
  const issuer = trimSlash(env.KEYCLOAK_ISSUER);
  const base = `${issuer}/protocol/openid-connect`;
  const acceptedIssuers = new Set([issuer]);
  if (env.KEYCLOAK_PUBLIC_ISSUER) acceptedIssuers.add(trimSlash(env.KEYCLOAK_PUBLIC_ISSUER));
  cached = {
    issuer,
    acceptedIssuers,
    clientId: env.KEYCLOAK_CLIENT_ID,
    clientSecret: env.KEYCLOAK_CLIENT_SECRET || undefined,
    tokenEndpoint: `${base}/token`,
    logoutEndpoint: `${base}/logout`,
    jwks: createRemoteJWKSet(new URL(`${base}/certs`), {
      timeoutDuration: REQUEST_TIMEOUT_MS,
      cooldownDuration: 30_000,
    }),
  };
  return cached;
}

type TokenResponse = {
  id_token?: unknown;
  refresh_token?: unknown;
  refresh_expires_in?: unknown;
};

type TokenFailure = { ok: false; code: IdentityFailure; detail: string };
type TokenSuccess = { ok: true; body: TokenResponse };

function failure(code: IdentityFailure, detail: string): TokenFailure {
  return { ok: false, code, detail };
}

/**
 * Turn the realm's `{error, error_description}` refusal into a code.
 *
 * The descriptions are the realm's fixed strings, matched loosely so a wording
 * change downgrades to the generic code rather than to a crash. The generic
 * code differs by grant: a refused password is "invalid credentials", a
 * refused refresh token is "session ended".
 */
function classifyRefusal(
  grant: "password" | "refresh_token",
  status: number,
  body: { error?: unknown; error_description?: unknown },
): TokenFailure {
  const error = typeof body.error === "string" ? body.error : "";
  const description =
    typeof body.error_description === "string" ? body.error_description.toLowerCase() : "";
  const detail = `${status} ${error}${description ? `: ${description}` : ""}`;
  if (error === "unauthorized_client" || error === "invalid_client" || error === "unsupported_grant_type") {
    return failure("not_configured", detail);
  }
  if (description.includes("temporarily")) return failure("account_locked", detail);
  if (description.includes("disabled") || description.includes("not fully set up")) {
    return failure("account_disabled", detail);
  }
  return failure(grant === "password" ? "invalid_credentials" : "session_ended", detail);
}

async function tokenRequest(
  realm: Realm,
  grant: "password" | "refresh_token",
  form: Record<string, string>,
  fetchImpl: typeof fetch,
): Promise<TokenSuccess | TokenFailure> {
  const params = new URLSearchParams({ grant_type: grant, client_id: realm.clientId, ...form });
  if (realm.clientSecret) params.set("client_secret", realm.clientSecret);
  let response: Response;
  try {
    response = await fetchImpl(realm.tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: params.toString(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      cache: "no-store",
    });
  } catch (err) {
    return failure("unavailable", `token endpoint unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (response.ok) {
    if (body === null || typeof body !== "object") {
      return failure("unavailable", `token endpoint answered ${response.status} with no JSON body`);
    }
    return { ok: true, body: body as TokenResponse };
  }
  if (response.status >= 500) return failure("unavailable", `token endpoint answered ${response.status}`);
  return classifyRefusal(grant, response.status, (body ?? {}) as Record<string, unknown>);
}

/**
 * Verify the ID token against the realm's keys and read the claims we keep.
 *
 * Signature, expiry and audience are checked by `jwtVerify`. The issuer is
 * checked here against both spellings, because the realm stamps tokens with
 * the URL it was reached on and the server may reach it privately.
 */
async function claimsFromIdToken(realm: Realm, idToken: unknown): Promise<RedsimClaims | TokenFailure> {
  if (typeof idToken !== "string" || !idToken) {
    return failure("not_configured", "the realm issued no id_token; the client needs the openid scope");
  }
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(idToken, realm.jwks, { audience: realm.clientId }));
  } catch (err) {
    return failure("unavailable", `id_token rejected: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof payload.iss !== "string" || !realm.acceptedIssuers.has(trimSlash(payload.iss))) {
    return failure("not_configured", `id_token issuer ${String(payload.iss)} is not the configured realm`);
  }
  if (typeof payload.sub !== "string" || !payload.sub) {
    return failure("unavailable", "id_token carries no subject");
  }
  const roles = payload["redsim_project_roles"];
  const email = payload["email"] ?? payload["preferred_username"] ?? "";
  return {
    sub: payload.sub,
    email: String(email),
    name: typeof payload["name"] === "string" ? payload["name"] : "",
    projectMemberships:
      roles && typeof roles === "object" && !Array.isArray(roles)
        ? (roles as Record<string, string>)
        : {},
  };
}

function isFailure(value: RedsimClaims | TokenFailure): value is TokenFailure {
  return "ok" in value && value.ok === false;
}

async function complete(realm: Realm, response: TokenSuccess): Promise<IdentityResult> {
  const claims = await claimsFromIdToken(realm, response.body.id_token);
  if (isFailure(claims)) return claims;
  const refreshToken =
    typeof response.body.refresh_token === "string" && response.body.refresh_token
      ? response.body.refresh_token
      : undefined;
  const refreshExpiresIn =
    typeof response.body.refresh_expires_in === "number" && response.body.refresh_expires_in > 0
      ? response.body.refresh_expires_in
      : undefined;
  return { ok: true, claims, refreshToken, refreshExpiresIn };
}

/**
 * Exchange an email and password for the session claims.
 *
 * @param email - What the user typed in the first field. Passed as the realm's
 *   username; the realm accepts an email there when email login is on.
 * @param password - Passed once to the realm and never stored or logged.
 */
export async function loginWithPassword(
  email: string,
  password: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IdentityResult> {
  const realm = configuredRealm();
  if (!realm) return failure("not_configured", "KEYCLOAK_ISSUER or KEYCLOAK_CLIENT_ID is unset");
  const response = await tokenRequest(
    realm,
    "password",
    { username: email, password, scope: "openid" },
    fetchImpl,
  );
  if (!response.ok) return response;
  return complete(realm, response);
}

/** Renew the session from the refresh token the login stored. */
export async function refreshWithToken(
  refreshToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IdentityResult> {
  const realm = configuredRealm();
  if (!realm) return failure("not_configured", "KEYCLOAK_ISSUER or KEYCLOAK_CLIENT_ID is unset");
  const response = await tokenRequest(realm, "refresh_token", { refresh_token: refreshToken }, fetchImpl);
  if (!response.ok) return response;
  return complete(realm, response);
}

/**
 * End the upstream session behind a refresh token. Best effort: a sign-out
 * must never fail because the realm was slow, so every error is swallowed and
 * the caller clears the cookies regardless.
 */
export async function revokeRefreshToken(
  refreshToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  const realm = configuredRealm();
  if (!realm) return false;
  const params = new URLSearchParams({ client_id: realm.clientId, refresh_token: refreshToken });
  if (realm.clientSecret) params.set("client_secret", realm.clientSecret);
  try {
    const response = await fetchImpl(realm.logoutEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: params.toString(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      cache: "no-store",
    });
    return response.ok;
  } catch {
    return false;
  }
}

/** HTTP status the auth routes answer for each failure code. */
export function statusForFailure(code: IdentityFailure): number {
  switch (code) {
    case "invalid_credentials":
    case "account_disabled":
    case "account_locked":
    case "session_ended":
      return 401;
    case "not_configured":
    case "unavailable":
      return 503;
  }
}
