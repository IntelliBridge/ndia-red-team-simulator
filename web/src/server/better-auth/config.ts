// The Better Auth instance.
//
// Lives under server/ because it holds BETTER_AUTH_SECRET and, through the
// after-hook, reaches the Redsim signing key. Nothing here may be imported
// from a client component.
//
// Stateless by construction: no database option, which selects the
// in-memory adapter, and no JWT plugin, which would want a jwks table and
// could not produce the fixed-key, fixed-iss, fixed-aud token FastAPI expects.
// FastAPI never sees Better Auth's session cookie. The only thing it sees is
// the RS256 redsim_api_session cookie the after-hook mints.
//
// The in-memory adapter does not survive a restart, so what carries a session
// across one is the signed session_data cookie and nothing else. That holds
// only inside the cookie-cache window, which is why the window is set to a
// working day below rather than left at the library default.

import { betterAuth } from "better-auth";
import { genericOAuth, keycloak } from "better-auth/plugins/generic-oauth";

import { env } from "@/env";

import { mintFromAccount } from "../redsim-cookies";

/** Keycloak's endpoint paths are fixed under a realm's issuer URL. */
function keycloakEndpoints(issuer: string) {
  const base = `${issuer.replace(/\/$/, "")}/protocol/openid-connect`;
  return { auth: `${base}/auth`, token: `${base}/token`, userinfo: `${base}/userinfo` };
}

/**
 * The Keycloak provider, or nothing when the realm is not configured.
 *
 * The generic OAuth plugin runs issuer discovery once, at construction, and
 * a failed discovery drops the provider for the life of the process. On a
 * deployed stack Keycloak restarts with no overlap on every release, so a web
 * task that booted during that window had no sign-in button until it was
 * restarted by hand. Keycloak's endpoints are deterministic under the realm
 * issuer, so they are set explicitly here: discovery still runs and, when it
 * succeeds, adds the issuer and JWKS used to verify ID tokens, but its failure
 * no longer removes the provider.
 *
 * Two issuers, because the browser and the server reach Keycloak by different
 * names: the authorization endpoint is what the browser is redirected to, so
 * it is built from KEYCLOAK_PUBLIC_ISSUER (the public origin); the token and
 * userinfo endpoints are server-to-server and stay on KEYCLOAK_ISSUER (the
 * in-VPC name on Fargate, the compose service name locally). When the public
 * issuer is unset both are the same URL, the single-host developer case.
 */
function keycloakProviders() {
  if (!env.KEYCLOAK_ISSUER || !env.KEYCLOAK_CLIENT_ID) return [];
  const internal = keycloakEndpoints(env.KEYCLOAK_ISSUER);
  const browser = keycloakEndpoints(env.KEYCLOAK_PUBLIC_ISSUER ?? env.KEYCLOAK_ISSUER);
  return [
    {
      ...keycloak({
        clientId: env.KEYCLOAK_CLIENT_ID,
        // The realm's redsim-web is a public client using PKCE, so the empty
        // string is the correct value rather than a missing one.
        clientSecret: env.KEYCLOAK_CLIENT_SECRET ?? "",
        issuer: env.KEYCLOAK_ISSUER,
      }),
      authorizationUrl: browser.auth,
      tokenUrl: internal.token,
      userInfoUrl: internal.userinfo,
    },
  ];
}

const isProd = env.REDSIM_ENV === "prod";

/**
 * Build the auth instance.
 *
 * Exported as a factory so the test suite can construct an instance against a
 * mock IdP without reaching for module-level state.
 */
export function createAuth() {
  return betterAuth({
    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
    trustedOrigins: env.BETTER_AUTH_URL ? [env.BETTER_AUTH_URL] : [],
    telemetry: { enabled: false },
    plugins: [genericOAuth({ config: keycloakProviders() })],
    account: {
      // Serializing the account record into the browser would put the Keycloak
      // id_token there unencrypted, and with it the redsim_project_roles claim
      // that drives project RBAC and the Postgres RLS tenant GUC.
      storeAccountCookie: false,
    },
    user: {
      // The refresh route's carry-forward binds to the session email, so the
      // email must not be movable by its owner.
      changeEmail: { enabled: false },
    },
    session: {
      // The cookie-cache window is the real session bound, not expiresIn.
      // Inside it the signed cookie is the authority. Past it Better Auth
      // falls back to the in-memory adapter row, which lives in one process:
      // a restart empties it and web.strategy Recreate makes restarts routine,
      // so at the library default of 300 seconds a user is signed out mid
      // session by any release. The refresh route cannot cover the gap, since
      // it checks Better Auth before the still-valid redsim cookie.
      //
      // Eight hours covers a working day, so a release no longer ends a
      // session in progress. It is deliberately short of expiresIn: the window
      // is also the revocation lag, because a sign-out or a Keycloak
      // suspension is not observed until the cache is consulted again. One
      // working day is the accepted lag, seven days was not.
      cookieCache: { enabled: true, maxAge: 60 * 60 * 8 },
      expiresIn: 60 * 60 * 24 * 7,
    },
    advanced: {
      // Follows the same secure-cookie rule as the redsim pair, rather than
      // the library's inference from the base URL protocol.
      useSecureCookies: isProd,
    },
    hooks: {
      after: mintFromAccount,
    },
  });
}
