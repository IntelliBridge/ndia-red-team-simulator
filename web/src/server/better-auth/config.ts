// The Better Auth instance.
//
// Lives under server/ because it holds BETTER_AUTH_SECRET and, through the
// after-hook, reaches the Redsim signing key. Nothing here may be imported
// from a client component.
//
// Stateless by construction (KTD12): no database option, which selects the
// in-memory adapter and carries the session across restarts in the encrypted
// session_data cookie, and no JWT plugin, which would want a jwks table and
// could not produce the fixed-key, fixed-iss, fixed-aud token FastAPI expects.
// FastAPI never sees Better Auth's session cookie. The only thing it sees is
// the RS256 redsim_api_session cookie the after-hook mints.

import { betterAuth } from "better-auth";
import { genericOAuth, keycloak } from "better-auth/plugins/generic-oauth";

import { env } from "@/env";

import { mintFromAccount } from "../redsim-cookies";

/**
 * The Keycloak provider, or nothing when the realm is not configured.
 *
 * Discovery runs at construction and a failure drops the provider with a
 * logged line rather than throwing, so a developer with no realm still gets a
 * booting app and the dev-token login path. On a deployed stack that silence
 * is the failure mode to design against, which is why compose orders the web
 * service after a healthy Keycloak (R31).
 */
function keycloakProviders() {
  if (!env.KEYCLOAK_ISSUER || !env.KEYCLOAK_CLIENT_ID) return [];
  return [
    keycloak({
      clientId: env.KEYCLOAK_CLIENT_ID,
      // The realm's redsim-web is a public client using PKCE, so the empty
      // string is the correct value rather than a missing one.
      clientSecret: env.KEYCLOAK_CLIENT_SECRET ?? "",
      issuer: env.KEYCLOAK_ISSUER,
    }),
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
      // R22 binds the refresh route's carry-forward to the session email, so
      // the email must not be movable by its owner.
      changeEmail: { enabled: false },
    },
    session: {
      // Both numbers are the library's own defaults on 1.7.3, taken as-is.
      // With web.replicaCount pinned to 1 (R35) they are one constraint: past
      // the cookie-cache window only the instance that handled the callback
      // resolves the session, because the memory adapter row lives there.
      cookieCache: { enabled: true, maxAge: 300 },
      expiresIn: 60 * 60 * 24 * 7,
    },
    advanced: {
      // Follow the same rule R19 sets for the redsim pair rather than the
      // library's inference from the base URL protocol.
      useSecureCookies: isProd,
    },
    hooks: {
      after: mintFromAccount,
    },
  });
}
