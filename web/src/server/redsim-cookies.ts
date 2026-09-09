// The bridge between Better Auth's browser session and the RS256 cookie
// FastAPI verifies.
//
// Lives under server/ because everything here touches the Redsim signing key.
// The minting itself stays in redsim-session.ts, which the FastAPI
// session-cookie contract freezes byte for byte; this module is the caller,
// not a replacement.

import { createPublicKey } from "node:crypto";

import { createAuthMiddleware } from "better-auth/api";
import { decodeJwt, importSPKI, jwtVerify } from "jose";

import { env } from "@/env";

import {
  csrfCookieName,
  mintRedsimSessionJwt,
  newCsrfToken,
  sessionCookieName,
  sessionTtlSeconds,
} from "./redsim-session";

const isProd = env.REDSIM_ENV === "prod";

/** Claims FastAPI reads out of redsim_api_session. */
export type RedsimClaims = {
  sub: string;
  email: string;
  name: string;
  projectMemberships: Record<string, string>;
};

/**
 * Cookie attributes for the redsim pair, shared by the after-hook and by the
 * refresh and sign-out routes so the three cannot drift.
 *
 * @param kind - `session` is httpOnly; `csrf` is not, because the SPA reads it
 *   to build the X-Redsim-CSRF double-submit header.
 * @param maxAge - Seconds. Pass 0 to clear the cookie.
 */
export function redsimCookieOptions(
  kind: "session" | "csrf",
  maxAge: number = sessionTtlSeconds,
) {
  return {
    httpOnly: kind === "session",
    secure: isProd,
    sameSite: "lax" as const,
    path: "/",
    maxAge,
  };
}

/**
 * The three cookie names, so callers do not re-derive them.
 *
 * The dev token is not part of the minted pair. It joins the list because
 * sign-out has to clear every credential the tRPC context would accept, and
 * `server/trpc/context.ts` accepts this one as a bearer in a dev or test
 * deployment. Its name comes from `env` rather than from `redsim-session.ts`,
 * which the FastAPI session-cookie contract freezes.
 */
export const redsimCookieNames = {
  session: sessionCookieName,
  csrf: csrfCookieName,
  devToken: env.REDSIM_DEV_TOKEN_COOKIE,
};

/**
 * Decode a JWT payload without verifying it.
 *
 * Only ever applied to the id_token Better Auth stored on the account, which
 * arrived over the verified OIDC code exchange. Never applied to a value that
 * came from the browser.
 *
 * jose's decodeJwt is the deliberately unverified counterpart to the jwtVerify
 * above. It throws JWTInvalid on anything that is not a well-formed token, so
 * the catch is what turns a malformed id_token into an empty claim set rather
 * than a failed sign-in.
 */
function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    return decodeJwt(token);
  } catch {
    return {};
  }
}

/**
 * Read the Keycloak identity out of a linked account record.
 *
 * `accountId` is the Keycloak `sub`. Better Auth's `session.user.id` is a
 * fresh nanoid per login and must never reach the `sub` claim: it drives
 * route auth and the rate-limit bucket key on the FastAPI side, so a per-login
 * value would write a different audited identity every time, with no error
 * anywhere. The roles map comes from the stored id_token rather than the
 * session user, because custom fields do not survive the session cookie.
 */
export function claimsFromAccount(
  account: { accountId?: unknown; idToken?: unknown },
  fallback: { email?: string | null; name?: string | null } = {},
): RedsimClaims {
  const idToken = typeof account.idToken === "string" ? account.idToken : "";
  const payload = idToken ? decodeJwtPayload(idToken) : {};
  const roles = payload["redsim_project_roles"];
  return {
    sub: String(account.accountId ?? ""),
    email: String(payload["email"] ?? fallback.email ?? ""),
    name: String(payload["name"] ?? fallback.name ?? ""),
    projectMemberships:
      roles && typeof roles === "object"
        ? (roles as Record<string, string>)
        : {},
  };
}

/**
 * Set the redsim pair on the response for the given claims.
 *
 * @throws whatever `mintRedsimSessionJwt` throws. Callers decide whether that
 *   is fatal: the after-hook swallows it, the refresh route returns 500.
 */
export async function setRedsimCookies(
  claims: RedsimClaims,
  set: (name: string, value: string, options: ReturnType<typeof redsimCookieOptions>) => void,
): Promise<number> {
  const jwt = await mintRedsimSessionJwt(claims);
  const maxAge = sessionTtlSeconds;
  set(redsimCookieNames.session, jwt, redsimCookieOptions("session", maxAge));
  set(redsimCookieNames.csrf, newCsrfToken(), redsimCookieOptions("csrf", maxAge));
  return maxAge;
}

/**
 * Clear every cookie that authenticates a caller. Shared by the sign-out route.
 *
 * The dev token is cleared with the `csrf` attribute shape, which is the
 * non-httpOnly one the login page writes it with. A sign-out that left it
 * behind would leave the middleware gate satisfied and the tRPC context still
 * forwarding a bearer, so the user would stay signed in.
 */
export function clearRedsimCookies(
  set: (name: string, value: string, options: ReturnType<typeof redsimCookieOptions>) => void,
): void {
  set(redsimCookieNames.session, "", redsimCookieOptions("session", 0));
  set(redsimCookieNames.csrf, "", redsimCookieOptions("csrf", 0));
  set(redsimCookieNames.devToken, "", redsimCookieOptions("csrf", 0));
}

/**
 * Better Auth's after-middleware: mint the redsim pair once a login produces a
 * new session.
 *
 * A mint failure (typically REDSIM_API_SESSION_PRIVATE_KEY unset in local dev)
 * is logged and swallowed, so the Better Auth login still completes and API
 * calls surface 401.
 */
export const mintFromAccount = createAuthMiddleware(async (ctx) => {
  const newSession = ctx.context.newSession;
  if (!newSession?.user) return;

  try {
    const accounts = await ctx.context.internalAdapter.findAccounts(
      newSession.user.id,
    );
    const account = accounts?.[0];
    if (!account) return;

    const claims = claimsFromAccount(account, newSession.user);
    await setRedsimCookies(claims, (name, value, options) =>
      ctx.setCookie(name, value, options),
    );
  } catch (err) {
    console.warn("redsim: failed to mint API session cookie", err);
  }
});

/**
 * Verify an existing redsim_api_session cookie and return its claims, bound to
 * the caller.
 *
 * Two properties, both load-bearing. The signature is verified against the
 * public half of REDSIM_API_SESSION_PRIVATE_KEY, along with issuer and
 * audience, because re-signing claims decoded without verification would
 * let any logged-in user forge roles into a freshly minted token. And the
 * cookie's email claim must match the caller's Better Auth session email,
 * compared case-insensitively, so a cookie that is authentic but belongs to
 * someone else is still rejected. Taking the caller's email as a parameter is
 * what stops a call site forgetting the binding.
 *
 * @returns the claims, or undefined when verification or binding fails.
 */
export async function verifyOwnSessionCookie(
  cookieValue: string | undefined,
  callerEmail: string | undefined,
): Promise<RedsimClaims | undefined> {
  if (!cookieValue || !callerEmail) return undefined;
  const privatePem = env.REDSIM_API_SESSION_PRIVATE_KEY;
  if (!privatePem) return undefined;

  try {
    const spki = createPublicKey(privatePem)
      .export({ type: "spki", format: "pem" })
      .toString();
    const key = await importSPKI(spki, "RS256");
    const { payload } = await jwtVerify(cookieValue, key, {
      issuer: "redsim-api-session",
      audience: "redsim-api",
    });

    const email = String(payload["email"] ?? "");
    if (email.toLowerCase() !== callerEmail.toLowerCase()) return undefined;

    const roles = payload["redsim_project_roles"];
    return {
      sub: String(payload.sub ?? ""),
      email,
      name: String(payload["name"] ?? ""),
      projectMemberships:
        roles && typeof roles === "object"
          ? (roles as Record<string, string>)
          : {},
    };
  } catch {
    return undefined;
  }
}
