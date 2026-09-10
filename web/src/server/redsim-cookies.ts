import "server-only";

import { env } from "@/env";

import { REFRESH_COOKIE_PATH } from "./refresh-cookie";
import {
  csrfCookieName,
  mintRedsimSessionJwt,
  newCsrfToken,
  sessionCookieName,
  sessionTtlSeconds,
} from "./redsim-session";

/**
 * The browser's credential cookies.
 *
 * Three cookies make a signed-in browser. The redsim session (httpOnly, the
 * RS256 JWT FastAPI verifies) and the csrf value (readable, echoed as a header
 * on mutations) live for the API session TTL and are re-minted by the refresh
 * route. The sealed refresh cookie (httpOnly, `/api/auth` only) is what the
 * refresh route trades for a new pair. Sign-out clears all three.
 */

const isProd = env.REDSIM_ENV === "prod";

export type RedsimClaims = {
  sub: string;
  email: string;
  name: string;
  projectMemberships: Record<string, string>;
};

export type CookieOptions = {
  httpOnly: boolean;
  secure: boolean;
  sameSite: "lax";
  path: string;
  maxAge: number;
};

export type CookieSetter = (name: string, value: string, options: CookieOptions) => void;

export function redsimCookieOptions(
  kind: "session" | "csrf" | "refresh",
  maxAge: number = sessionTtlSeconds,
): CookieOptions {
  return {
    httpOnly: kind !== "csrf",
    secure: isProd,
    sameSite: "lax",
    path: kind === "refresh" ? REFRESH_COOKIE_PATH : "/",
    maxAge,
  };
}

export const redsimCookieNames = {
  session: sessionCookieName,
  csrf: csrfCookieName,
  refresh: env.REDSIM_REFRESH_COOKIE,
};

/** Mint and set the session pair. Returns the max-age both cookies carry. */
export async function setRedsimCookies(claims: RedsimClaims, set: CookieSetter): Promise<number> {
  const jwt = await mintRedsimSessionJwt(claims);
  const maxAge = sessionTtlSeconds;
  set(redsimCookieNames.session, jwt, redsimCookieOptions("session", maxAge));
  set(redsimCookieNames.csrf, newCsrfToken(), redsimCookieOptions("csrf", maxAge));
  return maxAge;
}

/** Clear every credential cookie, the refresh cookie included. */
export function clearRedsimCookies(set: CookieSetter): void {
  set(redsimCookieNames.session, "", redsimCookieOptions("session", 0));
  set(redsimCookieNames.csrf, "", redsimCookieOptions("csrf", 0));
  set(redsimCookieNames.refresh, "", redsimCookieOptions("refresh", 0));
}
