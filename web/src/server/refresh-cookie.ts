import "server-only";

import { createHash } from "node:crypto";

import { EncryptJWT, jwtDecrypt } from "jose";

import { env } from "@/env";

/**
 * The sealed refresh-token cookie.
 *
 * The realm's refresh token is the one credential that outlives the fifteen
 * minute API session, so it never sits in the browser in the clear. It is
 * encrypted (JWE, direct A256GCM) under a key derived from the web process's
 * own secret, stored httpOnly and scoped to the auth routes, and opened only
 * by the refresh and sign-out routes. Rotating the secret makes every sealed
 * cookie unreadable, which signs every browser out.
 */

const AUDIENCE = "redsim-web-refresh";

/** Where the cookie is sent: only the auth routes ever read it. */
export const REFRESH_COOKIE_PATH = "/api/auth";

/** Fallback lifetime when the realm did not say how long the token lives. */
export const DEFAULT_REFRESH_TTL_SECONDS = 8 * 60 * 60;

/** Upper bound regardless of what the realm said. */
export const MAX_REFRESH_TTL_SECONDS = 24 * 60 * 60;

function sealingKey(): Uint8Array {
  const secret = env.REDSIM_WEB_SESSION_SECRET;
  if (!secret) throw new Error("REDSIM_WEB_SESSION_SECRET is not set in the web environment.");
  return new Uint8Array(createHash("sha256").update(secret).digest());
}

/** Clamp the realm's `refresh_expires_in` into the cookie lifetime. */
export function refreshTtlSeconds(fromRealm: number | undefined): number {
  if (fromRealm === undefined || !Number.isFinite(fromRealm) || fromRealm <= 0) {
    return DEFAULT_REFRESH_TTL_SECONDS;
  }
  return Math.min(Math.floor(fromRealm), MAX_REFRESH_TTL_SECONDS);
}

export async function sealRefreshToken(refreshToken: string, ttlSeconds: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new EncryptJWT({ rt: refreshToken })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setAudience(AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .encrypt(sealingKey());
}

/** The refresh token inside a sealed cookie, or undefined for anything else. */
export async function openRefreshToken(sealed: string | undefined): Promise<string | undefined> {
  if (!sealed) return undefined;
  try {
    const { payload } = await jwtDecrypt(sealed, sealingKey(), { audience: AUDIENCE });
    return typeof payload.rt === "string" && payload.rt ? payload.rt : undefined;
  } catch {
    return undefined;
  }
}
