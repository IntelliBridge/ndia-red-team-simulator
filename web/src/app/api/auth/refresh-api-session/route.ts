import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { refreshWithToken, statusForFailure } from "@/server/identity";
import {
  clearRedsimCookies,
  redsimCookieNames,
  redsimCookieOptions,
  setRedsimCookies,
} from "@/server/redsim-cookies";
import { openRefreshToken, refreshTtlSeconds, sealRefreshToken } from "@/server/refresh-cookie";

/**
 * Renew the API session while a tab is open.
 *
 * The session pair lives fifteen minutes. This route opens the sealed refresh
 * cookie, trades the refresh token for fresh claims at the realm, re-mints the
 * pair and rotates the refresh cookie. A refresh token the realm no longer
 * honours (signed out elsewhere, expired, revoked) clears every credential so
 * the next page load lands on the login page instead of looping on 401.
 */
export async function POST(): Promise<NextResponse> {
  const jar = cookies();
  const set = (name: string, value: string, options: Parameters<typeof jar.set>[2]) =>
    jar.set(name, value, options);

  const refreshToken = await openRefreshToken(jar.get(redsimCookieNames.refresh)?.value);
  if (!refreshToken) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }

  const result = await refreshWithToken(refreshToken);
  if (!result.ok) {
    const status = statusForFailure(result.code);
    if (status === 401) clearRedsimCookies(set);
    else console.error(`redsim: session refresh failed upstream (${result.code}): ${result.detail}`);
    return NextResponse.json({ error: result.code }, { status });
  }

  try {
    const expiresIn = await setRedsimCookies(result.claims, set);
    if (result.refreshToken) {
      const ttl = refreshTtlSeconds(result.refreshExpiresIn);
      set(
        redsimCookieNames.refresh,
        await sealRefreshToken(result.refreshToken, ttl),
        redsimCookieOptions("refresh", ttl),
      );
    }
    return NextResponse.json({ refreshed: true, expires_in: expiresIn });
  } catch (err) {
    console.warn("redsim: refresh-api-session failed", err);
    return NextResponse.json({ error: "mint failed" }, { status: 500 });
  }
}
