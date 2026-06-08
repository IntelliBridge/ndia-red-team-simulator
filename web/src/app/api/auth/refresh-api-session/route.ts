// POST /api/auth/refresh-api-session — re-mint the aegis_api_session
// + aegis_csrf cookies for the currently signed-in user.
//
// The SPA calls this from useEffect when the session is close to
// expiry, so a long-lived dashboard doesn't have to bounce through
// Keycloak every 15 minutes.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";

import { authOptions } from "@/server/auth-options";
import {
  csrfCookieName,
  mintAegisSessionJwt,
  newCsrfToken,
  sessionCookieName,
  sessionTtlSeconds,
} from "@/server/aegis-session";

const isProd = (process.env.AEGIS_ENV ?? "dev") === "prod";

export async function POST() {
  const session = await getServerSession(authOptions);
  if (!session?.user) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }

  const sub = (session.user as { sub?: string }).sub ?? "";
  const email = session.user.email ?? "";
  const name = session.user.name ?? "";
  const memberships =
    (session.user as { aegis_project_roles?: Record<string, string> })
      .aegis_project_roles ?? {};

  try {
    const jwt = await mintAegisSessionJwt({
      sub,
      email,
      name,
      projectMemberships: memberships,
    });
    const csrf = newCsrfToken();
    const maxAge = sessionTtlSeconds;
    const c = cookies();
    c.set(sessionCookieName, jwt, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      path: "/",
      maxAge,
    });
    c.set(csrfCookieName, csrf, {
      httpOnly: false,
      secure: isProd,
      sameSite: "lax",
      path: "/",
      maxAge,
    });
    return NextResponse.json({ refreshed: true, expires_in: maxAge });
  } catch (err) {
    console.warn("aegis: refresh-api-session failed", err);
    return NextResponse.json({ error: "mint failed" }, { status: 500 });
  }
}
