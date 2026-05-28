// POST /api/auth/signout-aegis — clear the Aegis-side cookies.
//
// NextAuth's own /api/auth/signout takes care of the next-auth.session-token
// cookie and the Keycloak end-session call. This route is the matching
// Aegis-side cleanup: clear aegis_api_session + aegis_csrf so a leftover
// cookie can't keep authenticating after sign-out.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import {
  csrfCookieName,
  sessionCookieName,
} from "@/server/aegis-session";

export async function POST() {
  const c = cookies();
  c.set(sessionCookieName, "", { path: "/", maxAge: 0 });
  c.set(csrfCookieName, "", { path: "/", maxAge: 0 });
  return NextResponse.json({ ok: true });
}
