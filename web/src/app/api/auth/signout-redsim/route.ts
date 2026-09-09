// POST /api/auth/signout-redsim — clear the Redsim-side cookies.
//
// Better Auth's own /api/auth/sign-out takes care of its session cookie and
// the Keycloak end-session call. This route is the matching Redsim-side
// cleanup: clear redsim_api_session and redsim_csrf so a leftover cookie
// cannot keep authenticating after sign-out.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { clearRedsimCookies } from "@/server/redsim-cookies";

export function POST() {
  const jar = cookies();
  clearRedsimCookies((name, value, options) => jar.set(name, value, options));
  return NextResponse.json({ ok: true });
}
