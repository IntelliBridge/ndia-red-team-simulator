// POST /api/auth/refresh-api-session — re-mint the redsim_api_session and
// redsim_csrf cookies for the currently signed-in user.
//
// Nothing calls this route today. The measured current behaviour is a 900
// second cookie lifetime followed by a forced interactive re-auth: requireAuth
// pushes to /login once the non-httpOnly redsim_csrf cookie expires, and
// /login renders a button the user must click. Adding an interval caller is
// deferred work under KTD12, and R22 forbids adding one here.
//
// The carry-forward is only ever taken from a signature-verified existing
// cookie that is bound to the caller. Re-signing claims decoded without
// verification would let any logged-in user forge roles into a freshly minted
// token, and re-signing a cookie that verifies but belongs to someone else
// would hand them that person's roles.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { getSession } from "@/server/better-auth";
import {
  redsimCookieNames,
  setRedsimCookies,
  verifyOwnSessionCookie,
} from "@/server/redsim-cookies";

export async function POST() {
  const session = await getSession();
  if (!session?.user) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }

  const jar = cookies();
  const claims = await verifyOwnSessionCookie(
    jar.get(redsimCookieNames.session)?.value,
    session.user.email ?? undefined,
  );
  if (!claims) {
    return NextResponse.json({ error: "not signed in" }, { status: 401 });
  }

  try {
    const maxAge = await setRedsimCookies(claims, (name, value, options) =>
      jar.set(name, value, options),
    );
    return NextResponse.json({ refreshed: true, expires_in: maxAge });
  } catch (err) {
    console.warn("redsim: refresh-api-session failed", err);
    return NextResponse.json({ error: "mint failed" }, { status: 500 });
  }
}
