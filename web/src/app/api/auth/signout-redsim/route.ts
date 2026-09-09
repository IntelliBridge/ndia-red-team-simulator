// /api/auth/signout-redsim — clear the Redsim-side cookies.
//
// Better Auth's own /api/auth/sign-out takes care of its session cookie and
// the Keycloak end-session call. This route is the matching Redsim-side
// cleanup: clear redsim_api_session and redsim_csrf so a leftover cookie
// cannot keep authenticating after sign-out.
//
// POST is the client path: the QueryClient's global handler calls it when a
// procedure answers 401. GET is the server path: a server component cannot
// write cookies, so an awaited prefetch that hits a 401 redirects the browser
// here instead (KTD7). U7 extends the GET form with the fetch-metadata refusal
// and the dev-cookie clear.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { env } from "@/env";
import { verifyHopToken } from "@/server/gate";
import { clearRedsimCookies } from "@/server/redsim-cookies";
import { cookieReaderFromHeader } from "@/server/trpc/context";

export function POST() {
  const jar = cookies();
  clearRedsimCookies((name, value, options) => jar.set(name, value, options));
  return NextResponse.json({ ok: true });
}

/** Where the hop always lands. No caller-supplied target, so no open redirect. */
const LOGIN_TARGET = "/login?reason=rejected";

/**
 * The server-prefetch hop.
 *
 * The browser recomputes `Sec-Fetch-Site` against the original initiator on
 * every redirect leg, so a run link opened from another site would reach this
 * form as cross-site and be refused, reopening the very loop the form closes.
 * The short-lived token in the query stands in for that check, and it is bound
 * to the credential the prefetch forwarded: a token minted with a garbage
 * cookie cannot log a different user out. A legitimate cross-site entry still
 * sends its own rejected cookie on the top-level GET, so it passes.
 *
 * The 303 goes to a fixed target, and clearing cookies is the only state this
 * changes.
 */
export async function GET(request: Request): Promise<NextResponse> {
  const cookie = cookieReaderFromHeader(request.headers.get("cookie"));
  const credential =
    cookie(env.REDSIM_API_SESSION_COOKIE) ?? cookie(env.REDSIM_DEV_TOKEN_COOKIE);
  const token = new URL(request.url).searchParams.get("hop");

  if (!(await verifyHopToken(env.BETTER_AUTH_SECRET ?? "", token, credential))) {
    return new NextResponse(null, { status: 403 });
  }

  const response = NextResponse.redirect(new URL(LOGIN_TARGET, request.url), 303);
  clearRedsimCookies((name, value, options) => response.cookies.set(name, value, options));
  return response;
}
