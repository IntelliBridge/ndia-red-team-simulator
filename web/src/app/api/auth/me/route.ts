import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { redsimCookieNames } from "@/server/redsim-cookies";
import { readRedsimSessionClaims } from "@/server/redsim-session";

/**
 * Who this browser is signed in as.
 *
 * The session cookie is httpOnly, so the client cannot read the identity it
 * carries. The user menu needs a name to show and an initial to draw, and
 * nothing else, so this answers those two fields and the subject, never the
 * token, the roles or the realm's own wording. No session is a 401 rather
 * than an empty body, so the menu can tell "signed out" from "still loading".
 */
export async function GET(): Promise<NextResponse> {
  const token = cookies().get(redsimCookieNames.session)?.value;
  const claims = await readRedsimSessionClaims(token);
  if (!claims) return NextResponse.json({ error: "not signed in" }, { status: 401 });
  return NextResponse.json(
    { sub: claims.sub, email: claims.email, name: claims.name },
    { headers: { "cache-control": "no-store" } },
  );
}
