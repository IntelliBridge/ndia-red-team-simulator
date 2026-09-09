// POST /api/auth/login: the branded sign-in.
//
// The login page posts a username and password here. The route runs the
// Keycloak password grant server-side and, on success, mints the same
// redsim_api_session and redsim_csrf pair the code flow's after-hook mints,
// through the same setRedsimCookies. FastAPI cannot tell the two apart, and
// the tRPC context and the middleware gate need no change.
//
// The password is read from the body, handed to the grant and dropped. It is
// never logged, never echoed and never stored.

import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";

import { env } from "@/env";
import { PasswordGrantError, passwordGrant } from "@/server/keycloak-password";
import { setRedsimCookies } from "@/server/redsim-cookies";
import { checkMutationRequest } from "@/server/trpc/mutation-gate";

/** What the page sends. Bounds keep an oversized body out of the grant. */
const LoginBody = z.object({
  username: z.string().trim().min(1).max(256),
  password: z.string().min(1).max(1024),
});

/** A refusal the page can render. The message is the whole diagnostic. */
function refuse(status: number, error: string, headers?: HeadersInit): NextResponse {
  return NextResponse.json({ error }, { status, headers });
}

/**
 * Sign in with a username and password.
 *
 * Gated like every other mutation: same-origin fetch metadata or a matching
 * `Origin`, and a JSON body, so a cross-site form post cannot drive a sign-in
 * with someone else's credentials into this browser's cookie jar.
 *
 * @param request - The incoming request.
 * @returns 200 with `{ ok, email, name }` and the cookie pair set; 400 for a
 *   malformed body; 401 `invalid_credentials` for any refusal of the
 *   credentials; 403 for a request from another origin; 500 `mint_failed`
 *   when the credentials were accepted but the web tier holds no signing key;
 *   503 `identity_unavailable` with `Retry-After` when Keycloak cannot be
 *   reached, and 503 `identity_misconfigured` when no realm is configured.
 */
export async function POST(request: Request): Promise<NextResponse> {
  const verdict = checkMutationRequest({
    secFetchSite: request.headers.get("sec-fetch-site"),
    origin: request.headers.get("origin"),
    contentType: request.headers.get("content-type"),
    acceptedContentType: "application/json",
    trustedOrigin: env.BETTER_AUTH_URL ?? "",
  });
  if (!verdict.ok) return refuse(403, verdict.reason);

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return refuse(400, "invalid_body");
  }
  const parsed = LoginBody.safeParse(raw);
  if (!parsed.success) return refuse(400, "invalid_body");

  let claims;
  try {
    claims = await passwordGrant(parsed.data.username, parsed.data.password);
  } catch (err) {
    if (err instanceof PasswordGrantError) {
      if (err.reason === "invalid_credentials") return refuse(401, err.reason);
      // The operator needs the detail; the browser gets only the reason.
      console.error(`redsim: login refused, ${err.reason}:`, err.message);
      return refuse(503, err.reason, { "retry-after": "10" });
    }
    throw err;
  }

  const jar = cookies();
  try {
    await setRedsimCookies(claims, (name, value, options) => jar.set(name, value, options));
  } catch (err) {
    // Typically REDSIM_API_SESSION_PRIVATE_KEY unset. The credentials were
    // right, so say so distinctly rather than as a bad password.
    console.error("redsim: login accepted but the API session could not be minted:", err);
    return refuse(500, "mint_failed");
  }

  return NextResponse.json({ ok: true, email: claims.email, name: claims.name });
}
