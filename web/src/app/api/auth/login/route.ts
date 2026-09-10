import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { env } from "@/env";
import { loginWithPassword, statusForFailure } from "@/server/identity";
import { redsimCookieNames, redsimCookieOptions, setRedsimCookies } from "@/server/redsim-cookies";
import { refreshTtlSeconds, sealRefreshToken } from "@/server/refresh-cookie";
import { checkRequestOrigin } from "@/server/trpc/mutation-gate";

/**
 * The login form's submit.
 *
 * Takes the email and password once, hands them to the identity module and
 * never keeps them. A success sets the three credential cookies and answers
 * `{ ok: true }`; a refusal answers a code the page turns into a sentence.
 * The realm's own wording never reaches the browser.
 *
 * Same-origin only, through the origin legs of the mutation gate, so a form on
 * another site cannot sign this browser in as someone else.
 */

/** Longest email the realm would accept, with room to spare. */
const MAX_EMAIL_LENGTH = 254;
/** Longest password we forward. Anything longer is not a password. */
const MAX_PASSWORD_LENGTH = 1024;

type Body = { email: string; password: string };

function readBody(value: unknown): Body | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const { email, password } = value as Record<string, unknown>;
  if (typeof email !== "string" || typeof password !== "string") return undefined;
  const trimmed = email.trim();
  if (!trimmed || trimmed.length > MAX_EMAIL_LENGTH) return undefined;
  if (!password || password.length > MAX_PASSWORD_LENGTH) return undefined;
  return { email: trimmed, password };
}

export async function POST(request: Request): Promise<NextResponse> {
  const verdict = checkRequestOrigin({
    secFetchSite: request.headers.get("sec-fetch-site"),
    origin: request.headers.get("origin"),
    trustedOrigin: env.REDSIM_WEB_ORIGIN ?? "",
  });
  if (!verdict.ok) return new NextResponse(null, { status: 403 });

  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    parsed = undefined;
  }
  const body = readBody(parsed);
  if (!body) return NextResponse.json({ error: "invalid_request" }, { status: 400 });

  const result = await loginWithPassword(body.email, body.password);
  if (!result.ok) {
    const status = statusForFailure(result.code);
    if (status >= 500) console.error(`redsim: login refused upstream (${result.code}): ${result.detail}`);
    return NextResponse.json(
      { error: result.code },
      { status, headers: status === 503 ? { "retry-after": "10" } : undefined },
    );
  }

  const jar = cookies();
  try {
    const expiresIn = await setRedsimCookies(result.claims, (name, value, options) =>
      jar.set(name, value, options),
    );
    if (result.refreshToken) {
      const ttl = refreshTtlSeconds(result.refreshExpiresIn);
      jar.set(
        redsimCookieNames.refresh,
        await sealRefreshToken(result.refreshToken, ttl),
        redsimCookieOptions("refresh", ttl),
      );
    }
    return NextResponse.json({ ok: true, expires_in: expiresIn });
  } catch (err) {
    console.error("redsim: login succeeded upstream but the session could not be minted", err);
    return NextResponse.json({ error: "unavailable" }, { status: 503 });
  }
}
