// The cookie-presence gate and the sign-out hop token.
//
// Everything here has to run on the edge runtime, because Next 14.2 runs
// middleware there and nowhere else. So: Web Crypto rather than node:crypto,
// and no import of redsim-session.ts or redsim-cookies.ts, both of which pull
// node:crypto in. The three cookie names come from env.js, which defaults them,
// so the edge bundle and the node modules read one validated source (KTD7).
import { DEV_ENVS, env } from "@/env";

/** Paths that render without a credential. */
const PUBLIC_PATHS = new Set(["/login"]);

export type GateRequest = {
  pathname: string;
  /** Presence only. Middleware never validates a cookie. The API does (R12). */
  hasSessionCookie: boolean;
  hasDevTokenCookie: boolean;
};

export type GateDecision = { action: "pass" } | { action: "redirect"; to: string };

/** Whether this deployment may honour a dev token or answer from fixtures. */
export function devEnvironment(): boolean {
  return DEV_ENVS.includes(env.REDSIM_ENV);
}

/**
 * Decide from cookie presence alone.
 *
 * Better Auth's own session cookie is deliberately not a pass: a Keycloak
 * login that failed to mint the redsim pair (signing key unset) has no API
 * access at all, and bouncing that case to /login is what lets R36 explain it.
 *
 * Fixture mode passes everything, because the fixture resolver answers without
 * a credential (KTD13).
 */
export function gateDecision(request: GateRequest): GateDecision {
  const authenticated =
    request.hasSessionCookie ||
    (request.hasDevTokenCookie && devEnvironment()) ||
    (env.REDSIM_DEV_FIXTURES && devEnvironment());

  if (PUBLIC_PATHS.has(request.pathname)) {
    return authenticated ? { action: "redirect", to: "/dashboard" } : { action: "pass" };
  }
  return authenticated ? { action: "pass" } : { action: "redirect", to: "/login" };
}

// --- The sign-out hop token (KTD7) -------------------------------------------

/**
 * Seconds a hop token stays valid. Long enough for one redirect chain, short
 * enough that a leaked token is not a logout primitive.
 */
export const HOP_TOKEN_TTL_SECONDS = 60;

const DOMAIN_LABEL = "redsim-hop:";

const encoder = new TextEncoder();

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

/** Length-safe, value-independent comparison. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Mint the token a server prefetch puts in the sign-out hop's query.
 *
 * Bound to the credential the prefetch actually forwarded and the API refused,
 * so the token cannot be minted with a garbage cookie and then used to log
 * another user out cross-site. That binding is what makes it safe to accept
 * the token in place of the fetch-metadata check, which a redirect hop
 * recomputes against the original initiator and would otherwise refuse.
 */
export async function mintHopToken(
  secret: string,
  credential: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const digest = await sha256Hex(credential);
  const mac = await hmacHex(secret, `${DOMAIN_LABEL}${nowSeconds}:${digest}`);
  return `${nowSeconds}.${mac}`;
}

/**
 * Verify a hop token against the credential the incoming request still carries.
 *
 * A legitimate cross-site entry still sends its rejected cookie on the
 * top-level GET, so it passes. A token minted for a different value does not.
 */
export async function verifyHopToken(
  secret: string,
  token: string | null | undefined,
  credential: string | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  if (!token || credential === undefined) return false;
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const issued = Number(token.slice(0, dot));
  if (!Number.isInteger(issued)) return false;
  if (issued > nowSeconds + 5) return false;
  if (nowSeconds - issued > HOP_TOKEN_TTL_SECONDS) return false;
  const expected = await mintHopToken(secret, credential, issued);
  return constantTimeEqual(token, expected);
}
