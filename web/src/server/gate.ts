// The sign-out hop token.
//
// The server prefetch cannot clear cookies, so when the API rejects the
// browser's session it redirects to the sign-out route with a short-lived token
// bound to the rejected cookie. The route verifies the token, clears the
// credentials and lands on /login. Nothing else gates a request here: the
// pages check for the session on the client and the API refuses what it does
// not trust.

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
 * top-level GET, so it passes; a token minted for a different value does not.
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
