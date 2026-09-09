import "server-only";

import { env } from "@/env";
import { devEnvironment } from "@/server/gate";

/**
 * Whether this deployment may honour a dev token or answer from fixtures.
 *
 * The middleware gate's own check under this module's name, not a second copy
 * of it. Middleware and the tRPC context have to agree on which deployments
 * accept a dev token, and one of them drifting from the other is a credential
 * bug rather than a cosmetic one (KTD7, KTD13).
 */
export { devEnvironment as isDevEnvironment };

/**
 * What the tRPC layer forwards upstream on behalf of one caller.
 *
 * There is no shared service credential: every upstream request carries the
 * browser's own cookie pair or its own dev bearer, so the API's per-principal
 * rate buckets and RLS tenancy stay per user (KTD2, R2).
 */
export type Credential =
  | {
      kind: "cookie";
      /** Exactly the redsim session and csrf cookies, in that order. */
      cookieHeader: string;
      /** The client's own X-Redsim-CSRF, never synthesized from the cookie. */
      csrfHeader: string | null;
    }
  | { kind: "bearer"; token: string }
  | null;

/** Everything the incoming HTTP request contributes, shared by a whole batch. */
export type TrpcContext = {
  /**
   * One id per procedure call, in the order the calls started (R3).
   *
   * The fetch adapter's `responseMeta` joins them into the response header, so
   * a user can quote the id of any call in a batch. A batch is one HTTP
   * request and therefore one context, which is why the ids live here rather
   * than being minted once per request.
   */
  requestIds: string[];
  credential: Credential;
  /** Read by the mutation gate (KTD2). */
  secFetchSite: string | null;
  origin: string | null;
  contentType: string | null;
  /** Answer from fixtures rather than from FastAPI (KTD13). */
  fixtures: boolean;
};

/** The context one procedure call sees: the request's, plus its own id. */
export type ProcedureContext = TrpcContext & { requestId: string };

/** A cookie lookup by name, so the builder does not care where cookies came from. */
export type CookieReader = (name: string) => string | undefined;

/**
 * The request as the context builder consumes it.
 *
 * A route handler passes the request's own headers; a server component passes
 * the results of `headers()` and `cookies()`. Keeping both behind one shape is
 * what makes `requestParts` the single site that changes when those Next APIs
 * become async in the six-major bump.
 */
export type RequestParts = { headers: Headers; cookie: CookieReader };

/**
 * Parse a `Cookie` header into a lookup.
 *
 * A pair whose value is not valid percent-encoding is skipped, the way Next's
 * own cookie parser skips it. `decodeURIComponent` throws a `URIError` on a
 * value like `junk=100%`, and both callers run this synchronously outside any
 * try/catch: the tRPC route handler builds the context before
 * `fetchRequestHandler`, and the sign-out hop builds it before it can clear
 * anything. One malformed cookie anywhere in the jar would otherwise turn
 * every procedure call and the recovery hop alike into a raw 500, leaving the
 * user with no way out.
 *
 * The raw value is deliberately not kept as a fallback. This reader has to
 * agree with `cookies()` on the server-component side, which decodes, and a
 * raw value here would make a legitimately encoded credential such as
 * `redsim_dev_token=dev%3Aoperator%40example.test` read differently on the two
 * paths and refuse the hop.
 */
export function cookieReaderFromHeader(header: string | null): CookieReader {
  const jar = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    try {
      jar.set(trimmed.slice(0, eq), decodeURIComponent(trimmed.slice(eq + 1)));
    } catch {
      // Not a cookie this app can read. Skipping the pair keeps the rest of
      // the jar usable, which is what makes the recovery hop reachable.
      continue;
    }
  }
  return (name) => jar.get(name);
}

/** The route-handler side of the seam. */
export function requestPartsFromRequest(request: Request): RequestParts {
  return {
    headers: request.headers,
    cookie: cookieReaderFromHeader(request.headers.get("cookie")),
  };
}

/**
 * The server-component side of the seam.
 *
 * `cookies()` and `headers()` are synchronous on Next 14.2 and become async in
 * Next 15. This function is the only place that has to change.
 */
export function requestPartsFromNextHeaders(
  nextHeaders: Headers,
  nextCookies: { get(name: string): { value: string } | undefined },
): RequestParts {
  return { headers: nextHeaders, cookie: (name) => nextCookies.get(name)?.value };
}

/** A 32-character hex token, the shape the API's own request-id middleware mints. */
export function newRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Build the per-request context.
 *
 * The credential rules, in order:
 *
 * 1. The redsim session cookie wins when present. The outbound `Cookie` header
 *    is built from exactly two names, because the API's double-submit
 *    middleware compares the client's header against the csrf cookie on its
 *    own request and answers 403 without it.
 * 2. Otherwise the dev-token cookie becomes a bearer, but only in `dev` or
 *    `test`. `prod`, `staging` and any unknown value forward nothing; an unset
 *    value reads as `dev` through the env module's default.
 * 3. Otherwise there is no credential, and `upstreamFetch` refuses before any
 *    upstream call.
 *
 * Nothing else crosses: not the Better Auth session cookie, which the API must
 * never see, not any other client header.
 */
export function createContext(parts: RequestParts): TrpcContext {
  const { headers, cookie } = parts;
  const session = cookie(env.REDSIM_API_SESSION_COOKIE);
  const csrfCookie = cookie(env.REDSIM_CSRF_COOKIE);
  const devToken = cookie(env.REDSIM_DEV_TOKEN_COOKIE);

  let credential: Credential = null;
  if (session !== undefined) {
    const pairs = [`${env.REDSIM_API_SESSION_COOKIE}=${session}`];
    if (csrfCookie !== undefined) pairs.push(`${env.REDSIM_CSRF_COOKIE}=${csrfCookie}`);
    credential = {
      kind: "cookie",
      cookieHeader: pairs.join("; "),
      csrfHeader: headers.get(env.NEXT_PUBLIC_REDSIM_CSRF_HEADER.toLowerCase()),
    };
  } else if (devToken !== undefined && devEnvironment()) {
    credential = { kind: "bearer", token: devToken };
  }

  return {
    requestIds: [],
    credential,
    secFetchSite: headers.get("sec-fetch-site"),
    origin: headers.get("origin"),
    contentType: headers.get("content-type"),
    fixtures: env.REDSIM_DEV_FIXTURES && devEnvironment(),
  };
}

/**
 * Start one procedure call: mint its id, record it for the response header,
 * and hand the call a context that carries it.
 */
export function beginCall(ctx: TrpcContext): ProcedureContext {
  const requestId = newRequestId();
  ctx.requestIds.push(requestId);
  return { ...ctx, requestId };
}
