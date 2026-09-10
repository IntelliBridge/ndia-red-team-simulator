import "server-only";

import { TRPCError } from "@trpc/server";
import type { TRPC_ERROR_CODE_KEY } from "@trpc/server/rpc";

import { env } from "@/env";
import type { UpstreamErrorBlock, UpstreamErrorData } from "@/lib/trpc/types";

import type { ProcedureContext } from "./context";

/** Seconds before an upstream call is aborted, unless the caller widens it. */
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * HTTP status to tRPC code (KTD8).
 *
 * Measured against `redsim/api/errors.py` at the branch cut (29db42c). The
 * spec 17.3 addendum of wave B0 added `endpoint_unreachable` at 502, a status
 * the plan's table did not carry, so 502 gets its row here. `capacity_deferred`
 * is a 202 marker that rides in an accepted response body and is never raised
 * as a refusal, so it needs none.
 *
 * 411 is the one row that answers to no code in that table at all. It comes
 * from a raw `HTTPException(411)` in `redsim/api/v1/models.py`, which refuses
 * an upload with no `Content-Length` and bypasses `redsim/api/errors.py`
 * entirely. It is Length Required, so it maps to BAD_REQUEST: the request is
 * malformed, and the payload it lacks a length for is not necessarily too
 * large. 413 is the row for too large.
 */
const TRPC_CODE_BY_STATUS: Readonly<Record<number, TRPC_ERROR_CODE_KEY>> = {
  400: "BAD_REQUEST",
  401: "UNAUTHORIZED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  409: "CONFLICT",
  411: "BAD_REQUEST",
  413: "PAYLOAD_TOO_LARGE",
  415: "UNSUPPORTED_MEDIA_TYPE",
  422: "UNPROCESSABLE_CONTENT",
  429: "TOO_MANY_REQUESTS",
  501: "NOT_IMPLEMENTED",
  502: "BAD_GATEWAY",
  503: "SERVICE_UNAVAILABLE",
};

export function trpcCodeForStatus(status: number): TRPC_ERROR_CODE_KEY {
  return TRPC_CODE_BY_STATUS[status] ?? "INTERNAL_SERVER_ERROR";
}

/**
 * The code to synthesize when the API answers with a plain-string `detail`.
 *
 * `forbidden`, `not_found`, `rate_limited` and `db_unavailable` are the four
 * names `redsim/api/errors.py` lists as string-detail codes. `unauthenticated`
 * and `service_unavailable` are web-side names with no row in that table: the
 * API answers 401 and a connection failure with no envelope at all, and a
 * component still has to branch on something.
 */
const SYNTHESIZED_CODE_BY_STATUS: Readonly<Record<number, string>> = {
  401: "unauthenticated",
  403: "forbidden",
  404: "not_found",
  429: "rate_limited",
  503: "db_unavailable",
};

export function synthesizedCodeForStatus(status: number): string {
  return SYNTHESIZED_CODE_BY_STATUS[status] ?? "upstream_error";
}

/**
 * A tRPC error carrying the upstream envelope as an own enumerable property.
 *
 * `data` is set at throw time rather than by the HTTP error formatter, because
 * the server options proxy calls procedures directly and the formatter never
 * runs on the prefetch path (KTD4). The formatter copies this object into the
 * wire shape rather than rebuilding it.
 */
export class UpstreamTRPCError extends TRPCError {
  readonly data: UpstreamErrorData;

  constructor(code: TRPC_ERROR_CODE_KEY, data: UpstreamErrorData) {
    super({ code, message: data.upstream.message });
    this.name = "UpstreamTRPCError";
    this.data = data;
  }
}

/** An envelope block before the HTTP status is stamped onto it. */
type EnvelopeBlock = { code: string; message: string; [extra: string]: unknown };

/** Build the refusal for a status and an envelope block. */
function refuse(status: number, block: EnvelopeBlock, requestId: string) {
  const upstream: UpstreamErrorBlock = { ...block, status };
  return new UpstreamTRPCError(trpcCodeForStatus(status), { upstream, requestId });
}

/**
 * What a procedure declares its upstream body is.
 *
 * Structural rather than a zod import, so this module stays free of the
 * validator and a procedure may supply anything with a `parse`. Required
 * rather than optional: it is what makes `T` a checked shape instead of an
 * assertion, and a procedure added later cannot forget it without failing to
 * compile.
 */
export type UpstreamSchema<T> = { parse(value: unknown): T };

export type UpstreamRequest = {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Path segments, each encoded once. No segment may contain a slash. */
  segments: readonly string[];
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  /** Widened to 120 s for campaign start (KTD2). */
  timeoutMs?: number;
};

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Parse `{ detail }` per KTD8, tolerating a body that is not the envelope at all. */
function blockFromBody(text: string, status: number): EnvelopeBlock {
  const fallback = { code: synthesizedCodeForStatus(status), message: `API responded ${status}` };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return fallback;
  }
  const detail = (parsed as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") {
    return { code: synthesizedCodeForStatus(status), message: detail };
  }
  if (detail && typeof detail === "object") {
    // `status` is moved aside before refuse() stamps the HTTP status onto the
    // block, because the two names collide. The API's own envelope uses
    // `status` for a domain value: redsim/api/v1/runs_cancel.py sends the run's
    // status with a 409 run_terminal, and runs.cancel is a procedure this layer
    // ships. Spreading the envelope and then stamping the number would have
    // replaced "succeeded" with 409 and left a component no way to read what
    // the run's status actually was.
    const { status: detailStatus, ...envelope } = detail as Record<string, unknown>;
    return {
      ...envelope,
      ...(detailStatus === undefined ? {} : { detail_status: detailStatus }),
      code: typeof envelope.code === "string" ? envelope.code : synthesizedCodeForStatus(status),
      message:
        typeof envelope.message === "string" ? envelope.message : `API responded ${status}`,
    };
  }
  return fallback;
}

/**
 * The one call into FastAPI.
 *
 * Every request is `no-store`, carries an abort timeout and the caller's own
 * credential, and generates nothing the browser did not send. Nothing here
 * logs the outbound `Cookie` or `Authorization` value, the API host, or the
 * text of a fetch failure: the cause of a connection error names the host, so
 * a network failure is reported as a fixed string and the cause is dropped
 * before anything is logged (KTD2, R2).
 *
 * Nothing leaves here unchecked. `schema` is the procedure's declaration of
 * what the body is, `T` comes from it rather than from a cast, and both the
 * upstream body and a recorded fixture go through it. A body that does not
 * match is a 502 refusal carrying no part of the offending value, the same way
 * a body that is not JSON at all is.
 *
 * @param ctx - The call's context, for its credential and request id.
 * @param init - The request to make.
 * @param schema - Anything with a `parse`, usually a zod schema.
 * @returns The parsed body, or `schema.parse(undefined)` for an empty one.
 */
export async function upstreamFetch<T>(
  ctx: ProcedureContext,
  init: UpstreamRequest,
  schema: UpstreamSchema<T>,
): Promise<T> {
  const path = init.segments.map((s) => encodeURIComponent(s)).join("/");

  // The fixture branch runs before the credential check, so a fixture-mode
  // request with no cookie answers from fixtures rather than being refused
  // (KTD13). The condition reads NEXT_PUBLIC_REDSIM_DEV_FIXTURES as a literal
  // member expression because that is the only form Next inlines, which is
  // what lets a build without the flag drop the module from the output.
  // deploy/Dockerfile.web sets it to "0" so the comparison folds to false and
  // the branch goes with it; U14 asserts the absence by grepping the build
  // output for the module's sentinel.
  //
  // Compared against "1" rather than read for truthiness: the string "0" is
  // truthy, so the old form had this half on where env.js's flag() had it off.
  // A comparison against one literal is also what keeps the branch foldable,
  // which an includes() over the four spellings flag() accepts would not be,
  // so the public flag is exactly "1" and any other spelling reads as off.
  // `ctx.fixtures` is the runtime authority beside it: the public flag alone
  // can never turn fixtures on.
  if (ctx.fixtures && process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES === "1") {
    const { resolveFixture } = await import("./fixtures");
    const fixture = resolveFixture(init.method, `/${path}`);
    if (fixture !== undefined) {
      try {
        return schema.parse(fixture);
      } catch {
        throw refuse(
          502,
          {
            code: "upstream_error",
            message: "the recorded fixture does not match this route's contract",
          },
          ctx.requestId,
        );
      }
    }
    throw refuse(
      404,
      { code: "not_found", message: "no fixture is recorded for this route" },
      ctx.requestId,
    );
  }

  if (ctx.credential === null) {
    throw refuse(
      401,
      { code: "unauthenticated", message: "sign in to continue" },
      ctx.requestId,
    );
  }

  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(init.query ?? {})) {
    if (value !== undefined) search.set(key, String(value));
  }
  const url = `${env.REDSIM_API_URL}/${path}${search.size ? `?${search}` : ""}`;

  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Redsim-Request-ID": ctx.requestId,
  };
  headers.Cookie = ctx.credential.cookieHeader;
  if (ctx.credential.csrfHeader !== null && MUTATING.has(init.method)) {
    headers[env.NEXT_PUBLIC_REDSIM_CSRF_HEADER] = ctx.credential.csrfHeader;
  }
  if (init.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  let text: string;
  try {
    response = await fetch(url, {
      method: init.method,
      cache: "no-store",
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(init.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    // Inside the same try as the fetch, because the same abort signal cuts the
    // body stream: a response whose headers arrived before the timeout and
    // whose body did not throws here. Read outside, that throw escaped as an
    // untyped error, skipped the refusal below and reached a component as
    // unknown_error rather than the 503 this function promises.
    text = await response.text();
  } catch {
    // Deliberately not `catch (cause)`: the cause of a fetch failure names the
    // API host, and this line is the one that reaches the logs.
    console.error(
      `upstream request failed request_id=${ctx.requestId} method=${init.method} route=/${init.segments[0] ?? ""}/${init.segments[1] ?? ""}`,
    );
    throw refuse(
      503,
      { code: "service_unavailable", message: "the API could not be reached" },
      ctx.requestId,
    );
  }

  if (!response.ok) throw refuse(response.status, blockFromBody(text, response.status), ctx.requestId);

  let parsed: unknown;
  try {
    parsed = text ? (JSON.parse(text) as unknown) : undefined;
  } catch {
    throw refuse(
      502,
      { code: "upstream_error", message: "the API returned a body that is not JSON" },
      ctx.requestId,
    );
  }

  try {
    // An empty body reaches the schema as undefined, so a route that answers
    // 204 declares that with its schema rather than being handed {} blind.
    return schema.parse(parsed);
  } catch {
    // Deliberately not the validator's own message: it quotes the values that
    // failed, and those are response data.
    throw refuse(
      502,
      { code: "upstream_error", message: "the API returned a body this route cannot read" },
      ctx.requestId,
    );
  }
}
