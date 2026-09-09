// @vitest-environment node
//
// The error contract of KTD8 and the fetch hygiene of KTD2, measured against
// the status table in redsim/api/errors.py at 29db42c.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { z } from "zod";

import { upstreamError } from "@/lib/api";

import { beginCall, createContext, requestPartsFromRequest, type ProcedureContext } from "./context";
import { trpcCodeForStatus, upstreamFetch } from "./upstream";

const API_HOST = "api.internal.invalid";

/** For the cases whose subject is the refusal, not the body. */
const anyBody = z.unknown();

/** The runs.list shape, for the two cases that assert on what came back. */
const runsListBody = z.looseObject({ runs: z.array(z.unknown()), count: z.number() });

const fetchMock = vi.fn();

function ctxWith(cookies: Record<string, string>, headers: Record<string, string> = {}): ProcedureContext {
  const cookie = Object.entries(cookies)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("; ");
  return beginCall(
    createContext(
      requestPartsFromRequest(
        new Request("http://localhost:3000/api/trpc/runs.list", {
          headers: cookie ? { ...headers, cookie } : headers,
        }),
      ),
    ),
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function lastInit(): RequestInit {
  return (fetchMock.mock.calls.at(-1)?.[1] ?? {}) as RequestInit;
}

function headerOf(name: string): string | undefined {
  const headers = lastInit().headers as Record<string, string> | undefined;
  return headers?.[name];
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("status to tRPC code map (KTD8)", () => {
  it("maps every status the spec 17.3 table can produce", () => {
    expect(trpcCodeForStatus(400)).toBe("BAD_REQUEST");
    expect(trpcCodeForStatus(401)).toBe("UNAUTHORIZED");
    expect(trpcCodeForStatus(403)).toBe("FORBIDDEN");
    expect(trpcCodeForStatus(404)).toBe("NOT_FOUND");
    expect(trpcCodeForStatus(409)).toBe("CONFLICT");
    expect(trpcCodeForStatus(413)).toBe("PAYLOAD_TOO_LARGE");
    expect(trpcCodeForStatus(415)).toBe("UNSUPPORTED_MEDIA_TYPE");
    expect(trpcCodeForStatus(422)).toBe("UNPROCESSABLE_CONTENT");
    expect(trpcCodeForStatus(429)).toBe("TOO_MANY_REQUESTS");
    expect(trpcCodeForStatus(501)).toBe("NOT_IMPLEMENTED");
    expect(trpcCodeForStatus(503)).toBe("SERVICE_UNAVAILABLE");
  });

  it("maps the 502 the Phase B addendum added for endpoint_unreachable", () => {
    // Drift against the plan's KTD8 table: redsim/api/errors.py gained
    // ENDPOINT_UNREACHABLE at 502 in the spec 17.3 addendum (wave B0), a
    // status the plan's map did not carry.
    expect(trpcCodeForStatus(502)).toBe("BAD_GATEWAY");
  });

  it("maps 411 as a bad request, the status models.py raises for a missing Content-Length", () => {
    // The one row with no code in redsim/api/errors.py: a raw
    // HTTPException(411) from redsim/api/v1/models.py. 411 is Length
    // Required, not Payload Too Large, and 413 is the row for too large.
    expect(trpcCodeForStatus(411)).toBe("BAD_REQUEST");
  });

  it("falls back to INTERNAL_SERVER_ERROR for a status the table does not name", () => {
    expect(trpcCodeForStatus(418)).toBe("INTERNAL_SERVER_ERROR");
  });
});

describe("credential forwarding", () => {
  it("sends the cookie pair and the client CSRF header on a mutation, and no bearer", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { run_id: "r1" }));
    const ctx = ctxWith(
      { redsim_api_session: "s", redsim_csrf: "c", redsim_dev_token: "dev:a@b.test" },
      { "x-redsim-csrf": "c", "x-something-else": "nope" },
    );
    await upstreamFetch(ctx, { method: "POST", segments: ["v1", "runs", "r1", "cancel"] }, anyBody);

    expect(headerOf("Cookie")).toBe("redsim_api_session=s; redsim_csrf=c");
    expect(headerOf("X-Redsim-CSRF")).toBe("c");
    expect(headerOf("Authorization")).toBeUndefined();
    expect(headerOf("x-something-else")).toBeUndefined();
    expect(lastInit().cache).toBe("no-store");
  });

  it("sends a bearer and no cookie on the dev-token path", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}));
    const ctx = ctxWith({ redsim_dev_token: "dev:a@b.test" }, { "x-redsim-csrf": "c" });
    await upstreamFetch(ctx, { method: "POST", segments: ["v1", "runs"] }, anyBody);

    expect(headerOf("Authorization")).toBe("Bearer dev:a@b.test");
    expect(headerOf("Cookie")).toBeUndefined();
    expect(headerOf("X-Redsim-CSRF")).toBeUndefined();
  });

  it("refuses before any upstream call when no credential is present", async () => {
    const ctx = ctxWith({});
    const error = await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }, anyBody).catch(
      (e: unknown) => e,
    );
    expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("issues zero upstream requests for a batch of twenty anonymous calls", async () => {
    const ctx = ctxWith({});
    await Promise.all(
      Array.from({ length: 20 }, () =>
        upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }, anyBody).catch(() => undefined),
      ),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never forwards an upstream Set-Cookie back to the caller", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ runs: [], count: 0 }), {
        status: 200,
        headers: { "content-type": "application/json", "set-cookie": "evil=1" },
      }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const result = await upstreamFetch(
      ctx,
      { method: "GET", segments: ["v1", "runs"] },
      runsListBody,
    );
    expect(result).toEqual({ runs: [], count: 0 });
    expect(JSON.stringify(result)).not.toContain("evil");
  });
});

describe("path and query encoding", () => {
  it("encodes each segment once and never into a second path segment", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs", "r%201"] }, anyBody);

    const url = String(fetchMock.mock.calls.at(-1)?.[0]);
    expect(url).toBe("http://localhost:8000/v1/runs/r%25201");
    expect(url.split("/").length).toBe(6);
  });

  it("drops undefined query values and encodes the rest", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    await upstreamFetch(ctx, {
      method: "GET",
      segments: ["v1", "runs"],
      query: { project: "p 1", limit: 25, severity: undefined },
    }, anyBody);
    const url = String(fetchMock.mock.calls.at(-1)?.[0]);
    expect(url).toBe("http://localhost:8000/v1/runs?project=p+1&limit=25");
  });
});

describe("the API envelope becomes typed error data", () => {
  it("carries an object detail whole, with every extra field", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, {
        detail: {
          code: "incompatible_campaigns",
          message: "campaigns with different settings cannot be compared",
          reasons: ["seed"],
        },
      }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = (await upstreamFetch(ctx, {
      method: "GET",
      segments: ["v1", "runs", "r1", "compare"],
    }, anyBody).catch((e: unknown) => e)) as { code: string; data: Record<string, unknown> };

    expect(error.code).toBe("CONFLICT");
    expect(error.data).toMatchObject({
      upstream: {
        status: 409,
        code: "incompatible_campaigns",
        reasons: ["seed"],
      },
      requestId: ctx.requestId,
    });
    // Own enumerable, so the shape survives the server prefetch path where the
    // HTTP error formatter never runs (KTD4).
    expect(Object.prototype.hasOwnProperty.call(error, "data")).toBe(true);
    expect(Object.keys(error)).toContain("data");
  });

  it("keeps the envelope's own status as detail_status, so the HTTP status cannot eat it", async () => {
    // The live shape of a 409 from redsim/api/v1/runs_cancel.py, which sends
    // the run's status under the same name refuse() stamps the HTTP status
    // onto. Spreading the envelope and then stamping the number replaced
    // "succeeded" with 409 and lost the domain value entirely.
    fetchMock.mockResolvedValue(
      jsonResponse(409, {
        detail: {
          code: "run_terminal",
          message: "the run is already terminal",
          run_id: "run-1",
          status: "succeeded",
        },
      }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = await upstreamFetch(ctx, {
      method: "POST",
      segments: ["v1", "runs", "run-1", "cancel"],
    }, anyBody).catch((e: unknown) => e);

    expect(upstreamError(error)).toMatchObject({
      status: 409,
      code: "run_terminal",
      run_id: "run-1",
      detail_status: "succeeded",
    });
  });

  it("adds no detail_status when the envelope carries no status of its own", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(422, { detail: { code: "eps_grid_invalid", message: "bad grid" } }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = await upstreamFetch(ctx, { method: "POST", segments: ["v1", "runs"] }, anyBody).catch(
      (e: unknown) => e,
    );

    const upstream = upstreamError(error);
    expect(upstream).toMatchObject({ status: 422, code: "eps_grid_invalid" });
    expect(upstream && "detail_status" in upstream).toBe(false);
  });

  it("synthesizes a code from the status for a plain string detail", async () => {
    fetchMock.mockResolvedValue(jsonResponse(404, { detail: "run not found" }));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = (await upstreamFetch(ctx, {
      method: "GET",
      segments: ["v1", "runs", "nope"],
    }, anyBody).catch((e: unknown) => e)) as { code: string };

    expect(error.code).toBe("NOT_FOUND");
    expect(upstreamError(error)).toMatchObject({
      status: 404,
      code: "not_found",
      message: "run not found",
    });
  });

  it("uses the four string-detail names redsim/api/errors.py lists", async () => {
    const cases: Array<[number, string]> = [
      [403, "forbidden"],
      [404, "not_found"],
      [429, "rate_limited"],
      [503, "db_unavailable"],
    ];
    for (const [status, code] of cases) {
      fetchMock.mockResolvedValue(jsonResponse(status, { detail: "refused" }));
      const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
      const error = await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }, anyBody).catch(
        (e: unknown) => e,
      );
      expect(upstreamError(error)).toMatchObject({ status, code });
    }
  });

  it("synthesizes unauthenticated for a 401, a web-side name with no row in the API table", async () => {
    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "not authenticated" }));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }, anyBody).catch(
      (e: unknown) => e,
    );
    expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
  });
});

describe("the body is validated, never cast", () => {
  it("refuses a 200 whose shape is not what the procedure declared", async () => {
    // The seam every procedure inherits. A cast would have handed the page a
    // value typed as a runs list that was nothing of the kind, and the first
    // sign of it would have been a crash in a component.
    fetchMock.mockResolvedValue(jsonResponse(200, { runs: "not an array", count: 0 }));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = await upstreamFetch(
      ctx,
      { method: "GET", segments: ["v1", "runs"] },
      runsListBody,
    ).catch((e: unknown) => e);

    expect(upstreamError(error)).toMatchObject({ status: 502, code: "upstream_error" });
  });

  it("names no part of the offending body, because that body is response data", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { runs: [{ id: "run-1", secret: "session-secret-value" }], count: "one" }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = (await upstreamFetch(
      ctx,
      { method: "GET", segments: ["v1", "runs"] },
      runsListBody,
    ).catch((e: unknown) => e)) as Error;

    const text = `${error.message} ${JSON.stringify(upstreamError(error))}`;
    expect(text).not.toContain("session-secret-value");
    expect(text).not.toContain("run-1");
  });

  it("keeps the not-JSON refusal distinct from the wrong-shape one", async () => {
    fetchMock.mockResolvedValue(
      new Response("<html>gateway</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = await upstreamFetch(
      ctx,
      { method: "GET", segments: ["v1", "runs"] },
      runsListBody,
    ).catch((e: unknown) => e);

    expect(upstreamError(error)).toMatchObject({
      status: 502,
      message: "the API returned a body that is not JSON",
    });
  });

  it("hands an empty body to the schema as undefined, rather than an invented {}", async () => {
    // A route that answers 204 declares that in its schema. Nothing here
    // decides on its behalf that an empty body means an empty object.
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });

    const allowsEmpty = await upstreamFetch(
      ctx,
      { method: "DELETE", segments: ["v1", "models", "m1"] },
      z.undefined(),
    );
    expect(allowsEmpty).toBeUndefined();

    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    const refusesEmpty = await upstreamFetch(
      ctx,
      { method: "GET", segments: ["v1", "runs"] },
      runsListBody,
    ).catch((e: unknown) => e);
    expect(upstreamError(refusesEmpty)).toMatchObject({ status: 502, code: "upstream_error" });
  });
});

describe("network failure hygiene", () => {
  it("becomes service_unavailable and never repeats the host or the fetch text", async () => {
    fetchMock.mockRejectedValue(
      Object.assign(new Error(`connect ECONNREFUSED ${API_HOST}:8000`), {
        cause: new Error(`getaddrinfo ENOTFOUND ${API_HOST}`),
      }),
    );
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = (await upstreamFetch(ctx, {
      method: "GET",
      segments: ["v1", "runs"],
    }, anyBody).catch((e: unknown) => e)) as Error & { code: string; cause?: unknown };

    expect(error.code).toBe("SERVICE_UNAVAILABLE");
    expect(upstreamError(error)).toMatchObject({ status: 503, code: "service_unavailable" });
    expect(error.message).not.toContain(API_HOST);
    expect(error.message).not.toContain("ECONNREFUSED");
    expect(error.cause).toBeUndefined();
  });

  it("becomes service_unavailable when the body is severed after the headers arrive", async () => {
    // The abort timeout cuts the body stream too, so a response whose headers
    // landed in time and whose body did not throws on the read. Read outside
    // the try, that throw escaped untyped and reached a component as
    // unknown_error rather than the 503 this function promises.
    const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.reject(new Error(`aborted reading from ${API_HOST}`)),
    });
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = (await upstreamFetch(ctx, {
      method: "GET",
      segments: ["v1", "runs"],
    }, anyBody).catch((e: unknown) => e)) as Error & { code: string; cause?: unknown };

    expect(error.code).toBe("SERVICE_UNAVAILABLE");
    expect(upstreamError(error)).toMatchObject({ status: 503, code: "service_unavailable" });
    // The same hygiene as a failed connection: no host, no cause, one line.
    expect(error.message).not.toContain(API_HOST);
    expect(error.cause).toBeUndefined();
    expect(logged.mock.calls.flat().map(String).join(" ")).not.toContain(API_HOST);
  });

  it("logs neither the credential headers, the host, nor the fetch error text", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
    fetchMock.mockRejectedValue(new Error(`connect ECONNREFUSED ${API_HOST}:8000`));
    const ctx = ctxWith(
      { redsim_api_session: "session-secret-value", redsim_csrf: "csrf-secret-value" },
      { "x-redsim-csrf": "csrf-secret-value" },
    );
    await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }, anyBody).catch(() => undefined);

    const text = logged.mock.calls.flat().map(String).join(" ");
    expect(logged).toHaveBeenCalled();
    expect(text).not.toContain("session-secret-value");
    expect(text).not.toContain("csrf-secret-value");
    expect(text).not.toContain(API_HOST);
    expect(text).not.toContain("ECONNREFUSED");
    for (const call of logged.mock.calls.flat()) {
      if (call instanceof Error) expect(call.cause).toBeUndefined();
    }
  });
});

describe("upstreamError", () => {
  it("reads a live error and a dehydrated plain object the same way, with no instanceof", () => {
    const dehydrated = {
      data: { upstream: { status: 409, code: "score_unavailable", message: "no score" }, requestId: "r" },
    };
    expect(upstreamError(dehydrated)).toMatchObject({ code: "score_unavailable" });
    expect(upstreamError({ shape: { data: dehydrated.data } })).toMatchObject({
      code: "score_unavailable",
    });
    expect(upstreamError(new Error("plain"))).toBeUndefined();
    expect(upstreamError(undefined)).toBeUndefined();
  });
});

describe("fixture mode (KTD13)", () => {
  it("answers before the credential check, so no cookie is needed and no fetch happens", async () => {
    const ctx = ctxWith({});
    const fixtureCtx: ProcedureContext = { ...ctx, fixtures: true };
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "1";
    try {
      const result = await upstreamFetch(
        fixtureCtx,
        { method: "GET", segments: ["v1", "runs"] },
        runsListBody,
      );
      expect(result.count).toBeGreaterThan(0);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    }
  });

  it("stays off when only the public build flag is on, so a build flag cannot fabricate evidence", async () => {
    // The failing direction of the AND. ctx.fixtures is the runtime authority:
    // it is env.REDSIM_DEV_FIXTURES and the dev-environment check together, so
    // a deployment that merely carries the public flag answers from the API or
    // refuses, and never from recorded fixtures. In a tool that reports
    // measured robustness, a fixture answering a production request would be
    // fabricated evidence.
    const ctx = ctxWith({});
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "1";
    try {
      const error = await upstreamFetch({ ...ctx, fixtures: false }, {
        method: "GET",
        segments: ["v1", "runs"],
      }, anyBody).catch((e: unknown) => e);

      // Refused for want of a credential, which is the non-fixture path.
      expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    }
  });

  it('reads the build flag "0" as off, the way the validated half does', async () => {
    // The string "0" is truthy. Read for truthiness, this half was on where
    // env.js's flag() had it off, so the two halves of one flag disagreed.
    const ctx = ctxWith({});
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "0";
    try {
      const error = await upstreamFetch(
        { ...ctx, fixtures: true },
        { method: "GET", segments: ["v1", "runs"] },
        anyBody,
      ).catch((e: unknown) => e);

      expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    }
  });

  it("stays off when the runtime says yes and the build flag is absent", async () => {
    // The other half: without the literal read Next cannot inline anything, so
    // the flag has to gate the dynamic import as well as the runtime check.
    delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    const ctx = ctxWith({});
    const error = await upstreamFetch({ ...ctx, fixtures: true }, {
      method: "GET",
      segments: ["v1", "runs"],
    }, anyBody).catch((e: unknown) => e);

    expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a fixture that does not match the procedure's contract", async () => {
    // Fixtures are recorded evidence in a tool that reports measured
    // robustness, so one that has drifted from the contract is refused rather
    // than rendered as though the API had said it.
    const ctx = ctxWith({});
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "1";
    try {
      const error = await upstreamFetch(
        { ...ctx, fixtures: true },
        { method: "GET", segments: ["v1", "runs"] },
        z.looseObject({ runs: z.array(z.unknown()), count: z.string() }),
      ).catch((e: unknown) => e);

      expect(upstreamError(error)).toMatchObject({
        status: 502,
        message: "the recorded fixture does not match this route's contract",
      });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    }
  });

  it("refuses a route it has no fixture for rather than reaching upstream", async () => {
    const ctx = ctxWith({});
    const fixtureCtx: ProcedureContext = { ...ctx, fixtures: true };
    process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES = "1";
    try {
      const error = await upstreamFetch(fixtureCtx, {
        method: "GET",
        segments: ["v1", "nothing-here"],
      }, anyBody).catch((e: unknown) => e);
      expect(upstreamError(error)).toMatchObject({ status: 404, code: "not_found" });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    }
  });
});
