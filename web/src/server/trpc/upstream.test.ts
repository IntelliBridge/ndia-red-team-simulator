// @vitest-environment node
//
// The error contract of KTD8 and the fetch hygiene of KTD2, measured against
// the status table in redsim/api/errors.py at 29db42c.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { upstreamError } from "@/lib/api";

import { beginCall, createContext, requestPartsFromRequest, type ProcedureContext } from "./context";
import { trpcCodeForStatus, upstreamFetch } from "./upstream";

const API_HOST = "api.internal.invalid";

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
    expect(trpcCodeForStatus(411)).toBe("PAYLOAD_TOO_LARGE");
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
    await upstreamFetch(ctx, { method: "POST", segments: ["v1", "runs", "r1", "cancel"] });

    expect(headerOf("Cookie")).toBe("redsim_api_session=s; redsim_csrf=c");
    expect(headerOf("X-Redsim-CSRF")).toBe("c");
    expect(headerOf("Authorization")).toBeUndefined();
    expect(headerOf("x-something-else")).toBeUndefined();
    expect(lastInit().cache).toBe("no-store");
  });

  it("sends a bearer and no cookie on the dev-token path", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}));
    const ctx = ctxWith({ redsim_dev_token: "dev:a@b.test" }, { "x-redsim-csrf": "c" });
    await upstreamFetch(ctx, { method: "POST", segments: ["v1", "runs"] });

    expect(headerOf("Authorization")).toBe("Bearer dev:a@b.test");
    expect(headerOf("Cookie")).toBeUndefined();
    expect(headerOf("X-Redsim-CSRF")).toBeUndefined();
  });

  it("refuses before any upstream call when no credential is present", async () => {
    const ctx = ctxWith({});
    const error = await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }).catch(
      (e: unknown) => e,
    );
    expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("issues zero upstream requests for a batch of twenty anonymous calls", async () => {
    const ctx = ctxWith({});
    await Promise.all(
      Array.from({ length: 20 }, () =>
        upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }).catch(() => undefined),
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
    const result = await upstreamFetch<Record<string, unknown>>(ctx, {
      method: "GET",
      segments: ["v1", "runs"],
    });
    expect(result).toEqual({ runs: [], count: 0 });
    expect(JSON.stringify(result)).not.toContain("evil");
  });
});

describe("path and query encoding", () => {
  it("encodes each segment once and never into a second path segment", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, {}));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs", "r%201"] });

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
    });
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
    }).catch((e: unknown) => e)) as { code: string; data: Record<string, unknown> };

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

  it("synthesizes a code from the status for a plain string detail", async () => {
    fetchMock.mockResolvedValue(jsonResponse(404, { detail: "run not found" }));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = (await upstreamFetch(ctx, {
      method: "GET",
      segments: ["v1", "runs", "nope"],
    }).catch((e: unknown) => e)) as { code: string };

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
      const error = await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }).catch(
        (e: unknown) => e,
      );
      expect(upstreamError(error)).toMatchObject({ status, code });
    }
  });

  it("synthesizes unauthenticated for a 401, a web-side name with no row in the API table", async () => {
    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "not authenticated" }));
    const ctx = ctxWith({ redsim_api_session: "s", redsim_csrf: "c" });
    const error = await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }).catch(
      (e: unknown) => e,
    );
    expect(upstreamError(error)).toMatchObject({ status: 401, code: "unauthenticated" });
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
    }).catch((e: unknown) => e)) as Error & { code: string; cause?: unknown };

    expect(error.code).toBe("SERVICE_UNAVAILABLE");
    expect(upstreamError(error)).toMatchObject({ status: 503, code: "service_unavailable" });
    expect(error.message).not.toContain(API_HOST);
    expect(error.message).not.toContain("ECONNREFUSED");
    expect(error.cause).toBeUndefined();
  });

  it("logs neither the credential headers, the host, nor the fetch error text", async () => {
    const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
    fetchMock.mockRejectedValue(new Error(`connect ECONNREFUSED ${API_HOST}:8000`));
    const ctx = ctxWith(
      { redsim_api_session: "session-secret-value", redsim_csrf: "csrf-secret-value" },
      { "x-redsim-csrf": "csrf-secret-value" },
    );
    await upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs"] }).catch(() => undefined);

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
      const result = await upstreamFetch<{ runs: unknown[]; count: number }>(fixtureCtx, {
        method: "GET",
        segments: ["v1", "runs"],
      });
      expect(result.count).toBeGreaterThan(0);
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
      }).catch((e: unknown) => e);
      expect(upstreamError(error)).toMatchObject({ status: 404, code: "not_found" });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      delete process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES;
    }
  });
});
