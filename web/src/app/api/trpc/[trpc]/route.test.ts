// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MAX_BATCH_ITEMS } from "@/lib/trpc/batch";

import * as route from "./route";

const fetchMock = vi.fn();

/** The cookie session, the only credential the handler forwards. */
const SESSION_COOKIE = "redsim_api_session=fake-session; redsim_csrf=fake-csrf";

function get(path: string): Request {
  return new Request(`http://localhost:3000${path}`, { headers: { cookie: SESSION_COOKIE } });
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function batchUrl(paths: string[], inputs: Record<string, unknown>): string {
  const input = encodeURIComponent(JSON.stringify(inputs));
  return `/api/trpc/${paths.join(",")}?batch=1&input=${input}`;
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the tRPC route handler", () => {
  it("declares itself dynamic, so a batched query GET is never route-cached", () => {
    expect(route.dynamic).toBe("force-dynamic");
  });

  it("answers runs.list with no-store and the request id of the call", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { runs: [], count: 0 }));
    const response = await route.GET(get(batchUrl(["runs.list"], {})));

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const requestId = response.headers.get("X-Redsim-Request-ID");
    expect(requestId).toMatch(/^[0-9a-f]{32}$/);
    // The same id reached the API, so its logs correlate with the browser's.
    const sent = (fetchMock.mock.calls.at(-1)?.[1] as RequestInit).headers as Record<string, string>;
    expect(sent["X-Redsim-Request-ID"]).toBe(requestId);
  });

  it("returns the typed envelope of an API refusal, keyed by upstream code", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(409, { detail: { code: "run_terminal", message: "the run is already terminal" } }),
    );
    const response = await route.GET(get(batchUrl(["runs.get"], { 0: { id: "run-1" } })));
    const body = (await response.json()) as Array<{ error: { data: Record<string, unknown> } }>;

    expect(response.status).toBe(409);
    expect(body[0]?.error.data).toMatchObject({
      upstream: { status: 409, code: "run_terminal" },
    });
  });

  it("carries one id per call in the batch, comma-joined in call order", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { runs: [], count: 0 }))
      .mockResolvedValueOnce(jsonResponse(404, { detail: "run not found" }));

    const response = await route.GET(
      get(batchUrl(["runs.list", "runs.get"], { 1: { id: "missing" } })),
    );
    const ids = (response.headers.get("X-Redsim-Request-ID") ?? "").split(",");
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);

    const body = (await response.json()) as Array<{ error?: { data: { requestId: string } } }>;
    expect(body[1]?.error?.data.requestId).toBe(ids[1]);
  });

  it("gives a schema failure its own id, its named field and the 400 block", async () => {
    const response = await route.GET(get(batchUrl(["runs.get"], { 0: { id: "" } })));
    const body = (await response.json()) as Array<{
      error: {
        data: {
          requestId: string;
          upstream?: { status: number; code: string; message: string };
          input?: { fieldErrors: Record<string, string[]> };
        };
      };
    }>;

    expect(fetchMock).not.toHaveBeenCalled();
    expect(body[0]?.error.data.requestId).toMatch(/^[0-9a-f]{32}$/);
    expect(body[0]?.error.data.input?.fieldErrors.id).toBeTruthy();
    // The block a component branches on, from the same helper the server
    // prefetch path calls, so a refused input reads the same on both paths
    // rather than arriving as a generic 500 on one of them.
    expect(body[0]?.error.data.upstream).toMatchObject({ status: 400, code: "bad_request" });
    // Not the stringified zod issue array, which is what tRPC's own message is.
    expect(body[0]?.error.data.upstream?.message).not.toContain("[");
  });

  it("refuses a batch above the cap before any upstream call, and admits one at it", async () => {
    // A fresh Response per call: a body can only be read once.
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(200, { runs: [], count: 0 })));
    const over = Array.from({ length: MAX_BATCH_ITEMS + 1 }, () => "runs.list");
    const refused = await route.GET(get(batchUrl(over, {})));

    expect(refused.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();

    const atCap = Array.from({ length: MAX_BATCH_ITEMS }, () => "runs.list");
    const admitted = await route.GET(get(batchUrl(atCap, {})));
    expect(admitted.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(MAX_BATCH_ITEMS);
  });

  it("refuses a cross-site mutation before any upstream call", async () => {
    const request = new Request("http://localhost:3000/api/trpc/runs.cancel?batch=1", {
      method: "POST",
      headers: {
        cookie: SESSION_COOKIE,
        "content-type": "application/json",
        "sec-fetch-site": "cross-site",
      },
      body: JSON.stringify({ 0: { id: "run-1" } }),
    });
    const response = await route.POST(request);
    const body = (await response.json()) as Array<{ error: { data: { upstream: { code: string; refusal_reason: string } } } }>;

    expect(fetchMock).not.toHaveBeenCalled();
    expect(response.status).toBe(403);
    expect(body[0]?.error.data.upstream).toMatchObject({
      code: "forbidden",
      refusal_reason: "cross_site_request",
    });
  });

  it("accepts the detail shape GET /v1/runs/{id} really returns", async () => {
    // redsim/api/v1/runs.py serializes the detail route without created_by and
    // with completed_at and stage_table, while only the list route carries
    // created_by. Validated against the list shape, every successful detail
    // call became a 502 on the parse rather than reaching the page.
    const detail = {
      id: "run-1",
      project_id: "default",
      status: "succeeded",
      scanner: "ml.campaign",
      mode: "campaign",
      created_at: "2026-09-09T09:30:00Z",
      completed_at: "2026-09-09T09:41:00Z",
      stage_table: { stages: { load_target: { status: "succeeded" } } },
    };
    fetchMock.mockResolvedValue(jsonResponse(200, detail));
    const response = await route.GET(get(batchUrl(["runs.get"], { 0: { id: "run-1" } })));
    const body = (await response.json()) as Array<{ result: { data: unknown } }>;

    expect(response.status).toBe(200);
    expect(body[0]?.result.data).toEqual(detail);
  });

  it("still refuses a detail body missing a field the route always sends", async () => {
    // The looseObject keeps unknown keys, so the schema is only worth having
    // if a genuinely wrong shape is still a 502.
    fetchMock.mockResolvedValue(jsonResponse(200, { id: "run-1", project_id: "default" }));
    const response = await route.GET(get(batchUrl(["runs.get"], { 0: { id: "run-1" } })));
    const body = (await response.json()) as Array<{ error: { data: { upstream: { code: string } } } }>;

    expect(response.status).toBe(502);
    expect(body[0]?.error.data.upstream).toMatchObject({ code: "upstream_error" });
  });

  it("never forwards an upstream Set-Cookie to the browser", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ runs: [], count: 0 }), {
        status: 200,
        headers: { "content-type": "application/json", "set-cookie": "evil=1" },
      }),
    );
    const response = await route.GET(get(batchUrl(["runs.list"], {})));
    expect(response.headers.get("set-cookie")).toBeNull();
  });
});
