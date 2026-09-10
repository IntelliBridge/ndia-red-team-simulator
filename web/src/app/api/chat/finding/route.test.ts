// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import campaignFixture from "@/__fixtures__/campaign.json";
import findingFixture from "@/__fixtures__/finding.json";

const savedEnv = { ...process.env };

const API = "http://localhost:8000";
const GATEWAY = "https://gateway.test";
const KEY = "pk_test_not_a_real_key";

type Call = { url: string; method: string; headers: Record<string, string>; body: string | null };

/** A fetch stub that plays FastAPI and the gateway by URL and records every call. */
function fakeNetwork(options: { gateway?: () => Response; finding?: Response; campaign?: Response } = {}) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: { ...((init?.headers as Record<string, string> | undefined) ?? {}) },
      body: typeof init?.body === "string" ? init.body : null,
    });
    if (url.startsWith(`${API}/v1/findings/`)) return options.finding ?? Response.json(findingFixture);
    if (url.endsWith("/campaign")) return options.campaign ?? Response.json(campaignFixture);
    if (url === `${GATEWAY}/v1/chat/completions`) {
      return options.gateway
        ? options.gateway()
        : new Response(
            'data: {"choices":[{"delta":{"content":"Recorded "}}]}\n\ndata: {"choices":[{"delta":{"content":"answer."}}]}\n\ndata: [DONE]\n\n',
            { headers: { "content-type": "text/event-stream" } },
          );
    }
    return new Response("unexpected", { status: 500 });
  });
  return { calls, fetchMock };
}

async function load(extra: Record<string, string> = {}) {
  vi.resetModules();
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
    REDSIM_API_URL: API,
    PYTHIA_BASE_URL: GATEWAY,
    PYTHIA_API_KEY: KEY,
    ...extra,
  } as NodeJS.ProcessEnv;
  return import("./route");
}

const ROUTE = "http://localhost:3000/api/chat/finding";
const COOKIE = "redsim_api_session=s1; redsim_csrf=c1";

function post(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(ROUTE, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "sec-fetch-site": "same-origin",
      cookie: COOKIE,
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const ask = { finding_id: "fixture-finding", messages: [{ role: "user", content: "Explain this finding." }] };

async function events(response: Response): Promise<Array<Record<string, unknown>>> {
  const text = await response.text();
  return text
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  process.env = { ...savedEnv };
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("GET /api/chat/finding", () => {
  it("refuses without a session cookie", async () => {
    const { GET } = await load();
    const res = await GET(new Request(ROUTE));
    expect(res.status).toBe(401);
    expect(res.headers.get("X-Redsim-Request-ID")).toMatch(/^[0-9a-f]{32}$/);
  });

  it("reports the configuration and the model, never the key", async () => {
    const { GET } = await load();
    const res = await GET(new Request(ROUTE, { headers: { cookie: COOKIE } }));
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ configured: true, model: "anthropic/claude-opus-5" });
    expect(text).not.toContain(KEY);
  });

  it("says unconfigured without gateway settings", async () => {
    const { GET } = await load({ PYTHIA_BASE_URL: "", PYTHIA_API_KEY: "" });
    const res = await GET(new Request(ROUTE, { headers: { cookie: COOKIE } }));
    await expect(res.json()).resolves.toEqual({ configured: false, model: null });
  });
});

describe("POST /api/chat/finding", () => {
  it("refuses a cross-site sender before reading anything", async () => {
    const { calls, fetchMock } = fakeNetwork();
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask, { "sec-fetch-site": "cross-site" }));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ code: "forbidden" });
    expect(calls).toHaveLength(0);
  });

  it("refuses without a session cookie", async () => {
    const { calls, fetchMock } = fakeNetwork();
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask, { cookie: "" }));
    expect(res.status).toBe(401);
    expect(calls).toHaveLength(0);
  });

  it("refuses a malformed body and a history that does not end with the user", async () => {
    const { fetchMock } = fakeNetwork();
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    expect((await POST(post("not json"))).status).toBe(400);
    const res = await POST(
      post({ finding_id: "f", messages: [{ role: "user", content: "a" }, { role: "assistant", content: "b" }] }),
    );
    expect(res.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("answers 503 llm_not_configured without gateway settings, before any API call", async () => {
    const { fetchMock } = fakeNetwork();
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load({ PYTHIA_BASE_URL: "", PYTHIA_API_KEY: "" });
    const res = await POST(post(ask));
    expect(res.status).toBe(503);
    await expect(res.json()).resolves.toMatchObject({ code: "llm_not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards the API's refusal of the finding with its status and code", async () => {
    const { fetchMock } = fakeNetwork({
      finding: Response.json({ detail: { code: "not_found", message: "no such finding" } }, { status: 404 }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask));
    expect(res.status).toBe(404);
    await expect(res.json()).resolves.toEqual({ code: "not_found", message: "no such finding" });
  });

  it("streams the answer: the API sees the cookie, the gateway sees the key and the record, never the cookie", async () => {
    const { calls, fetchMock } = fakeNetwork();
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask));
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/x-ndjson");
    const requestId = res.headers.get("X-Redsim-Request-ID");
    const got = await events(res);
    expect(got).toEqual([
      { type: "meta", model: "anthropic/claude-opus-5", request_id: requestId },
      { type: "delta", text: "Recorded " },
      { type: "delta", text: "answer." },
      { type: "done" },
    ]);

    expect(calls.map((c) => c.url)).toEqual([
      `${API}/v1/findings/fixture-finding`,
      `${API}/v1/runs/fixture-run-001/campaign`,
      `${GATEWAY}/v1/chat/completions`,
    ]);
    for (const apiCall of calls.slice(0, 2)) {
      expect(apiCall.headers.Cookie).toBe(COOKIE);
      expect(apiCall.headers.Authorization).toBeUndefined();
    }
    const gateway = calls[2]!;
    expect(gateway.headers.Authorization).toBe(`Bearer ${KEY}`);
    expect(gateway.headers.Cookie).toBeUndefined();
    const body = JSON.parse(gateway.body ?? "{}") as { messages: Array<{ role: string; content: string }>; stream: boolean };
    expect(body.stream).toBe(true);
    expect(body.messages[0]?.role).toBe("system");
    expect(body.messages[0]?.content).toContain('"mri":0.58');
    expect(body.messages[0]?.content).toContain('"id":"m1"');
    expect(body.messages[body.messages.length - 1]).toEqual({ role: "user", content: "Explain this finding." });
    expect(gateway.body).not.toContain(COOKIE);
  });

  it("chats on the finding alone when the campaign record is refused", async () => {
    const { calls, fetchMock } = fakeNetwork({
      campaign: Response.json({ detail: { code: "llm_target_required", message: "probe run" } }, { status: 409 }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask));
    expect(res.status).toBe(200);
    const got = await events(res);
    expect(got.at(-1)).toEqual({ type: "done" });
    const body = JSON.parse(calls[2]!.body ?? "{}") as { messages: Array<{ content: string }> };
    expect(body.messages[0]?.content).toContain('"campaign_unavailable":"llm_target_required"');
  });

  it("answers the gateway's refusal as JSON before any stream starts", async () => {
    const { fetchMock } = fakeNetwork({ gateway: () => new Response("quota", { status: 429 }) });
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask));
    expect(res.status).toBe(502);
    await expect(res.json()).resolves.toMatchObject({ code: "gateway_error", message: "the gateway answered 429" });
  });

  it("ends the stream with an error event when the gateway fails mid-answer", async () => {
    const { fetchMock } = fakeNetwork({
      gateway: () =>
        new Response('data: {"choices":[{"delta":{"content":"part"}}]}\n\ndata: {"error":{"message":"boom"}}\n\n', {
          headers: { "content-type": "text/event-stream" },
        }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const { POST } = await load();
    const res = await POST(post(ask));
    const got = await events(res);
    expect(got[1]).toEqual({ type: "delta", text: "part" });
    expect(got.at(-1)).toMatchObject({ type: "error", code: "gateway_stream_error" });
  });
});
