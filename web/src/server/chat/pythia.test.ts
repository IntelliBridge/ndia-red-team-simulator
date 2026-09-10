// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };

async function load(extra: Record<string, string> = {}) {
  vi.resetModules();
  process.env = {
    ...savedEnv,
    REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
    REDSIM_WEB_ORIGIN: "http://localhost:3000",
    ...extra,
  } as NodeJS.ProcessEnv;
  return import("./pythia");
}

async function collect(iterable: AsyncIterable<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const chunk of iterable) out.push(chunk);
  return out;
}

function sse(events: unknown[], done = true): string {
  const lines = events.map((event) => `data: ${typeof event === "string" ? event : JSON.stringify(event)}\n\n`);
  if (done) lines.push("data: [DONE]\n\n");
  return lines.join("");
}

const chunk = (text: string) => ({ choices: [{ delta: { content: text } }] });

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  process.env = { ...savedEnv };
  vi.unstubAllGlobals();
});

describe("gatewaySettings", () => {
  it("is null without a base URL and a key", async () => {
    const { gatewaySettings } = await load();
    expect(gatewaySettings()).toBeNull();
    const withUrl = await load({ PYTHIA_BASE_URL: "https://gateway.test" });
    expect(withUrl.gatewaySettings()).toBeNull();
  });

  it("reads the four names and the chat model, trimming a trailing slash", async () => {
    const { gatewaySettings } = await load({
      PYTHIA_BASE_URL: "https://gateway.test/",
      PYTHIA_API_KEY: "pk_test_not_a_real_key",
      PYTHIA_PERSONA: "analyst",
      PYTHIA_TIMEOUT_S: "45",
    });
    expect(gatewaySettings()).toEqual({
      baseUrl: "https://gateway.test",
      apiKey: "pk_test_not_a_real_key",
      persona: "analyst",
      timeoutMs: 45_000,
      model: "anthropic/claude-opus-5",
    });
  });
});

describe("sseDeltas", () => {
  it("yields the content deltas and stops at [DONE]", async () => {
    const { sseDeltas } = await load();
    const body = new Response(sse([chunk("Hel"), chunk("lo"), { choices: [{ delta: {} }] }, chunk("!")])).body!;
    expect(await collect(sseDeltas(body))).toEqual(["Hel", "lo", "!"]);
  });

  it("survives a chunk boundary inside an event and skips a malformed line", async () => {
    const { sseDeltas } = await load();
    const text = sse([chunk("ab"), "not json", chunk("cd")]);
    const half = Math.floor(text.length / 2);
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(text.slice(0, half)));
        controller.enqueue(encoder.encode(text.slice(half)));
        controller.close();
      },
    });
    expect(await collect(sseDeltas(body))).toEqual(["ab", "cd"]);
  });

  it("raises gateway_stream_error on an error event", async () => {
    const { sseDeltas, GatewayStreamError } = await load();
    const body = new Response(sse([chunk("a"), { error: { message: "quota" } }])).body!;
    await expect(collect(sseDeltas(body))).rejects.toBeInstanceOf(GatewayStreamError);
  });
});

describe("openChatStream", () => {
  const settings = {
    baseUrl: "https://gateway.test",
    apiKey: "pk_test_not_a_real_key",
    persona: "analyst",
    timeoutMs: 5_000,
    model: "anthropic/claude-opus-5",
  };
  const messages = [{ role: "system" as const, content: "rules" }, { role: "user" as const, content: "hi" }];

  it("posts a streamed completion with the bearer and persona, and reads the events", async () => {
    const { openChatStream } = await load();
    const fetchMock = vi.fn(async () =>
      new Response(sse([chunk("yes")]), { headers: { "content-type": "text/event-stream" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const opened = await openChatStream(settings, messages, new AbortController().signal);
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(await collect(opened.deltas)).toEqual(["yes"]);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://gateway.test/v1/chat/completions");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer pk_test_not_a_real_key");
    expect(headers["X-Pythia-Persona"]).toBe("analyst");
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body).toMatchObject({ model: "anthropic/claude-opus-5", stream: true, messages });
  });

  it("reads a plain JSON completion as one delta", async () => {
    const { openChatStream } = await load();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ choices: [{ message: { content: "whole answer" } }] })),
    );
    const opened = await openChatStream(settings, messages, new AbortController().signal);
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(await collect(opened.deltas)).toEqual(["whole answer"]);
  });

  it("reports a non-2xx by status and a connection failure as unreachable", async () => {
    const { openChatStream } = await load();
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 429 })));
    expect(await openChatStream(settings, messages, new AbortController().signal)).toEqual({
      ok: false,
      code: "gateway_error",
      status: 429,
    });
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("fetch failed"))));
    expect(await openChatStream(settings, messages, new AbortController().signal)).toEqual({
      ok: false,
      code: "gateway_unreachable",
      status: 503,
    });
  });
});
