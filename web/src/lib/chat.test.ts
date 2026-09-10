import { afterEach, describe, expect, it, vi } from "vitest";

import findingFixture from "@/__fixtures__/finding.json";
import type { Finding } from "@/lib/api";

import {
  ChatError,
  CHAT_STORAGE_PREFIX,
  describeChatError,
  examplePrompts,
  loadConversation,
  readNdjson,
  saveConversation,
  streamFindingChat,
  type ChatStreamEvent,
} from "./chat";

const finding = findingFixture as unknown as Finding;

async function collect(iterable: AsyncIterable<ChatStreamEvent>) {
  const out: ChatStreamEvent[] = [];
  for await (const event of iterable) out.push(event);
  return out;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.sessionStorage.clear();
});

describe("readNdjson", () => {
  it("yields one event per line across chunk boundaries and reads a trailing line", async () => {
    const text = '{"type":"meta","model":"m","request_id":"r"}\n{"type":"delta","text":"a"}\n{"type":"done"}';
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(text.slice(0, 20)));
        controller.enqueue(encoder.encode(text.slice(20)));
        controller.close();
      },
    });
    expect(await collect(readNdjson(body))).toEqual([
      { type: "meta", model: "m", request_id: "r" },
      { type: "delta", text: "a" },
      { type: "done" },
    ]);
  });

  it("turns an unreadable line into an error event rather than throwing", async () => {
    const body = new Response("garbage\n").body!;
    expect(await collect(readNdjson(body))).toEqual([
      { type: "error", code: "bad_event", message: "the chat stream sent an unreadable event" },
    ]);
  });
});

describe("streamFindingChat", () => {
  it("posts the finding id and history same-origin and raises the route's refusal", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({ code: "llm_not_configured", message: "no gateway" }, { status: 503 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const history = [{ role: "user" as const, content: "hi" }];
    await expect(collect(streamFindingChat("f1", history))).rejects.toMatchObject({
      status: 503,
      code: "llm_not_configured",
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/chat/finding");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
    expect(JSON.parse(String(init.body))).toEqual({ finding_id: "f1", messages: history });
  });
});

describe("describeChatError", () => {
  it("names the configuration gap and the session end", () => {
    expect(describeChatError(new ChatError(503, "llm_not_configured", "x"))).toMatch(/no Pythia gateway settings/);
    expect(describeChatError(new ChatError(401, "unauthenticated", "x"))).toMatch(/Sign in again/);
    expect(describeChatError(new ChatError(502, "gateway_error", "x"))).toBe("The gateway refused the request (502).");
    expect(describeChatError(new Error("boom"))).toBe("The chat request failed. Try again.");
  });
});

describe("examplePrompts", () => {
  it("uses the finding's attack, reference eps and severity", () => {
    const prompts = examplePrompts(finding);
    expect(prompts).toHaveLength(6);
    expect(prompts.join("\n")).toContain("ε = 0.03");
    expect(prompts.join("\n")).toContain(`${finding.severity} severity`);
    expect(prompts.join("\n")).not.toMatch(/deploy|ready|certif/i);
  });

  it("falls back to generic terms on a finding without ML detail", () => {
    const bare = { ...finding, schema_blob: {} } as Finding;
    expect(examplePrompts(bare)[2]).toBe("How does the noise control compare with the attack?");
  });
});

describe("conversation storage", () => {
  it("round-trips per finding and drops malformed entries", () => {
    const turns = [
      { id: "1", role: "user" as const, content: "q" },
      { id: "2", role: "assistant" as const, content: "a" },
    ];
    saveConversation("f1", turns);
    expect(loadConversation("f1")).toEqual(turns);
    expect(loadConversation("f2")).toEqual([]);
    window.sessionStorage.setItem(`${CHAT_STORAGE_PREFIX}f3`, JSON.stringify([{ nope: true }, turns[0]]));
    expect(loadConversation("f3")).toEqual([turns[0]]);
    saveConversation("f1", []);
    expect(window.sessionStorage.getItem(`${CHAT_STORAGE_PREFIX}f1`)).toBeNull();
  });
});
