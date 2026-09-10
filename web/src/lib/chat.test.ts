import { afterEach, describe, expect, it, vi } from "vitest";

import findingFixture from "@/__fixtures__/finding.json";
import type { Finding } from "@/lib/api";

import campaignFixture from "@/__fixtures__/campaign.json";
import type { Campaign } from "@/lib/api";

import {
  buildProposalRequest,
  ChatError,
  CHAT_STORAGE_PREFIX,
  describeChatError,
  examplePrompts,
  loadConversation,
  parseProposal,
  PROPOSAL_FENCE,
  readNdjson,
  saveConversation,
  streamFindingChat,
  validateProposal,
  type ChatStreamEvent,
} from "./chat";

const campaign = campaignFixture as unknown as Campaign;

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
    expect(prompts).toHaveLength(7);
    expect(prompts[0]).toBe("What should I run next to narrow this finding? Propose a campaign.");
    expect(prompts.join("\n")).toContain("ε = 0.03");
    expect(prompts.join("\n")).toContain(`${finding.severity} severity`);
    expect(prompts.join("\n")).not.toMatch(/deploy|ready|certif/i);
  });

  it("falls back to generic terms on a finding without ML detail", () => {
    const bare = { ...finding, schema_blob: {} } as Finding;
    expect(examplePrompts(bare)[3]).toBe("How does the noise control compare with the attack?");
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

const PROPOSAL = {
  attack_ids: ["pgd", "fgsm", "pgd"],
  norm: "linf",
  eps_grid: [0.03, 0.01, 0.1],
  reference_eps: 0.03,
  n_samples: 50,
  rationale: "m1 measured 24/50 correct at eps 0.03 under fgsm.",
};

function block(doc: unknown): string {
  return "```" + PROPOSAL_FENCE + "\n" + JSON.stringify(doc, null, 2) + "\n```";
}

describe("parseProposal", () => {
  it("returns the prose untouched when there is no block", () => {
    expect(parseProposal("Measured at m1.")).toEqual({ text: "Measured at m1.", proposal: null, invalid: null, pending: false });
  });

  it("splits a closed block from the prose, sorts the grid and drops a repeated attack id", () => {
    const parsed = parseProposal(`Run PGD next.\n\n${block(PROPOSAL)}`);
    expect(parsed.text).toBe("Run PGD next.");
    expect(parsed.pending).toBe(false);
    expect(parsed.invalid).toBeNull();
    expect(parsed.proposal).toEqual({
      attack_ids: ["pgd", "fgsm"],
      norm: "linf",
      eps_grid: [0.01, 0.03, 0.1],
      reference_eps: 0.03,
      n_samples: 50,
      rationale: "m1 measured 24/50 correct at eps 0.03 under fgsm.",
    });
  });

  it("keeps a half-written block out of the prose while the stream is inside it", () => {
    const parsed = parseProposal("Run PGD next.\n\n```" + PROPOSAL_FENCE + '\n{"attack_ids": ["pgd"');
    expect(parsed).toEqual({ text: "Run PGD next.", proposal: null, invalid: null, pending: true });
  });

  it("keeps prose written after the block", () => {
    const parsed = parseProposal(`Before.\n${block(PROPOSAL)}\nAfter.`);
    expect(parsed.text).toBe("Before.\n\nAfter.");
    expect(parsed.proposal?.attack_ids).toEqual(["pgd", "fgsm"]);
  });

  it("names why a block cannot be run and still shows the prose", () => {
    expect(parseProposal("Text.\n```" + PROPOSAL_FENCE + "\nnot json\n```").invalid).toMatch(/not valid JSON/);
    expect(parseProposal(`T.\n${block({ ...PROPOSAL, reference_eps: 0.5 })}`).invalid).toMatch(/reference_eps/);
    expect(parseProposal(`T.\n${block({ ...PROPOSAL, attack_ids: [] })}`).invalid).toMatch(/attack_ids/);
    expect(parseProposal(`T.\n${block({ ...PROPOSAL, norm: "l7" })}`).invalid).toMatch(/norm/);
    expect(parseProposal(`T.\n${block({ ...PROPOSAL, n_samples: 5000 })}`).invalid).toMatch(/n_samples/);
    expect(parseProposal(`T.\n${block({ ...PROPOSAL, eps_grid: [0.03, 0.03] })}`).invalid).toMatch(/repeat/);
    // The admission refuses more than three grid members by default, so the panel does too.
    expect(parseProposal(`T.\n${block({ ...PROPOSAL, eps_grid: [0.001, 0.002, 0.004, 0.03] })}`).invalid).toMatch(/1 to 3/);
    expect(validateProposal([]).invalid).toMatch(/JSON object/);
  });
});

describe("buildProposalRequest", () => {
  it("keeps the recorded settings, replaces the attack set and grid, and carries no server-owned key", () => {
    const parsed = parseProposal(block(PROPOSAL));
    const request = buildProposalRequest(campaign.config, parsed.proposal!);
    expect(request).toMatchObject({
      attack_ids: ["pgd", "fgsm"],
      norm: "linf",
      eps_grid: [0.01, 0.03, 0.1],
      reference_eps: 0.03,
      n_samples: 50,
      dataset_id: "fixture-public-image",
      dataset_revision: "fixture-revision",
      seed: 7,
      include_control: true,
      finding_asr_threshold: 0.2,
      explain_k: 8,
    });
    for (const key of ["target_id", "modality", "dataset_split", "scoring", "target_snapshot", "attacks", "attack_params"]) {
      expect(request).not.toHaveProperty(key);
    }
  });
});
