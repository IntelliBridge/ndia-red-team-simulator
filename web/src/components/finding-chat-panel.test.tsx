import { createElement } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import findingFixture from "@/__fixtures__/finding.json";
import type { Finding } from "@/lib/api";
import type { ChatStreamEvent } from "@/lib/chat";

import campaignFixture from "@/__fixtures__/campaign.json";

const fetchChatStatus = vi.hoisted(() => vi.fn());
const streamFindingChat = vi.hoisted(() => vi.fn());
vi.mock("@/lib/chat", async () => ({
  ...(await vi.importActual<typeof import("@/lib/chat")>("@/lib/chat")),
  fetchChatStatus,
  streamFindingChat,
}));

const startCampaign = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  startCampaign,
}));

const rolesMock = vi.hoisted(() => ({ roles: { default: "scanner" } as Record<string, string> }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: rolesMock.roles, projects: [], isLoading: false, error: undefined }),
}));

const campaignMock = vi.hoisted(() => ({ data: undefined as unknown, error: undefined as unknown }));
vi.mock("@/hooks/useCampaign", () => ({
  useCampaign: () => ({ data: campaignMock.data, error: campaignMock.error }),
}));

import { FindingChatPanel } from "./finding-chat-panel";

const PROPOSAL_TEXT =
  "Run a black-box attack next.\n\n```redsim-proposal\n" +
  JSON.stringify({ attack_ids: ["hopskipjump"], norm: "linf", eps_grid: [0.01, 0.03, 0.1], reference_eps: 0.03, n_samples: 50, rationale: "m1 measured 24/50 correct at eps 0.03." }) +
  "\n```";

const finding = findingFixture as unknown as Finding;

async function* answer(...events: ChatStreamEvent[]) {
  for (const event of events) yield event;
}

function mount(open = true) {
  const onOpenChange = vi.fn();
  render(createElement(FindingChatPanel, { finding, open, onOpenChange }));
  return { onOpenChange };
}

beforeEach(() => {
  vi.clearAllMocks();
  window.sessionStorage.clear();
  fetchChatStatus.mockResolvedValue({ configured: true, model: "anthropic/claude-opus-5" });
  rolesMock.roles = { default: "scanner" };
  campaignMock.data = campaignFixture;
  campaignMock.error = undefined;
});

afterEach(() => cleanup());

describe("FindingChatPanel", () => {
  it("renders nothing while closed and never asks the server", () => {
    mount(false);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(fetchChatStatus).not.toHaveBeenCalled();
  });

  it("opens as a dialog with the example prompts, the finding id and the standing caveat", async () => {
    mount();
    const dialog = await screen.findByRole("dialog", { name: "Chat with this finding" });
    expect(dialog).toBeTruthy();
    expect(screen.getByText(/fixture-finding/)).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/anthropic\/claude-opus-5 via Pythia/)).toBeTruthy());
    expect(screen.getAllByRole("listitem", {})).toHaveLength(7);
    expect(screen.getByText(/Not a measurement/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Send" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Close chat" })).toBeTruthy();
  });

  it("sends an example prompt and streams the answer into the transcript", async () => {
    streamFindingChat.mockReturnValue(
      answer(
        { type: "meta", model: "anthropic/claude-opus-5", request_id: "r1" },
        { type: "delta", text: "Measured " },
        { type: "delta", text: "at m1, n=50." },
        { type: "done" },
      ),
    );
    mount();
    await screen.findByRole("dialog");
    fireEvent.click(await screen.findByRole("button", { name: /What limitations should I cite/ }));
    await waitFor(() => expect(screen.getByText("Measured at m1, n=50.")).toBeTruthy());
    const [id, history] = streamFindingChat.mock.calls[0] as [string, Array<{ role: string; content: string }>];
    expect(id).toBe("fixture-finding");
    expect(history).toEqual([{ role: "user", content: "What limitations should I cite before I act on this finding?" }]);
    expect(screen.getByText("What limitations should I cite before I act on this finding?")).toBeTruthy();
    // The transcript survives in sessionStorage for the next open.
    expect(window.sessionStorage.getItem("redsim.chat.fixture-finding")).toContain("n=50");
  });

  it("sends a typed question on Enter and shows a stream error under the answer", async () => {
    streamFindingChat.mockReturnValue(
      answer(
        { type: "delta", text: "partial" },
        { type: "error", code: "gateway_stream_error", message: "the gateway stream ended with an error" },
      ),
    );
    mount();
    const input = await screen.findByLabelText("Your question");
    fireEvent.change(input, { target: { value: "Why medium?" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain("the gateway stream ended with an error"),
    );
    expect(screen.getByText("partial")).toBeTruthy();
    expect((input as HTMLTextAreaElement).value).toBe("");
  });

  it("says so and disables the input when the web server has no gateway settings", async () => {
    fetchChatStatus.mockResolvedValue({ configured: false, model: null });
    mount();
    await screen.findByRole("dialog");
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/no Pythia gateway settings/));
    expect((screen.getByLabelText("Your question") as HTMLTextAreaElement).disabled).toBe(true);
    expect(screen.queryByRole("button", { name: /What limitations/ })).toBeNull();
  });

  it("renders a proposal as a card, runs it through the API on approval and links the admitted run", async () => {
    streamFindingChat.mockReturnValue(answer({ type: "delta", text: PROPOSAL_TEXT }, { type: "done" }));
    startCampaign.mockResolvedValue({ run_id: "run-next-1", job_ids: ["job-1"], status_url: "/v1/runs/run-next-1" });
    mount();
    await screen.findByRole("dialog");
    fireEvent.click(await screen.findByRole("button", { name: /Propose a campaign/ }));
    const card = await screen.findByRole("region", { name: "Proposed campaign" });
    expect(card.textContent).toContain("candidate, not run");
    expect(card.textContent).toContain("hopskipjump");
    expect(card.textContent).toContain("0.01, 0.03, 0.1");
    expect(card.textContent).toContain("m1 measured 24/50 correct");
    // The block never reaches the prose.
    expect(screen.getByText("Run a black-box attack next.")).toBeTruthy();
    expect(screen.queryByText(/redsim-proposal/)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Run this campaign" }));
    await waitFor(() => expect(startCampaign).toHaveBeenCalledTimes(1));
    const [targetId, request] = startCampaign.mock.calls[0] as [string, Record<string, unknown>];
    expect(targetId).toBe("fixture-model");
    expect(request).toMatchObject({ attack_ids: ["hopskipjump"], eps_grid: [0.01, 0.03, 0.1], reference_eps: 0.03, n_samples: 50, dataset_id: "fixture-public-image" });
    expect(request).not.toHaveProperty("scoring");
    const link = await screen.findByRole("link", { name: /run-next-1/ });
    expect(link.getAttribute("href")).toBe("/runs/run-next-1");
    expect(screen.queryByRole("button", { name: "Run this campaign" })).toBeNull();
    // The admitted run survives with the transcript.
    expect(window.sessionStorage.getItem("redsim.chat.fixture-finding")).toContain("run-next-1");
  });

  it("shows the API refusal by code and hides the Run button from a viewer", async () => {
    streamFindingChat.mockReturnValue(answer({ type: "delta", text: PROPOSAL_TEXT }, { type: "done" }));
    const { ApiError } = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
    startCampaign.mockRejectedValue(
      new ApiError(422, JSON.stringify({ detail: { code: "attack_requires_gradients", message: "no gradients" } })),
    );
    mount();
    await screen.findByRole("dialog");
    fireEvent.click(await screen.findByRole("button", { name: /Propose a campaign/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Run this campaign" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("attack_requires_gradients: no gradients"));

    cleanup();
    rolesMock.roles = { default: "viewer" };
    mount();
    await screen.findByRole("region", { name: "Proposed campaign" });
    expect(screen.queryByRole("button", { name: "Run this campaign" })).toBeNull();
  });

  it("says why an unusable proposal cannot run and keeps the prose", async () => {
    streamFindingChat.mockReturnValue(
      answer({ type: "delta", text: "Text.\n```redsim-proposal\n{\"attack_ids\": []}\n```" }, { type: "done" }),
    );
    mount();
    await screen.findByRole("dialog");
    fireEvent.click(await screen.findByRole("button", { name: /Propose a campaign/ }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/cannot run: attack_ids/));
    expect(screen.getByText("Text.")).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Proposed campaign" })).toBeNull();
  });

  it("closes through the Close button", async () => {
    const { onOpenChange } = mount();
    fireEvent.click(await screen.findByRole("button", { name: "Close chat" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
