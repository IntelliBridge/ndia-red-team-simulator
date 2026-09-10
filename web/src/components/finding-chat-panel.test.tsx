import { createElement } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import findingFixture from "@/__fixtures__/finding.json";
import type { Finding } from "@/lib/api";
import type { ChatStreamEvent } from "@/lib/chat";

const fetchChatStatus = vi.hoisted(() => vi.fn());
const streamFindingChat = vi.hoisted(() => vi.fn());
vi.mock("@/lib/chat", async () => ({
  ...(await vi.importActual<typeof import("@/lib/chat")>("@/lib/chat")),
  fetchChatStatus,
  streamFindingChat,
}));

import { FindingChatPanel } from "./finding-chat-panel";

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
    expect(screen.getAllByRole("listitem", {})).toHaveLength(6);
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

  it("closes through the Close button", async () => {
    const { onOpenChange } = mount();
    fireEvent.click(await screen.findByRole("button", { name: "Close chat" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
