import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true as boolean));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

// Stub the design-system Tooltip primitives to passthrough children so the
// test stays isolated from Radix portal/provider plumbing. The TooltipContent
// (full hash on hover) is rendered inline so we can assert on it.
vi.mock("@redsim/design-system", () => ({
  TooltipProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Tooltip: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  TooltipTrigger: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  TooltipContent: ({ children }: { children: React.ReactNode }) =>
    React.createElement("span", { "data-testid": "tooltip-content" }, children),
}));

import AuditPage from "./page";

afterEach(cleanup);
beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
});

describe("AuditPage", () => {
  it("renders the 'Verifying chains…' paragraph in the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(React.createElement(AuditPage));
    const el = screen.getByText("Verifying chains…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders a red error paragraph containing the error message on failure", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("403 Forbidden"),
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    const el = screen.getByText(/Failed to verify/);
    expect(el.textContent).toContain("403 Forbidden");
    expect(el.className).toContain("border-destructive");
  });

  it("renders 'Redirecting to sign in…' when not authed", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(React.createElement(AuditPage));
    const el = screen.getByText("Redirecting to sign in…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders the 'Audit chains' H1 and subtitle text", () => {
    useSWRMock.mockReturnValue({ data: { chains: [] }, error: undefined, isLoading: false });
    render(React.createElement(AuditPage));
    expect(screen.getByText("Audit chains").tagName.toLowerCase()).toBe("h1");
    const subtitle = screen.getByText(/append-only hash-chained audit/);
    expect(subtitle.tagName.toLowerCase()).toBe("p");
  });

  it("renders the empty state and no overall-status badge when chains is empty", () => {
    useSWRMock.mockReturnValue({ data: { chains: [] }, error: undefined, isLoading: false });
    render(React.createElement(AuditPage));
    expect(screen.getByText("No audit chains found.")).toBeTruthy();
    expect(screen.queryByTestId("overall-status")).toBeNull();
  });

  it("renders a verified chain with a robust-toned 'verified' status and event blocks", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "project:alpha",
            verified: true,
            event_count: 2,
            head_hash: "deadbeef12345678abcdef0000000000",
            events: [
              { seq: 1, this_hash: "aaaa1111", prev_hash: null },
              { seq: 2, this_hash: "bbbb2222", prev_hash: "aaaa1111" },
            ],
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));

    const status = screen.getByTestId("status-project:alpha");
    expect(status.textContent).toContain("verified");
    // The "robust" token, not a raw palette literal: the design port moved
    // every status tone onto the shared palette, so this asserts the tone the
    // component means rather than the colour it happened to compile to.
    expect(status.className).toContain("robust");

    // Per-event blocks render with seq labels.
    expect(screen.getByText("seq 1")).toBeTruthy();
    expect(screen.getByText("seq 2")).toBeTruthy();

    // Overall status reflects all-verified.
    const overall = screen.getByTestId("overall-status");
    expect(overall.textContent).toContain("All chains verified");
    expect(overall.className).toContain("robust");
  });

  it("renders a broken chain with a destructive-toned 'broken' status", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "run:xyz",
            verified: false,
            event_count: 3,
            head_hash: "00112233",
            broken_at: 2,
            events: [
              { seq: 1, this_hash: "h1", prev_hash: null },
              { seq: 2, this_hash: "h2", prev_hash: "WRONG" },
              { seq: 3, this_hash: "h3", prev_hash: "h2" },
            ],
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));

    const status = screen.getByTestId("status-run:xyz");
    expect(status.textContent).toContain("broken");
    expect(status.className).toContain("destructive");

    const overall = screen.getByTestId("overall-status");
    expect(overall.textContent).toContain("broken");
    expect(overall.className).toContain("destructive");
  });

  it("falls back to a head-only summary node when a chain has no events", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "system",
            verified: false,
            event_count: 5,
            head_hash: "abcdef0123456789aabbccddeeff",
            broken_at: 4,
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    // Head node present, no seq blocks.
    expect(screen.getByTestId("hash-head")).toBeTruthy();
    expect(screen.queryByText("seq 1")).toBeNull();
    expect(screen.getByText(/chain broken at seq 4/)).toBeTruthy();
  });

  it("distinguishes a valid chain from a broken chain when both are present", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "project:good",
            verified: true,
            event_count: 1,
            head_hash: "good0000",
            events: [{ seq: 1, this_hash: "good0000", prev_hash: null }],
          },
          {
            chain_id: "run:bad",
            verified: false,
            event_count: 1,
            head_hash: "bad0000",
            broken_at: 1,
            events: [{ seq: 1, this_hash: "bad0000", prev_hash: null }],
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));

    expect(screen.getByTestId("status-project:good").textContent).toContain(
      "verified",
    );
    expect(screen.getByTestId("status-run:bad").textContent).toContain("broken");

    // With one broken chain the overall status is not all-verified.
    expect(screen.getByTestId("overall-status").textContent).toContain(
      "1 chain broken",
    );
  });

  it("truncates a long this_hash and exposes the full hash via tooltip content", () => {
    const full = "aabbccddeeff0011223344556677889900";
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "project:trunc",
            verified: true,
            event_count: 1,
            head_hash: full,
            events: [{ seq: 1, this_hash: full, prev_hash: null }],
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    // Truncated to 16 chars + ellipsis appears in the node.
    expect(screen.getAllByText("aabbccddeeff0011…").length).toBeGreaterThan(0);
    // Full hash surfaced inside the (mocked) tooltip content.
    const tips = screen.getAllByTestId("tooltip-content");
    expect(tips.some((t) => t.textContent === full)).toBe(true);
  });
});
