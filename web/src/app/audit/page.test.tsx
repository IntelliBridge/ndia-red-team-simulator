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

// Stub AuditChainBadge to keep the test isolated from design-system internals
vi.mock("@aegis/design-system", () => ({
  AuditChainBadge: ({
    state,
    chainId,
  }: {
    state: string;
    chainId: string;
    events: number;
  }) =>
    React.createElement(
      "span",
      { "data-testid": `badge-${chainId}` },
      state
    ),
}));

import AuditPage from "./page";

afterEach(cleanup);
beforeEach(() => {
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

  it("renders table headers and no badge elements when chains array is empty", () => {
    useSWRMock.mockReturnValue({ data: { chains: [] }, error: undefined, isLoading: false });
    render(React.createElement(AuditPage));
    expect(screen.getByText("Chain").textContent).toBe("Chain");
    expect(screen.getByText("Events").textContent).toBe("Events");
    expect(screen.getByText("State").textContent).toBe("State");
    expect(screen.getByText("Head hash").textContent).toBe("Head hash");
    expect(screen.queryByTestId(/^badge-/)).toBeNull();
  });

  it("renders a verified chain row with chain_id, event_count, and badge", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "chain-abc",
            verified: true,
            event_count: 42,
            head_hash: "deadbeef12345678abcdef0000000000",
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    expect(screen.getByText("chain-abc").textContent).toBe("chain-abc");
    expect(screen.getByText("42").textContent).toBe("42");
    const badge = screen.getByTestId("badge-chain-abc");
    expect(badge.textContent).toBe("verified");
  });

  it("renders a head hash truncated to 16 characters plus ellipsis", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "chain-xyz",
            verified: false,
            event_count: 5,
            head_hash: "aabbccddeeff0011223344556677889900",
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    // page does: head_hash.slice(0, 16) + "…"
    const cell = screen.getByText("aabbccddeeff0011…");
    expect(cell.textContent).toBe("aabbccddeeff0011…");
  });

  it("renders '—' for a null head_hash", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "chain-null",
            verified: false,
            event_count: 0,
            head_hash: null,
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    expect(screen.getByText("—").textContent).toBe("—");
  });

  it("renders 'broken' badge state for an unverified chain", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          {
            chain_id: "chain-broken",
            verified: false,
            event_count: 3,
            head_hash: "1234567890abcdef",
          },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    expect(screen.getByTestId("badge-chain-broken").textContent).toBe("broken");
  });

  it("renders multiple chain rows with independent badge states", () => {
    useSWRMock.mockReturnValue({
      data: {
        chains: [
          { chain_id: "chain-1", verified: true, event_count: 10, head_hash: "aaaa0000bbbb1111" },
          { chain_id: "chain-2", verified: false, event_count: 7, head_hash: null },
        ],
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(AuditPage));
    expect(screen.getByText("chain-1").textContent).toBe("chain-1");
    expect(screen.getByText("chain-2").textContent).toBe("chain-2");
    expect(screen.getByTestId("badge-chain-1").textContent).toBe("verified");
    expect(screen.getByTestId("badge-chain-2").textContent).toBe("broken");
  });
});
