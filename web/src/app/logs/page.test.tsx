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

// useSearchParams — default to no filters
const searchParamsMock = vi.hoisted(() => vi.fn(() => new URLSearchParams()));
vi.mock("next/navigation", () => ({
  useSearchParams: searchParamsMock,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

import LogsPage from "./page";

afterEach(cleanup);
beforeEach(() => {
  useRequireAuthMock.mockReturnValue(true);
  searchParamsMock.mockReturnValue(new URLSearchParams());
});

describe("LogsPage", () => {
  it("renders the 'Loading…' state while SWR is fetching", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(React.createElement(LogsPage));
    // getByText throws if not found — that itself is the existence check
    const el = screen.getByText("Loading…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders a red error panel on SWR failure", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("network timeout"),
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    const el = screen.getByText(/Failed to load/);
    expect(el.textContent).toContain("network timeout");
  });

  it("renders the 'Redirecting to sign in…' placeholder when not authed", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(React.createElement(LogsPage));
    const el = screen.getByText("Redirecting to sign in…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders the empty-state cell when there are no log rows", () => {
    useSWRMock.mockReturnValue({
      data: { logs: [], next_cursor: null, count: 0 },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    const cell = screen.getByText("No log rows match these filters.");
    expect(cell.tagName.toLowerCase()).toBe("td");
  });

  it("renders a data row with severity, service, message, run_id, and request_id", () => {
    useSWRMock.mockReturnValue({
      data: {
        logs: [
          {
            id: 1,
            ts: "2026-01-01T00:00:00Z",
            severity: "error",
            service: "auth-svc",
            message: "token expired",
            run_id: "run-abc",
            project_id: "proj-1",
            request_id: "req-123",
            trace_id: null,
            span_id: null,
            actor: null,
          },
        ],
        next_cursor: null,
        count: 1,
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    expect(screen.getByText("error").textContent).toBe("error");
    expect(screen.getByText("auth-svc").textContent).toBe("auth-svc");
    expect(screen.getByText("token expired").textContent).toBe("token expired");
    expect(screen.getByText("run-abc").textContent).toBe("run-abc");
    expect(screen.getByText("req-123").textContent).toBe("req-123");
  });

  it("renders '—' placeholders for null run_id and request_id", () => {
    useSWRMock.mockReturnValue({
      data: {
        logs: [
          {
            id: 2,
            ts: "2026-01-01T01:00:00Z",
            severity: "info",
            service: "scanner",
            message: "scan started",
            run_id: null,
            project_id: null,
            request_id: null,
            trace_id: null,
            span_id: null,
            actor: null,
          },
        ],
        next_cursor: null,
        count: 1,
      },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBeGreaterThanOrEqual(2);
  });

  it("renders the 'Logs' heading and 'Across all runs' subtitle when no run filter", () => {
    useSWRMock.mockReturnValue({
      data: { logs: [], next_cursor: null, count: 0 },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    expect(screen.getByText("Logs").textContent).toBe("Logs");
    const subtitle = screen.getByText(/Across all runs/);
    expect(subtitle.textContent).toContain("Newest first.");
  });

  it("shows a run filter note when a run query param is present", () => {
    searchParamsMock.mockReturnValue(new URLSearchParams("run=run-xyz"));
    useSWRMock.mockReturnValue({
      data: { logs: [], next_cursor: null, count: 0 },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    const subtitle = screen.getByText(/Filtered to run run-xyz/);
    expect(subtitle.textContent).toContain("run-xyz");
  });

  it("renders all six table column headers", () => {
    useSWRMock.mockReturnValue({
      data: { logs: [], next_cursor: null, count: 0 },
      error: undefined,
      isLoading: false,
    });
    render(React.createElement(LogsPage));
    for (const label of ["ts", "sev", "service", "message", "run", "request"]) {
      expect(screen.getByText(label).textContent).toBe(label);
    }
  });
});
