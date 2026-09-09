import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// vitest v4 + tsconfig `jsx: "preserve"` => build elements with
// React.createElement (`h`) rather than raw JSX in test files.

// SWR drives the cost fetch; hoisted so each test can pick the
// loading/error/empty/data branch and we can assert the SWR key.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true as boolean));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

const useRolesMock = vi.hoisted(() =>
  vi.fn(() => ({
    projects: [] as Array<{ id: string; org_id: string }>,
    roles: {} as Record<string, string>,
    isLoading: false,
    error: undefined as unknown,
  })),
);
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

// Keep the real centsToUsd/resolveOrgId; only stub getOrgCost so no fetch
// fires (SWR itself is mocked, so the fetcher never actually runs anyway).
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, getOrgCost: vi.fn() };
});

import CostPage from "./page";
import type { OrgCost } from "@/lib/api";

function cost(over: Partial<OrgCost> = {}): OrgCost {
  return {
    org_id: "org-acme",
    total_cents: 12345,
    call_count: 42,
    by_day: { "2026-06-01": 5000, "2026-06-02": 7345 },
    by_model: { "gpt-4o": 9000, "claude-3": 3345 },
    by_task: { recon: 8000, exploit: 4345 },
    budget: {
      monthly_cap_cents: 50000,
      month_spent_cents: 22222,
      remaining_cents: 27778,
    },
    ...over,
  };
}

beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
  useRolesMock.mockReturnValue({
    projects: [{ id: "p1", org_id: "org-acme" }],
    roles: {},
    isLoading: false,
    error: undefined,
  });
});

afterEach(cleanup);

describe("CostPage", () => {
  it("redirects to sign in when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(CostPage));
    expect(screen.getByText("Signing in…")).toBeTruthy();
    expect(screen.queryByText("Cost")).toBeNull();
  });

  it("passes a [orgId, days] SWR key resolved from the projects list", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(CostPage));
    expect(useSWRMock).toHaveBeenLastCalledWith(
      ["org-acme", 30],
      expect.any(Function),
    );
  });

  it("falls back to the 'default' org when the caller has no projects", () => {
    useRolesMock.mockReturnValue({
      projects: [],
      roles: {},
      isLoading: false,
      error: undefined,
    });
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(CostPage));
    expect(useSWRMock).toHaveBeenLastCalledWith(
      ["default", 30],
      expect.any(Function),
    );
  });

  it("holds the SWR key null until projects finish loading", () => {
    useRolesMock.mockReturnValue({
      projects: [],
      roles: {},
      isLoading: true,
      error: undefined,
    });
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(CostPage));
    expect(useSWRMock).toHaveBeenLastCalledWith(null, expect.any(Function));
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(CostPage));
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders a red error panel on failure", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("boom-503"),
      isLoading: false,
    });
    render(h(CostPage));
    const panel = screen.getByText(/Failed to load cost:/);
    expect(panel.textContent).toContain("boom-503");
    expect(panel.className).toContain("border-destructive");
  });

  it("surfaces a projects-fetch error too", () => {
    useRolesMock.mockReturnValue({
      projects: [],
      roles: {},
      isLoading: false,
      error: new Error("forbidden"),
    });
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(CostPage));
    expect(screen.getByText(/Failed to load cost:/).textContent).toContain(
      "forbidden",
    );
  });

  it("renders the header cards: total spend and call count", () => {
    useSWRMock.mockReturnValue({ data: cost(), error: undefined, isLoading: false });
    render(h(CostPage));
    // 12345 cents => $123.45
    expect(screen.getByText("$123.45")).toBeTruthy();
    expect(screen.getByText("Total spend")).toBeTruthy();
    expect(screen.getByText("42")).toBeTruthy();
  });

  it("renders a capped budget card with cap, MTD spend, and remaining", () => {
    useSWRMock.mockReturnValue({ data: cost(), error: undefined, isLoading: false });
    render(h(CostPage));
    expect(screen.getByText("$500.00")).toBeTruthy(); // cap
    expect(screen.getByText("$222.22")).toBeTruthy(); // month to date
    expect(screen.getByText("$277.78")).toBeTruthy(); // remaining
  });

  it("shows 'Uncapped' for a null monthly cap and null remaining", () => {
    useSWRMock.mockReturnValue({
      data: cost({
        budget: {
          monthly_cap_cents: null,
          month_spent_cents: 12345,
          remaining_cents: null,
        },
      }),
      error: undefined,
      isLoading: false,
    });
    render(h(CostPage));
    expect(screen.getAllByText("Uncapped").length).toBeGreaterThanOrEqual(2);
  });

  it("flags remaining as over budget when at or below zero", () => {
    useSWRMock.mockReturnValue({
      data: cost({
        budget: {
          monthly_cap_cents: 10000,
          month_spent_cents: 12000,
          remaining_cents: -2000,
        },
      }),
      error: undefined,
      isLoading: false,
    });
    render(h(CostPage));
    // Over budget carries a non-colour cue (the "over budget —" prefix) plus
    // the destructive token, so the state isn't conveyed by colour alone.
    const remaining = screen.getByText(/over budget — -\$20\.00/);
    expect(remaining.className).toContain("text-destructive");
  });

  it("renders one by-day bar per day with day attribution", () => {
    useSWRMock.mockReturnValue({ data: cost(), error: undefined, isLoading: false });
    render(h(CostPage));
    const bars = screen.getAllByTestId("bar");
    expect(bars.length).toBe(2);
    expect(bars.map((b) => b.getAttribute("data-day"))).toEqual([
      "2026-06-01",
      "2026-06-02",
    ]);
  });

  it("renders by-model and by-task tables sorted desc by cents", () => {
    useSWRMock.mockReturnValue({ data: cost(), error: undefined, isLoading: false });
    render(h(CostPage));
    expect(screen.getByText("gpt-4o")).toBeTruthy();
    expect(screen.getByText("claude-3")).toBeTruthy();
    expect(screen.getByText("recon")).toBeTruthy();
    expect(screen.getByText("exploit")).toBeTruthy();
    // gpt-4o (9000) sorts before claude-3 (3345)
    const models = screen.getAllByText(/gpt-4o|claude-3/);
    expect(models[0].textContent).toBe("gpt-4o");
  });

  it("refetches with the selected days when the window changes", () => {
    useSWRMock.mockReturnValue({ data: cost(), error: undefined, isLoading: false });
    render(h(CostPage));
    fireEvent.change(screen.getByLabelText("Days window"), {
      target: { value: "90" },
    });
    expect(useSWRMock).toHaveBeenLastCalledWith(
      ["org-acme", 90],
      expect.any(Function),
    );
  });

  it("renders the no-usage empty state when there is zero spend", () => {
    useSWRMock.mockReturnValue({
      data: cost({
        total_cents: 0,
        call_count: 0,
        by_day: {},
        by_model: {},
        by_task: {},
      }),
      error: undefined,
      isLoading: false,
    });
    render(h(CostPage));
    expect(
      screen.getByText(/No usage recorded for this org/),
    ).toBeTruthy();
  });
});
