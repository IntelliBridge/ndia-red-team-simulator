import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// SWR drives the findings list; hoisted so per-test mockReturnValue selects
// the loading/error/empty/data branch.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

vi.mock("@/lib/api", () => ({ api: vi.fn() }));

// Stub the design-system table/severity primitives down to plain elements so
// the test asserts page behaviour, not primitive styling.
vi.mock("@redsim/design-system", () => ({
  SeverityChip: ({ level }: { level: string }) =>
    h("span", { "data-testid": "sev" }, level),
  Table: ({ children }: any) => h("table", null, children),
  TableHeader: ({ children }: any) => h("thead", null, children),
  TableBody: ({ children }: any) => h("tbody", null, children),
  TableRow: ({ children }: any) => h("tr", null, children),
  TableHead: ({ children }: any) => h("th", null, children),
  TableCell: ({ children }: any) => h("td", null, children),
  TableCaption: ({ children }: any) => h("caption", null, children),
}));

import FindingsPage from "./page";

function finding(over: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    run_id: "run-1",
    project_id: "proj-1",
    severity: "high",
    status: "open",
    source_tool: "trivy",
    validation_state: "unvalidated",
    dedup_key: null,
    schema_blob: { title: "SQLi" },
    ...over,
  };
}

beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
});

afterEach(cleanup);

describe("FindingsPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(FindingsPage));
    expect(screen.getByText("Signing in…")).toBeTruthy();
    expect(screen.queryByText("Findings")).toBeNull();
  });

  it("requests the unfiltered findings key when authed and no filter", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(FindingsPage));
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/findings", expect.any(Function));
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(FindingsPage));
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders the error panel", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: new Error("boom-503"), isLoading: false });
    render(h(FindingsPage));
    const panel = screen.getByText(/Failed to load findings:/);
    expect(panel.textContent).toContain("boom-503");
    expect(panel.className).toContain("border-destructive");
  });

  it("renders the empty state", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    render(h(FindingsPage));
    expect(screen.getByText(/No findings/)).toBeTruthy();
  });

  it("renders a row per finding with a link, severity chip and source", () => {
    useSWRMock.mockReturnValue({
      data: {
        findings: [
          finding({ id: "f-7", severity: "critical", schema_blob: { title: "RCE" } }),
          finding({ id: "f-8", severity: "low", source_tool: null, schema_blob: {} }),
        ],
        count: 2,
      },
      error: undefined,
      isLoading: false,
    });
    render(h(FindingsPage));

    const link7 = screen.getByRole("link", { name: "f-7" });
    expect(link7.getAttribute("href")).toBe("/findings/f-7");
    expect(screen.getByRole("link", { name: "f-8" }).getAttribute("href")).toBe("/findings/f-8");

    const chips = screen.getAllByTestId("sev");
    expect(chips.map((c) => c.textContent)).toEqual(["critical", "low"]);

    expect(screen.getByText("RCE")).toBeTruthy();
    // Missing title and null source both fall back to the em dash.
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("re-keys the SWR query when a severity filter is chosen", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    render(h(FindingsPage));

    fireEvent.change(screen.getByLabelText("Filter by severity"), {
      target: { value: "critical" },
    });
    expect(useSWRMock).toHaveBeenLastCalledWith(
      "/v1/findings?severity=critical",
      expect.any(Function),
    );
  });
});
