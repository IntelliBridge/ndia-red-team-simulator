import { createElement as h } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

vi.mock("@/lib/api", () => ({ api: vi.fn() }));

vi.mock("@redsim/design-system", () => ({
  RunStatusBadge: ({ status }: { status: string }) =>
    h("span", { "data-testid": "run-status" }, status),
  Table: ({ children }: any) => h("table", null, children),
  TableHeader: ({ children }: any) => h("thead", null, children),
  TableBody: ({ children }: any) => h("tbody", null, children),
  TableRow: ({ children }: any) => h("tr", null, children),
  TableHead: ({ children }: any) => h("th", null, children),
  TableCell: ({ children }: any) => h("td", null, children),
  TableCaption: ({ children }: any) => h("caption", null, children),
}));

import RunsPage from "./page";

function run(over: Record<string, unknown> = {}) {
  return {
    id: "run-1",
    project_id: "proj-alpha",
    status: "completed",
    scanner: "trivy",
    mode: "live",
    created_at: "2026-01-02T03:04:05.000Z",
    created_by: null,
    ...over,
  };
}

beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
});

afterEach(cleanup);

describe("RunsPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(RunsPage));
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
    expect(screen.queryByText("Runs")).toBeNull();
  });

  it("passes the runs key only once authed (null while not)", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(RunsPage));
    expect(useSWRMock).toHaveBeenLastCalledWith(null, expect.any(Function));

    cleanup();
    useRequireAuthMock.mockReturnValue(true);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(RunsPage));
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/runs", expect.any(Function));
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(RunsPage));
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders the error panel", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: new Error("boom-503"), isLoading: false });
    render(h(RunsPage));
    const panel = screen.getByText(/Failed to load runs:/);
    expect(panel.textContent).toContain("boom-503");
    expect(panel.className).toContain("border-destructive");
  });

  it("renders the empty state with a /models link", () => {
    useSWRMock.mockReturnValue({ data: { runs: [], count: 0 }, error: undefined, isLoading: false });
    render(h(RunsPage));
    expect(screen.getByText(/No runs yet\./)).toBeTruthy();
    expect(screen.getByRole("link", { name: "/models" }).getAttribute("href")).toBe("/models");
  });

  it("renders a row per run with a link, status badge, project and scanner", () => {
    useSWRMock.mockReturnValue({
      data: {
        runs: [
          run({ id: "run-7", project_id: "proj-alpha", scanner: "trivy", status: "running" }),
          run({ id: "run-8", project_id: "proj-beta", scanner: null, status: "failed" }),
        ],
        count: 2,
      },
      error: undefined,
      isLoading: false,
    });
    render(h(RunsPage));

    expect(screen.getByRole("link", { name: "run-7" }).getAttribute("href")).toBe("/runs/run-7");
    expect(screen.getByRole("link", { name: "run-8" }).getAttribute("href")).toBe("/runs/run-8");

    const badges = screen.getAllByTestId("run-status");
    expect(badges.map((b) => b.textContent)).toEqual(["running", "failed"]);

    expect(screen.getByText("proj-alpha")).toBeTruthy();
    expect(screen.getByText("proj-beta")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
  });
});
