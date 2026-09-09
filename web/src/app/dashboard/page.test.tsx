import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: this workspace's vitest v4 transforms via oxc, and web/tsconfig.json
// sets `jsx: "preserve"` (required by Next), so raw JSX syntax fails to parse
// in test files. We therefore build elements with React.createElement (`h`)
// instead of JSX — behaviour and assertions are unchanged.

// SWR is the data source for the runs list. Hoisted so per-test mockReturnValue
// can drive the loading/error/empty/data branches.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

// Router push is asserted on sign-out.
const pushMock = vi.fn();
const replaceMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: replaceMock }),
}));

// Auth gate: default authed; individual tests flip it to false.
const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

// auth helpers the page imports: getEmail (display) + logout (sign-out wiring).
const logoutMock = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
const getEmailMock = vi.hoisted(() => vi.fn(() => "dev@redsim.local"));
vi.mock("@/lib/auth", () => ({
  getEmail: getEmailMock,
  logout: logoutMock,
}));

// Isolate the page: stub the only design-system symbol it renders.
vi.mock("@redsim/design-system", () => ({
  RunStatusBadge: ({ status }: { status: string }) =>
    h("span", { "data-testid": "run-status" }, status),
  SeverityChip: ({ level }: { level: string }) => h("span", { "data-testid": "sev" }, level),
}));

import DashboardPage from "./page";

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
  pushMock.mockReset();
  replaceMock.mockReset();
  logoutMock.mockReset();
  logoutMock.mockResolvedValue(undefined);
  getEmailMock.mockReset();
  getEmailMock.mockReturnValue("dev@redsim.local");
  useRequireAuthMock.mockReturnValue(true);
});

afterEach(cleanup);

describe("DashboardPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });

    render(h(DashboardPage));

    expect(screen.getByText("Signing in…")).toBeTruthy();
    // The heading must not render on the gated path.
    expect(screen.queryByText("Recent runs")).toBeNull();
  });

  it("passes the runs key only once authed (null while not)", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(DashboardPage));
    expect(useSWRMock).toHaveBeenLastCalledWith(null, expect.any(Function), {
      refreshInterval: 15000,
    });

    cleanup();
    useRequireAuthMock.mockReturnValue(true);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(DashboardPage));
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/runs", expect.any(Function), {
      refreshInterval: 15000,
    });
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });

    render(h(DashboardPage));

    expect(screen.getByText("Loading…")).toBeTruthy();
    expect(screen.queryByText("No runs yet.", { exact: false })).toBeNull();
  });

  it("renders the error panel with the stringified error", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("boom-503"),
      isLoading: false,
    });

    render(h(DashboardPage));

    const panel = screen.getByText(/Failed to load runs:/);
    expect(panel.textContent).toContain("boom-503");
    expect(panel.className).toContain("border-destructive");
  });

  it("renders the empty state when there are no runs", () => {
    useSWRMock.mockReturnValue({
      data: { runs: [], count: 0 },
      error: undefined,
      isLoading: false,
    });

    render(h(DashboardPage));

    expect(screen.getByText(/No runs yet\./)).toBeTruthy();
    const link = screen.getByRole("link", { name: "/models" });
    expect(link.getAttribute("href")).toBe("/models");
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

    render(h(DashboardPage));

    const link7 = screen.getByRole("link", { name: "run-7" });
    expect(link7.getAttribute("href")).toBe("/runs/run-7");
    expect(
      screen.getByRole("link", { name: "run-8" }).getAttribute("href"),
    ).toBe("/runs/run-8");

    // Status badges receive each run's status.
    const badges = screen.getAllByTestId("run-status");
    expect(badges.map((b) => b.textContent)).toEqual(["running", "failed"]);

    // Project ids render; the null scanner falls back to the em dash.
    expect(screen.getByText("proj-alpha")).toBeTruthy();
    expect(screen.getByText("proj-beta")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
  });

  it("renders the stat tiles, the severity bars and the severe findings from the three lists", () => {
    // The mock answers every SWR call with the same object, so it carries all
    // three lists at once; the page reads only the key each hook expects.
    useSWRMock.mockReturnValue({
      data: {
        runs: [run(), run({ id: "run-2", status: "running" }), run({ id: "run-3", status: "failed" })],
        models: [
          { id: "m1", status: "available", registered: true },
          { id: "m2", status: "validating", registered: true },
          { id: "b1", status: "available", registered: false },
        ],
        findings: [
          { id: "f-1", run_id: "run-1", severity: "high", status: "open",
            schema_blob: { title: "PGD flips predictions", target: "bundled:vehicles_cnn", affected_component: "vehicles_cnn-1234abcd",
              description: "What happened: redsim took the images this model classified correctly. Measured: PGD ..." } },
          { id: "f-2", run_id: "run-1", severity: "low", status: "open", schema_blob: { title: "Low one" } },
          { id: "f-3", run_id: "run-1", severity: "critical", status: "false_positive", schema_blob: { title: "Dismissed" } },
        ],
        count: 3,
      },
      error: undefined,
      isLoading: false,
    });
    render(h(DashboardPage));
    expect(screen.getByText("Registered models").nextSibling?.textContent).toBe("2");
    expect(screen.getByText("1 available to attack")).toBeTruthy();
    expect(screen.getByText("Runs").nextSibling?.textContent).toBe("3");
    expect(screen.getByText("1 running or queued")).toBeTruthy();
    expect(screen.getByText("Open findings").nextSibling?.textContent).toBe("2");
    expect(screen.getByText("High or critical").nextSibling?.textContent).toBe("2");
    expect(screen.getByText("1 critical")).toBeTruthy();
    // Severity bars carry label and count, never colour alone.
    const bars = screen.getByLabelText("Findings by severity");
    expect(bars.textContent).toContain("critical");
    expect(bars.textContent).toContain("high");
    expect(bars.textContent).toContain("low");
    // The severe list shows the open high finding with its plain-language lead
    // and omits the dismissed critical one.
    expect(screen.getByRole("link", { name: "PGD flips predictions" }).getAttribute("href")).toBe("/findings/f-1");
    expect(screen.getByText("redsim took the images this model classified correctly.")).toBeTruthy();
    expect(screen.queryByText("Dismissed")).toBeNull();
    // The model the finding is about, linked to its page.
    expect(screen.getByRole("link", { name: "vehicles_cnn" }).getAttribute("href")).toBe("/models/vehicles_cnn-1234abcd");
  });

  it("shows the session email from getEmail()", () => {
    getEmailMock.mockReturnValue("alice@redsim.local");
    useSWRMock.mockReturnValue({ data: { runs: [], count: 0 }, error: undefined, isLoading: false });

    render(h(DashboardPage));

    expect(screen.getByText("alice@redsim.local")).toBeTruthy();
  });

  it("signs out: calls logout() then routes to /login", async () => {
    useSWRMock.mockReturnValue({ data: { runs: [], count: 0 }, error: undefined, isLoading: false });

    render(h(DashboardPage));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));

    expect(logoutMock).toHaveBeenCalledTimes(1);
    // logout() ends the Better Auth and Keycloak sessions before it resolves,
    // so the redirect lands a microtask later rather than on the click.
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/login"));
  });
});
