import { createElement as h } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: this workspace's vitest v4 transforms via oxc, and web/tsconfig.json
// sets `jsx: "preserve"` (required by Next), so raw JSX syntax fails to parse
// in test files. We build elements with React.createElement (`h`) instead —
// behaviour and assertions are unchanged.

// SWR drives both the findings fetch and the run-status fetch; the mock keys
// off the request path so each useSWR call gets the right slice. mutate() is
// the revalidation hook the live job-event path calls; the fallback poll
// passes refreshInterval through.
const useSWRMock = vi.hoisted(() => vi.fn());
const mutateMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

const useRolesMock = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

const cancelRunMock = vi.hoisted(() => vi.fn());

// apiBase/apiWsBase are imported as VALUES (anchor links + WS url) -> mock them
// to deterministic hosts. api() itself is only the SWR fetcher (never invoked).
// bearerToken is read by useRunEvents to pick the cookie vs subprotocol path;
// default to the cookie (browser) path here and override per-test as needed.
const bearerTokenMock = vi.hoisted(() => vi.fn<() => string | undefined>(() => undefined));
vi.mock("@/lib/api", () => ({
  api: vi.fn(),
  apiBase: "http://api.test",
  apiWsBase: "ws://api.test",
  cancelRun: cancelRunMock,
  isCancellable: (s: string | undefined) =>
    s != null && ["queued", "running", "pending"].includes(s),
  reportUrl: (id: string, ext: string) => `http://api.test/v1/runs/${id}/report.${ext}`,
  bearerToken: bearerTokenMock,
}));

// Stub design-system. StageTimeline lists stage names so the WS path is
// observable; AlertDialog/Tooltip/RoleGated are rendered transparently so
// confirm-flow + gating remain observable in the DOM.
vi.mock("@redsim/design-system", () => ({
  SeverityChip: ({ level }: { level: string }) =>
    h("span", { "data-testid": "severity" }, level),
  StageTimeline: ({ stages }: { stages: Array<{ name: string }> }) =>
    h(
      "ul",
      { "data-testid": "stage-timeline" },
      stages.map((s, i) => h("li", { key: i }, s.name)),
    ),
  RoleGated: ({ minRole, callerRole, children, fallback }: any) => {
    const rank: Record<string, number> = { scanner: 1, remediator: 2, approver: 3, admin: 4 };
    return (rank[callerRole] ?? 0) >= (rank[minRole] ?? 99)
      ? h("div", null, children)
      : h("div", null, fallback ?? null);
  },
  TooltipProvider: ({ children }: any) => h("div", null, children),
  Tooltip: ({ children }: any) => h("div", null, children),
  TooltipTrigger: ({ children }: any) => h("div", null, children),
  TooltipContent: ({ children }: any) => h("div", null, children),
  AlertDialog: ({ children }: any) => h("div", null, children),
  AlertDialogTrigger: ({ children }: any) => h("div", null, children),
  AlertDialogContent: ({ children }: any) => h("div", null, children),
  AlertDialogHeader: ({ children }: any) => h("div", null, children),
  AlertDialogFooter: ({ children }: any) => h("div", null, children),
  AlertDialogTitle: ({ children }: any) => h("div", null, children),
  AlertDialogDescription: ({ children }: any) => h("div", null, children),
  AlertDialogAction: ({ children, onClick }: any) =>
    h("button", { onClick }, children),
  AlertDialogCancel: ({ children }: any) => h("button", null, children),
}));

// jsdom has no WebSocket. Capture each constructed instance so tests can drive
// onmessage and assert close-on-unmount. The page now opens TWO sockets to the
// same events URL: useRunEvents (job-lifecycle, declared first) and the legacy
// stage-events effect. Both hit ws://api.test/v1/runs/<id>/events, so tests
// select by construction order via jobWs()/stageWs() rather than by url.
const wsInstances: FakeWS[] = [];
class FakeWS {
  onmessage: ((ev: { data: string }) => void) | null = null;
  close = vi.fn();
  url: string;
  protocols?: string | string[];
  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocols = protocols;
    wsInstances.push(this);
  }
}

// useRunEvents' effect is declared before the legacy stage-events effect, and
// React runs effects in declaration order, so the job socket is constructed
// first.
const jobWs = () => wsInstances[0];
const stageWs = () => wsInstances[1];

import RunPage from "./page";

function finding(over: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    run_id: "run-1",
    project_id: "proj-alpha",
    severity: "high",
    status: "open",
    source_tool: "trivy",
    validation_state: "poc_passed",
    dedup_key: null,
    schema_blob: { title: "SQLi" },
    ...over,
  };
}

// Configure useSWR to answer per request path.
function setSWR(opts: {
  findings?: unknown;
  findingsError?: unknown;
  findingsLoading?: boolean;
  run?: unknown;
}) {
  const mutate = vi.fn();
  useSWRMock.mockImplementation((key: string | null) => {
    if (typeof key === "string" && key.startsWith("/v1/findings")) {
      return {
        data: opts.findings,
        error: opts.findingsError,
        isLoading: opts.findingsLoading ?? false,
      };
    }
    if (typeof key === "string" && key.startsWith("/v1/runs/")) {
      return { data: opts.run, error: undefined, mutate };
    }
    return { data: undefined, error: undefined, mutate };
  });
  return mutate;
}

function renderPage(id = "run-1") {
  return render(h(RunPage, { params: { id } }));
}

beforeEach(() => {
  useSWRMock.mockReset();
  cancelRunMock.mockReset();
  mutateMock.mockReset();
  bearerTokenMock.mockReset();
  bearerTokenMock.mockReturnValue(undefined);
  useRequireAuthMock.mockReturnValue(true);
  useRolesMock.mockReturnValue({ roles: { "proj-alpha": "admin" }, projects: [], isLoading: false, error: undefined });
  wsInstances.length = 0;
  vi.stubGlobal("WebSocket", FakeWS);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("RunPage", () => {
  it("shows the redirect placeholder when unauthenticated and opens no socket", () => {
    useRequireAuthMock.mockReturnValue(false);
    setSWR({});
    renderPage();
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
    expect(wsInstances).toHaveLength(0);
  });

  it("renders the loading state", () => {
    setSWR({ findingsLoading: true });
    renderPage();
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders the error panel with the stringified error", () => {
    setSWR({ findingsError: new Error("ws-down-500") });
    renderPage();
    const panel = screen.getByText(/Failed to load:/);
    expect(panel.textContent).toContain("ws-down-500");
    expect(panel.className).toContain("border-destructive");
  });

  it("opens both event sockets at the apiWsBase events url for the run", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage("run-77");
    // Two subscribers on the same channel: job-lifecycle + legacy stage events.
    expect(wsInstances).toHaveLength(2);
    expect(jobWs().url).toBe("ws://api.test/v1/runs/run-77/events");
    expect(stageWs().url).toBe("ws://api.test/v1/runs/run-77/events");
  });

  it("offers no subprotocol on the job socket when on the cookie (browser) path", () => {
    bearerTokenMock.mockReturnValue(undefined);
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage("run-77");
    expect(jobWs().protocols).toBeUndefined();
  });

  it("offers the redsim.bearer.<token> subprotocol on the job socket for programmatic callers", () => {
    bearerTokenMock.mockReturnValue("tok-abc");
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage("run-77");
    expect(jobWs().protocols).toEqual(["redsim.bearer.tok-abc"]);
  });

  it("shows the header id and report links per ext built from reportUrl", () => {
    setSWR({ findings: { findings: [], count: 0 } });
    renderPage("run-77");

    expect(screen.getByRole("heading", { name: "run-77" })).toBeTruthy();
    const html = screen.getByRole("link", { name: /HTML report/ });
    expect(html.getAttribute("href")).toBe("http://api.test/v1/runs/run-77/report.html");
    expect(screen.getByRole("link", { name: "JSON" }).getAttribute("href")).toBe(
      "http://api.test/v1/runs/run-77/report.json",
    );
    expect(screen.getByRole("link", { name: "Markdown" }).getAttribute("href")).toBe(
      "http://api.test/v1/runs/run-77/report.md",
    );
    // The Vulnfixer remediation export was removed with the pentest domain.
    expect(screen.queryByRole("link", { name: /Vulnfixer/ })).toBeNull();
  });

  it("renders a finding row per finding with severity, title, validation, status and the count", () => {
    setSWR({
      findings: {
        findings: [
          finding({ id: "f-1", severity: "high", schema_blob: { title: "SQLi" }, validation_state: "poc_passed", status: "open" }),
          finding({ id: "f-2", severity: "low", schema_blob: {}, validation_state: "unvalidated", status: "triaged" }),
        ],
        count: 2,
      },
    });
    renderPage();

    expect(screen.getByText("Findings (2)")).toBeTruthy();
    expect(screen.getByRole("link", { name: "f-1" }).getAttribute("href")).toBe("/findings/f-1");
    expect(screen.getByRole("link", { name: "f-2" }).getAttribute("href")).toBe("/findings/f-2");
    expect(screen.getAllByTestId("severity").map((s) => s.textContent)).toEqual(["high", "low"]);
    expect(screen.getByText("SQLi")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
    expect(screen.getByText("poc passed")).toBeTruthy();
    expect(screen.getByText("unvalidated")).toBeTruthy();
    expect(screen.getByText("triaged")).toBeTruthy();
  });

  it("defaults the findings count to 0 when data is absent", () => {
    setSWR({});
    renderPage();
    expect(screen.getByText("Findings (0)")).toBeTruthy();
  });

  it("closes both sockets on unmount", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    const { unmount } = renderPage();
    const job = jobWs();
    const stage = stageWs();
    unmount();
    expect(job.close).toHaveBeenCalledTimes(1);
    expect(stage.close).toHaveBeenCalledTimes(1);
  });

  it("appends stage events from the socket into the StageTimeline", () => {
    setSWR({ findings: { findings: [], count: 0 } });
    renderPage();

    const ws = stageWs();
    act(() => {
      ws.onmessage?.({ data: JSON.stringify({ name: "recon" }) });
      ws.onmessage?.({ data: JSON.stringify({ name: "scan", mode: "live" }) });
    });
    const timeline = screen.getByTestId("stage-timeline");
    expect(timeline.textContent).toContain("recon");
    expect(timeline.textContent).toContain("scan");
    expect(screen.queryByText("Waiting for the worker to emit stage events…")).toBeNull();
  });

  it("ignores malformed/heartbeat frames without a name", () => {
    setSWR({ findings: { findings: [], count: 0 } });
    renderPage();

    const ws = stageWs();
    act(() => {
      ws.onmessage?.({ data: "not json" });
      ws.onmessage?.({ data: JSON.stringify({ mode: "live" }) });
    });
    expect(screen.getByText("Waiting for the worker to emit stage events…")).toBeTruthy();
  });

  it("hides Cancel run for a terminal run status", () => {
    setSWR({
      findings: { findings: [], count: 0 },
      run: { id: "run-1", project_id: "proj-alpha", status: "completed" },
    });
    renderPage();
    expect(screen.queryByRole("button", { name: "Cancel run" })).toBeNull();
  });


  it("hides Cancel run when the caller lacks the remediator role", () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "scanner" }, projects: [], isLoading: false, error: undefined });
    setSWR({
      findings: { findings: [], count: 0 },
      run: { id: "run-1", project_id: "proj-alpha", status: "running" },
    });
    renderPage();
    expect(screen.queryByText("Cancel run")).toBeNull();
  });

  it("shows Cancel run for a cancellable run and POSTs on confirm", async () => {
    cancelRunMock.mockResolvedValue(undefined);
    setSWR({
      findings: { findings: [], count: 0 },
      run: { id: "run-1", project_id: "proj-alpha", status: "running" },
    });
    renderPage("run-1");

    // The trigger button + the AlertDialogAction (transparently rendered) both
    // read "Cancel run"; click the confirm action.
    const buttons = screen.getAllByRole("button", { name: "Cancel run" });
    expect(buttons.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => expect(cancelRunMock).toHaveBeenCalledWith("run-1"));
  });

  it("surfaces an inline error when cancel fails", async () => {
    cancelRunMock.mockRejectedValue(new Error("cancel-denied-403"));
    setSWR({
      findings: { findings: [], count: 0 },
      run: { id: "run-1", project_id: "proj-alpha", status: "running" },
    });
    renderPage("run-1");

    const buttons = screen.getAllByRole("button", { name: "Cancel run" });
    fireEvent.click(buttons[buttons.length - 1]);

    expect(await screen.findByText(/cancel-denied-403/)).toBeTruthy();
  });

  it("passes the fallback poll interval through to SWR", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage();
    // 3rd arg is SWR's options object; the slow poll is the WS fallback.
    expect(useSWRMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(Function),
      expect.objectContaining({ refreshInterval: 30_000 }),
    );
  });

  it("revalidates the findings query (mutate) on a job-lifecycle frame", () => {
    useSWRMock.mockReturnValue({
      data: { findings: [], count: 0 },
      error: undefined,
      isLoading: false,
      mutate: mutateMock,
    });
    renderPage("run-9");

    act(() => {
      jobWs().onmessage?.({
        data: JSON.stringify({
          type: "job",
          run_id: "run-9",
          job_id: "j-1",
          status: "running",
        }),
      });
    });

    expect(mutateMock).toHaveBeenCalledTimes(1);
  });

  it("does not revalidate on heartbeat / non-job frames", () => {
    useSWRMock.mockReturnValue({
      data: { findings: [], count: 0 },
      error: undefined,
      isLoading: false,
      mutate: mutateMock,
    });
    renderPage("run-9");

    act(() => {
      // heartbeat, the legacy stage shape, and pure garbage are all ignored.
      jobWs().onmessage?.({ data: JSON.stringify({ type: "heartbeat" }) });
      jobWs().onmessage?.({ data: JSON.stringify({ name: "recon" }) });
      jobWs().onmessage?.({ data: "not json" });
    });

    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("opens no job socket while unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    renderPage();
    // Neither the job nor the stage effect should construct a socket.
    expect(wsInstances).toHaveLength(0);
  });
});
