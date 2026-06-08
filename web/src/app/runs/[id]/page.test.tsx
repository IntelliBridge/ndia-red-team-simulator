import { createElement as h } from "react";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: this workspace's vitest v4 transforms via oxc, and web/tsconfig.json
// sets `jsx: "preserve"` (required by Next), so raw JSX syntax fails to parse
// in test files. We build elements with React.createElement (`h`) instead —
// behaviour and assertions are unchanged.

// SWR drives the findings fetch.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

// apiBase/apiWsBase are imported as VALUES (anchor links + WS url) -> mock them
// to deterministic hosts. api() itself is only the SWR fetcher (never invoked).
vi.mock("@/lib/api", () => ({
  api: vi.fn(),
  apiBase: "http://api.test",
  apiWsBase: "ws://api.test",
}));

// Stub design-system. StageTimeline lists stage names so the WS path is observable.
vi.mock("@aegis/design-system", () => ({
  SeverityChip: ({ level }: { level: string }) =>
    h("span", { "data-testid": "severity" }, level),
  StageTimeline: ({ stages }: { stages: Array<{ name: string }> }) =>
    h(
      "ul",
      { "data-testid": "stage-timeline" },
      stages.map((s, i) => h("li", { key: i }, s.name)),
    ),
}));

// jsdom has no WebSocket. Capture each constructed instance so tests can drive
// onmessage and assert close-on-unmount.
const wsInstances: FakeWS[] = [];
class FakeWS {
  onmessage: ((ev: { data: string }) => void) | null = null;
  close = vi.fn();
  url: string;
  constructor(url: string) {
    this.url = url;
    wsInstances.push(this);
  }
}

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

function renderPage(id = "run-1") {
  return render(h(RunPage, { params: { id } }));
}

beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
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
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });

    renderPage();

    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
    expect(wsInstances).toHaveLength(0);
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    renderPage();
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders the error panel with the stringified error", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("ws-down-500"),
      isLoading: false,
    });
    renderPage();
    const panel = screen.getByText(/Failed to load:/);
    expect(panel.textContent).toContain("ws-down-500");
    expect(panel.className).toContain("border-red-200");
  });

  it("opens a WebSocket at the apiWsBase events url for the run", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage("run-77");
    expect(wsInstances).toHaveLength(1);
    expect(wsInstances[0].url).toBe("ws://api.test/v1/runs/run-77/events");
  });

  it("shows the header id and an HTML report link built from apiBase", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage("run-77");

    expect(screen.getByRole("heading", { name: "run-77" })).toBeTruthy();
    const link = screen.getByRole("link", { name: /Open HTML report/ });
    expect(link.getAttribute("href")).toBe("http://api.test/v1/runs/run-77/report.html");
    expect(link.getAttribute("target")).toBe("_blank");
  });

  it("shows the waiting placeholder before any stage events arrive", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage();
    expect(screen.getByText("Waiting for the worker to emit stage events…")).toBeTruthy();
    expect(screen.queryByTestId("stage-timeline")).toBeNull();
  });

  it("renders a finding row per finding with severity, title, validation, status and the count", () => {
    useSWRMock.mockReturnValue({
      data: {
        findings: [
          finding({ id: "f-1", severity: "high", schema_blob: { title: "SQLi" }, validation_state: "poc_passed", status: "open" }),
          finding({ id: "f-2", severity: "low", schema_blob: {}, validation_state: "unvalidated", status: "triaged" }),
        ],
        count: 2,
      },
      error: undefined,
      isLoading: false,
    });

    renderPage();

    expect(screen.getByText("Findings (2)")).toBeTruthy();

    const f1 = screen.getByRole("link", { name: "f-1" });
    expect(f1.getAttribute("href")).toBe("/findings/f-1");
    expect(screen.getByRole("link", { name: "f-2" }).getAttribute("href")).toBe("/findings/f-2");

    expect(screen.getAllByTestId("severity").map((s) => s.textContent)).toEqual(["high", "low"]);

    expect(screen.getByText("SQLi")).toBeTruthy();
    // Missing title falls back to the em dash.
    expect(screen.getByText("—")).toBeTruthy();
    // validation_state underscores are humanised.
    expect(screen.getByText("poc passed")).toBeTruthy();
    expect(screen.getByText("unvalidated")).toBeTruthy();
    expect(screen.getByText("triaged")).toBeTruthy();
  });

  it("defaults the findings count to 0 when data is absent", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    renderPage();
    expect(screen.getByText("Findings (0)")).toBeTruthy();
  });

  it("closes the socket on unmount", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    const { unmount } = renderPage();
    const ws = wsInstances[0];
    unmount();
    expect(ws.close).toHaveBeenCalledTimes(1);
  });

  it("appends stage events from the socket into the StageTimeline", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage();

    const ws = wsInstances[0];
    act(() => {
      ws.onmessage?.({ data: JSON.stringify({ name: "recon" }) });
      ws.onmessage?.({ data: JSON.stringify({ name: "scan", mode: "live" }) });
    });

    const timeline = screen.getByTestId("stage-timeline");
    expect(timeline.textContent).toContain("recon");
    expect(timeline.textContent).toContain("scan");
    // The placeholder is gone once at least one event lands.
    expect(screen.queryByText("Waiting for the worker to emit stage events…")).toBeNull();
  });

  it("ignores malformed/heartbeat frames without a name", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    renderPage();

    const ws = wsInstances[0];
    act(() => {
      ws.onmessage?.({ data: "not json" });
      ws.onmessage?.({ data: JSON.stringify({ mode: "live" }) });
    });

    // Still waiting: no stage rendered for nameless/garbage frames.
    expect(screen.getByText("Waiting for the worker to emit stage events…")).toBeTruthy();
  });
});
