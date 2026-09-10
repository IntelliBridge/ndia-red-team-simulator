import { createElement } from "react";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import campaignFixture from "@/__fixtures__/campaign.json";

const mocks = vi.hoisted(() => ({
  useCampaign: vi.fn(),
  useRequireAuth: vi.fn(),
  useRoles: vi.fn(),
  useRunEvents: vi.fn(),
  mutate: vi.fn(),
  api: vi.fn(),
  cancelRun: vi.fn(),
  compareRuns: vi.fn(),
  dismissFinding: vi.fn(),
  patchReviewerNotes: vi.fn(),
  startCampaign: vi.fn(),
}));

vi.mock("@/hooks/useCampaign", () => ({
  useCampaign: mocks.useCampaign,
}));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: mocks.useRequireAuth,
}));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: mocks.useRoles,
}));
vi.mock("@/hooks/useRunEvents", () => ({
  useRunEvents: mocks.useRunEvents,
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  api: mocks.api,
  cancelRun: mocks.cancelRun,
  compareRuns: mocks.compareRuns,
  dismissFinding: mocks.dismissFinding,
  patchReviewerNotes: mocks.patchReviewerNotes,
  startCampaign: mocks.startCampaign,
  artifactUrl: (id: string) => `/v1/artifacts/${id}`,
  reportUrl: (id: string, ext: string) => `/v1/runs/${id}/report.${ext}`,
}));

import { ApiError } from "@/lib/api";
import RunPage from "./page";

type RunEvent = {
  type: "job" | "stage";
  name?: string;
  status: "running" | "succeeded" | "failed";
};

let eventHandler: ((event: RunEvent) => void) | undefined;

function campaign(overrides: Record<string, unknown> = {}) {
  return {
    ...structuredClone(campaignFixture),
    ...overrides,
  };
}

function setCampaign(data: ReturnType<typeof campaign> | undefined, error?: unknown) {
  mocks.useCampaign.mockReturnValue({
    data,
    error,
    mutate: mocks.mutate,
  });
}

function renderPage() {
  return render(createElement(RunPage, { params: { id: "fixture-run-001" } }));
}

beforeEach(() => {
  vi.clearAllMocks();
  eventHandler = undefined;
  mocks.useRequireAuth.mockReturnValue(true);
  mocks.useRoles.mockReturnValue({
    roles: { default: "approver" },
  });
  mocks.useRunEvents.mockImplementation(
    (_id: string | null, onEvent: (event: RunEvent) => void) => {
      eventHandler = onEvent;
    },
  );
  mocks.cancelRun.mockResolvedValue({});
  mocks.api.mockRejectedValue(new Error("no api read is expected in this case"));
  mocks.compareRuns.mockResolvedValue({
    compatible: true,
    mode: "side_by_side",
    scorecards: [
      { run_id: "fixture-run-001", mri: 58, grade: "C" },
      { run_id: "prior-run", mri: 61, grade: "C" },
    ],
    changed_variables: ["seed"],
    unchanged_variables: ["n_samples", "eps_grid"],
    caveats: ["Two measurements side by side; no delta is derived."],
  });
  setCampaign(campaign());
});

afterEach(() => cleanup());

describe("/runs/[id] campaign review", () => {
  it("keeps the authenticated guard and a non-claiming loading state", () => {
    mocks.useRequireAuth.mockReturnValue(false);
    setCampaign(undefined);
    renderPage();
    expect(screen.getByText("Signing in…")).toBeTruthy();

    cleanup();
    mocks.useRequireAuth.mockReturnValue(true);
    setCampaign(undefined);
    const { container } = renderPage();
    expect(container.querySelectorAll(".animate-pulse")).toHaveLength(2);
  });

  it("maps unavailable campaign reads without exposing raw response bodies", () => {
    setCampaign(undefined, new Error("private backend detail"));
    renderPage();
    expect(screen.getByText("Campaign unavailable. Retry.")).toBeTruthy();
    expect(screen.queryByText(/private backend detail/)).toBeNull();
  });

  it("renders the ordered 13-panel evidence review and scoped reports", () => {
    const { container } = renderPage();
    const panels = Array.from(
      container.querySelectorAll('[data-testid^="run-panel-"]'),
    );
    expect(panels).toHaveLength(13);
    expect(panels.map((node) => node.getAttribute("data-testid"))).toEqual(
      Array.from({ length: 13 }, (_, index) => `run-panel-${index + 1}`),
    );
    expect(
      screen.getByRole("heading", { name: "fixture-run-001" }),
    ).toBeTruthy();
    expect(screen.getByRole("link", { name: "HTML" })).toHaveProperty(
      "href",
      expect.stringContaining("/v1/runs/fixture-run-001/report.html"),
    );
    expect(screen.getByText("MRI scorecard")).toBeTruthy();
    expect(screen.getByText("Candidate actions")).toBeTruthy();
    expect(screen.getByText("Audit chain")).toBeTruthy();
  });

  it("does not claim failed campaigns are still receiving evidence", () => {
    setCampaign(campaign({ status: "failed", evidence_complete: false }));
    renderPage();
    expect(screen.queryByText(/Evidence is still arriving/)).toBeNull();
    expect(
      screen.getByText(
        "Campaign failed. Recorded partial evidence is preserved.",
      ),
    ).toBeTruthy();
  });

  it("keeps notes and report downloads read-only for viewers", () => {
    mocks.useRoles.mockReturnValue({ roles: { default: "viewer" } });
    const { container } = renderPage();
    const notes = container.querySelector("textarea");
    expect(notes).toHaveProperty("readOnly", true);
    expect(screen.queryByRole("button", { name: "Save notes" })).toBeNull();
    expect(screen.queryByRole("link", { name: "HTML" })).toBeNull();
    expect(screen.getByText("Reviewer notes are read-only for this role.")).toBeTruthy();
  });

  it("labels every recommendation as a candidate with its narrative source", () => {
    renderPage();
    expect(screen.getByText("candidate")).toBeTruthy();
    expect(screen.getByText(/· candidate · rules narrative/)).toBeTruthy();
    expect(screen.queryByText(/not evaluated/)).toBeNull();
    expect(screen.queryByText(/Measured verification/)).toBeNull();
    expect(screen.queryByText(/ΔMRI/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull();
  });

  it("upserts repeated stage events and revalidates campaign evidence", () => {
    renderPage();
    expect(eventHandler).toBeTypeOf("function");
    act(() => {
      eventHandler?.({
        type: "stage",
        name: "attack.execute",
        status: "running",
      });
      eventHandler?.({
        type: "stage",
        name: "attack.execute",
        status: "succeeded",
      });
    });
    expect(screen.getAllByText("attack.execute")).toHaveLength(1);
    expect(mocks.mutate).toHaveBeenCalledTimes(2);
  });

  it("revalidates job frames without inventing a stage", () => {
    renderPage();
    act(() => {
      eventHandler?.({ type: "job", status: "running" });
    });
    expect(screen.queryByText("campaign stage")).toBeNull();
    expect(mocks.mutate).toHaveBeenCalledTimes(1);
  });

  it("recovers the prompts-sent bar of an LLM probe run from the run detail and revalidates it on a job frame", async () => {
    // AE2: the campaign read is 404 (a probe run has no campaign record); the page falls back to
    // GET /v1/runs/{id}, whose stage_table.progress block feeds the header bar. A run id of its own so
    // SWR's global cache cannot serve another case's data.
    const runId = "llm-run-reload-001";
    const detail = {
      id: runId,
      project_id: "default",
      status: "running",
      scanner: "ml.llm_probe",
      mode: "probe",
      created_at: "2026-09-10T12:00:00.000Z",
      completed_at: null,
      stage_table: {
        kind: "llm_probe",
        stages_done: ["load_target", "entitlement"],
        progress: {
          unit: "prompts",
          done: 37,
          total: 64,
          percent: 57,
          probe: "Dan_11_0",
          probes_done: 0,
          n_probes: 2,
          updated_at: new Date().toISOString(),
        },
      },
    };
    mocks.api.mockImplementation(async (path: string) => {
      if (path === `/v1/runs/${runId}`) return detail;
      if (path.endsWith("/llm-scorecard")) return null;
      if (path.endsWith("/artifacts")) return { artifacts: [], count: 0 };
      if (path.startsWith("/v1/findings")) return { findings: [], count: 0 };
      throw new Error(`unexpected api read ${path}`);
    });
    setCampaign(
      undefined,
      new ApiError(404, '{"detail":{"code":"campaign_not_found"}}'),
    );
    render(createElement(RunPage, { params: { id: runId } }));
    const bar = await screen.findByRole("progressbar", { name: "prompts sent" });
    expect(bar.getAttribute("aria-valuenow")).toBe("57");
    expect(
      screen.getByText(/^prompts sent 37 of 64 · probe Dan_11_0 · updated \d+ s ago$/),
    ).toBeTruthy();
    const runReads = () =>
      mocks.api.mock.calls.filter(([path]) => path === `/v1/runs/${runId}`)
        .length;
    expect(runReads()).toBe(1);
    act(() => {
      eventHandler?.({ type: "job", status: "running" });
    });
    await waitFor(() => expect(runReads()).toBe(2));
  });

  it("cancels active campaigns only after confirmation", async () => {
    setCampaign(campaign({ status: "running" }));
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Cancel run" }));
    await waitFor(() =>
      expect(mocks.cancelRun).toHaveBeenCalledWith("fixture-run-001"),
    );
    expect(mocks.mutate).toHaveBeenCalled();
  });

  it("renders a side-by-side comparison with no delta", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText("Compare with run"), {
      target: { value: "prior-run" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(await screen.findByText("Scorecard 1 · fixture-run-001")).toBeTruthy();
    expect(screen.getByText("Scorecard 2 · prior-run")).toBeTruthy();
    expect(screen.getByText(/Changed variables: seed/)).toBeTruthy();
    expect(screen.queryByText(/ΔMRI/)).toBeNull();
    expect(screen.queryByText(/verify/i)).toBeNull();
  });
});
