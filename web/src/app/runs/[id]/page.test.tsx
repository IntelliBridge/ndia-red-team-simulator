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
  api: vi.fn(),
  useCampaign: vi.fn(),
  useRequireAuth: vi.fn(),
  useRoles: vi.fn(),
  useRunEvents: vi.fn(),
  mutate: vi.fn(),
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

function renderPage(id = "fixture-run-001") {
  return render(createElement(RunPage, { params: { id } }));
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

describe("/runs/[id] runs without a campaign record", () => {
  function notFound() {
    return new ApiError(404, JSON.stringify({ detail: { code: "campaign_not_found" } }));
  }

  it("shows a model validation run instead of 'Campaign not found'", async () => {
    setCampaign(undefined, notFound());
    mocks.api.mockResolvedValue({
      id: "ingest-run-001",
      project_id: "default",
      status: "succeeded",
      scanner: "ml.ingest",
      mode: "api",
      created_at: "2026-09-10T12:22:55Z",
      completed_at: "2026-09-10T12:23:01Z",
      stage_table: {},
    });
    renderPage("ingest-run-001");
    expect(await screen.findByTestId("run-fallback")).toBeTruthy();
    expect(screen.getByText("model validation")).toBeTruthy();
    expect(screen.getByText(/not an attack campaign/)).toBeTruthy();
    expect(screen.queryByText("Campaign not found.")).toBeNull();
  });

  it("shows a failed campaign's error and stages, never a scorecard", async () => {
    setCampaign(undefined, notFound());
    mocks.api.mockResolvedValue({
      id: "failed-run-001",
      project_id: "default",
      status: "failed",
      scanner: "ml.campaign",
      mode: "api",
      created_at: "2026-09-10T04:53:42Z",
      completed_at: "2026-09-10T05:10:00Z",
      stage_table: {
        error: "SandboxKilled: ML sandbox child died with signal SIGKILL",
        stages: {
          load_target: { status: "succeeded" },
          "attack:pgd": { status: "failed" },
        },
      },
    });
    renderPage("failed-run-001");
    expect(await screen.findByTestId("run-fallback")).toBeTruthy();
    expect(screen.getByText(/did not complete/)).toBeTruthy();
    expect(screen.getByTestId("run-fallback-error").textContent).toContain(
      "SandboxKilled",
    );
    expect(screen.queryByText("MRI scorecard")).toBeNull();
  });

  it("says a running campaign is still running", async () => {
    setCampaign(undefined, notFound());
    mocks.api.mockResolvedValue({
      id: "running-run-001",
      project_id: "default",
      status: "running",
      scanner: "ml.campaign",
      mode: "api",
      created_at: "2026-09-10T12:30:52Z",
      completed_at: null,
      stage_table: { stages: { load_target: { status: "running" } } },
    });
    renderPage("running-run-001");
    expect(await screen.findByTestId("run-fallback")).toBeTruthy();
    expect(screen.getByText(/still running/)).toBeTruthy();
  });
});
