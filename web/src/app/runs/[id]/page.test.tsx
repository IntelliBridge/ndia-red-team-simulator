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
  useDefenses: vi.fn(),
  mutate: vi.fn(),
  cancelRun: vi.fn(),
  compareRuns: vi.fn(),
  dismissFinding: vi.fn(),
  patchReviewerNotes: vi.fn(),
  startCampaign: vi.fn(),
  verifyFinding: vi.fn(),
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
vi.mock("@/hooks/useMlCatalog", () => ({
  useDefenses: mocks.useDefenses,
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  cancelRun: mocks.cancelRun,
  compareRuns: mocks.compareRuns,
  dismissFinding: mocks.dismissFinding,
  patchReviewerNotes: mocks.patchReviewerNotes,
  startCampaign: mocks.startCampaign,
  verifyFinding: mocks.verifyFinding,
  artifactUrl: (id: string) => `/v1/artifacts/${id}`,
  reportUrl: (id: string, ext: string) => `/v1/runs/${id}/report.${ext}`,
}));

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
  mocks.useDefenses.mockReturnValue({
    data: [
      {
        id: "jpeg",
        name: "JPEG preprocessing",
        status: "available",
        modalities: ["image"],
      },
    ],
  });
  mocks.useRunEvents.mockImplementation(
    (_id: string | null, onEvent: (event: RunEvent) => void) => {
      eventHandler = onEvent;
    },
  );
  mocks.cancelRun.mockResolvedValue({});
  mocks.verifyFinding.mockResolvedValue({});
  mocks.compareRuns.mockResolvedValue({
    compatible: true,
    mode: "verify_delta",
    delta_mri: 4.2,
    delta_dimensions: { S_asr: 0.08 },
    delta_families: [],
    changed_variables: ["defense"],
    unchanged_variables: ["seed", "n_samples", "eps_grid"],
    caveats: ["Same campaign settings."],
  });
  setCampaign(campaign());
});

afterEach(() => cleanup());

describe("/runs/[id] campaign review", () => {
  it("keeps the authenticated guard and a non-claiming loading state", () => {
    mocks.useRequireAuth.mockReturnValue(false);
    setCampaign(undefined);
    renderPage();
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();

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

  it("verifies only recommendations linked to a real finding id", async () => {
    const unlinked = campaign();
    setCampaign(unlinked);
    const first = renderPage();
    expect(
      screen.getByText(/no finding is linked to this recommendation/),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Verify" })).toHaveProperty(
      "disabled",
      true,
    );

    first.unmount();
    const linked = campaign();
    (linked.recommendations[0] as typeof linked.recommendations[0] & {
      finding_id: string;
    }).finding_id = "finding-1";
    setCampaign(linked);
    renderPage();
    fireEvent.change(
      screen.getByLabelText("Defense for Evaluate input preprocessing"),
      { target: { value: "jpeg" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() =>
      expect(mocks.verifyFinding).toHaveBeenCalledWith(
        "finding-1",
        "jpeg",
        {},
        "r.1",
      ),
    );
    expect(mocks.mutate).toHaveBeenCalled();
  });

  it("labels a recommendation as measured only when that candidate has a measured record", () => {
    const measured = campaign();
    const recommendation = measured.recommendations[0] as
      (typeof measured.recommendations)[number] & {
        measured?: {
          delta_mri: number;
          delta_asr: number;
          baseline_run_id: string;
          verify_run_id: string;
        };
      };
    recommendation.validation = "measured";
    recommendation.measured = {
      delta_mri: 3.1,
      delta_asr: -0.08,
      baseline_run_id: "baseline-run",
      verify_run_id: "verify-run",
    };
    setCampaign(measured);
    renderPage();
    expect(
      screen.getByText(
        "candidate · measured ΔMRI +3.1 at these settings",
      ),
    ).toBeTruthy();
    expect(screen.queryByText("candidate · not evaluated")).toBeNull();
    expect(screen.getByText(/Measured verification ΔMRI 3.1/)).toBeTruthy();
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

  it("renders measured comparison evidence rather than a compatibility label", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText("Compare with run"), {
      target: { value: "prior-run" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(
      await screen.findByText("Measured verify comparison"),
    ).toBeTruthy();
    expect(screen.getByText("ΔMRI 4.2")).toBeTruthy();
    expect(screen.getByText("S_asr: 0.08")).toBeTruthy();
  });
});