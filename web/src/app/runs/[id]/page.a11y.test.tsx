import { createElement } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";

import campaign from "@/__fixtures__/campaign.json";

// The campaign read and the API client are swapped per case: the first render
// is the image campaign fixture, the second an LLM probe run whose campaign
// read is 404 so the page falls back to GET /v1/runs/{id} and its
// stage_table.progress block.
const state = vi.hoisted(() => ({
  campaign: undefined as unknown,
  error: undefined as unknown,
  api: async (path: string): Promise<unknown> => {
    throw new Error(`unexpected api read ${path}`);
  },
}));

vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: () => true,
}));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "approver" } }),
}));
vi.mock("@/hooks/useCampaign", () => ({
  useCampaign: () => ({ data: state.campaign, error: state.error, mutate: vi.fn() }),
}));
vi.mock("@/hooks/useRunEvents", () => ({
  useRunEvents: () => undefined,
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  api: (path: string) => state.api(path),
  artifactUrl: (id: string) => `/v1/artifacts/${id}`,
  reportUrl: (id: string, ext: string) => `/v1/runs/${id}/report.${ext}`,
}));

import { ApiError } from "@/lib/api";
import RunPage from "./page";

beforeEach(() => {
  state.campaign = campaign;
  state.error = undefined;
});

afterEach(() => cleanup());

it("has no obvious accessibility violations", async () => {
  const { container } = render(
    createElement(RunPage, { params: { id: "fixture-run-001" } }),
  );
  expect((await axe(container)).violations).toHaveLength(0);
});

it("has no obvious accessibility violations on an LLM probe run with a progress bar", async () => {
  const runId = "llm-run-a11y-001";
  state.campaign = undefined;
  state.error = new ApiError(404, '{"detail":{"code":"campaign_not_found"}}');
  state.api = async (path: string) => {
    if (path === `/v1/runs/${runId}`) {
      return {
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
    }
    if (path.endsWith("/llm-scorecard")) return null;
    if (path.endsWith("/artifacts")) return { artifacts: [], count: 0 };
    if (path.startsWith("/v1/findings")) return { findings: [], count: 0 };
    throw new Error(`unexpected api read ${path}`);
  };
  const { container } = render(
    createElement(RunPage, { params: { id: runId } }),
  );
  const bar = await screen.findByRole("progressbar", { name: "prompts sent" });
  expect(bar.getAttribute("aria-valuenow")).toBe("57");
  expect((await axe(container)).violations).toHaveLength(0);
});
