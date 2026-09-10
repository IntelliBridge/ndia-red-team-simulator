import { createElement } from "react";
import { render } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { axe } from "vitest-axe";

import campaign from "@/__fixtures__/campaign.json";

vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: () => true,
}));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "approver" } }),
}));
vi.mock("@/hooks/useCampaign", () => ({
  useCampaign: () => ({ data: campaign, mutate: vi.fn() }),
}));
vi.mock("@/hooks/useRunEvents", () => ({
  useRunEvents: () => undefined,
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  artifactUrl: (id: string) => `/v1/artifacts/${id}`,
  reportUrl: (id: string, ext: string) => `/v1/runs/${id}/report.${ext}`,
}));

import RunPage from "./page";

it("has no obvious accessibility violations", async () => {
  const { container } = render(
    createElement(RunPage, { params: { id: "fixture-run-001" } }),
  );
  expect((await axe(container)).violations).toHaveLength(0);
});