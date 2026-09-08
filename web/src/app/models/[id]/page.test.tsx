import { createElement } from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { p1: "scanner" } }),
}));
vi.mock("@/hooks/useModel", () => ({
  useModel: () => ({
    data: {
      id: "m1",
      project_id: "p1",
      name: "Model",
      source: "bundled",
      modality: "image",
      format: "onnx",
      sha256: null,
      manifest: { dataset_id: "d1", dataset_revision: "r1" },
      status: "available",
    },
  }),
}));
vi.mock("@/hooks/useMlCatalog", () => ({
  useAttacks: () => ({
    data: [
      {
        id: "fgsm",
        name: "FGSM",
        domain: "image",
        family: "evasion",
        description: "",
        params_schema: [],
        references: [],
        phase: "A",
        access: "white-box",
        requires_gradients: true,
        status: "available",
      },
    ],
  }),
  useDatasets: () => ({
    data: [
      {
        id: "d1",
        name: "CIFAR-10",
        revision: "r1",
        license: "open",
        source_url: "https://example.invalid",
        classes: [],
        size: 10,
        format: "parquet",
        role: "ci_fixture",
        reachability: "recorded",
        compatible_modalities: ["image"],
      },
    ],
  }),
  useDefenses: () => ({ data: [] }),
  useCapabilities: () => ({
    data: {
      worker_ml_extra: true,
      sandbox_enabled: true,
      llm_narrative: { configured: false },
    },
  }),
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  startCampaign: vi.fn(),
}));
import ModelPage from "./page";
describe("model launcher", () => {
  it("renders server attack and editable campaign controls", () => {
    render(createElement(ModelPage, { params: { id: "m1" } }));
    expect(screen.getByText("FGSM")).toBeTruthy();
    expect(screen.getByText(/scoring weights/i)).toBeTruthy();
    const samples = screen.getByLabelText("Samples");
    expect(samples.getAttribute("min")).toBe("50");
    expect(samples.getAttribute("max")).toBe("500");
    expect(
      screen.getAllByText(/CI fixture — not the demo dataset/).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", { name: /start campaign/i }),
    ).toBeTruthy();
  });
});
