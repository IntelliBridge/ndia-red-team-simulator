import { createElement } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "remediator" } }),
}));
vi.mock("@/hooks/useModels", () => ({
  useModels: () => ({
    data: [
      {
        id: "m1",
        project_id: "default",
        name: "Model",
        source: "bundled",
        modality: "image",
        format: "onnx",
        sha256: null,
        manifest: {},
        status: "available",
      },
    ],
    isLoading: false,
  }),
}));
vi.mock("@/hooks/useMlCatalog", () => ({
  useCapabilities: () => ({
    data: {
      endpoint_connector: {
        status: "not_implemented",
        reason: "Phase B connector is not implemented.",
        phase: "B",
      },
    },
  }),
  useDatasets: () => ({ data: [] }),
}));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

import ModelsPage from "./page";

describe("/models", () => {
  it("renders availability state and disables the endpoint connector", () => {
    render(createElement(ModelsPage));
    expect(screen.getByText("available")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    expect(
      screen.getByRole("button", { name: /connect endpoint/i }),
    ).toHaveProperty("disabled", true);
  });
});
