import { createElement } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api";

const useModels = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "remediator" } }),
}));
vi.mock("@/hooks/useModels", () => ({ useModels }));
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
  beforeEach(() => {
    useModels.mockReturnValue({
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
      mutate: vi.fn(),
    });
  });
  afterEach(() => cleanup());
  it("states that the catalog API is not implemented when /v1/models answers 404", () => {
    useModels.mockReturnValue({
      data: undefined,
      error: new ApiError(404, "Not Found"),
      isLoading: false,
      mutate: vi.fn(),
    });
    render(createElement(ModelsPage));
    expect(
      screen.getByText(/Model catalog not_implemented: GET \/v1\/models is not mounted/),
    ).toBeTruthy();
    expect(screen.queryByText("No registered models")).toBeNull();
  });
  it("renders availability state and disables the endpoint connector", () => {
    render(createElement(ModelsPage));
    expect(screen.getByText("available")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    expect(
      screen.getByRole("button", { name: /connect endpoint/i }),
    ).toHaveProperty("disabled", true);
  });
});
