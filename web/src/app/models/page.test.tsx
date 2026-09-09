import { createElement } from "react";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
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
  useDatasets: () => ({
    data: [
      {
        id: "d1",
        name: "CIFAR-10 slice",
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
      {
        id: "d2",
        name: "Phishing URLs",
        revision: "r2",
        license: "open",
        source_url: "https://example.invalid",
        classes: [],
        size: 10,
        format: "parquet",
        role: "demo",
        reachability: "recorded",
        compatible_modalities: ["tabular"],
      },
    ],
  }),
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
  it("renders the manifest clean-accuracy block as text (value, n, split)", () => {
    // The live API returns redsim.ml.schema.CleanAccuracy, an object; rendering
    // it as a React child was React error #31 on /models.
    useModels.mockReturnValue({
      data: [
        {
          id: "vehicles_cnn-1234abcd",
          project_id: "demo",
          name: "Vehicles CNN",
          source: "bundled",
          modality: "image",
          format: "torch_state_dict",
          sha256: "432569ef744c",
          manifest: { clean_accuracy: { value: 0.5990129549660703, n: 1621, split: "test_coarse" } },
          status: "available",
        },
        {
          id: "legacy-number",
          project_id: "demo",
          name: "Legacy",
          source: "bundled",
          modality: "image",
          format: "onnx",
          sha256: null,
          manifest: { clean_accuracy: 0.82, clean_n: 50 },
          status: "available",
        },
      ],
      isLoading: false,
      mutate: vi.fn(),
    });
    render(createElement(ModelsPage));
    expect(screen.getByText("0.599 (n=1621, test_coarse)")).toBeTruthy();
    expect(screen.getByText("0.82 (n=50)")).toBeTruthy();
  });
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
  it("lists only image-compatible datasets for artifact uploads", () => {
    render(createElement(ModelsPage));
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    fireEvent.click(screen.getByRole("button", { name: "Upload artifact" }));
    const select = screen.getByLabelText("Evaluation dataset");
    expect(
      within(select).getByRole("option", { name: "CIFAR-10 slice · r1" }),
    ).toBeTruthy();
    expect(
      within(select).queryByRole("option", { name: /Phishing URLs/ }),
    ).toBeNull();
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
