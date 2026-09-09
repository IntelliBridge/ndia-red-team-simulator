import { createElement } from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
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
    localStorage.clear();
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
  it("shows the average score by category when the model has scored campaigns", () => {
    useModels.mockReturnValue({
      data: [
        { id: "m1", project_id: "default", name: "Model", source: "bundled", modality: "image", format: "onnx",
          sha256: null, manifest: {}, status: "available",
          score_summary: { kind: "mri", n_campaigns: 2, mri_mean: 55.5,
            subscores_mean: { S_acc: 60, S_asr: 51, S_eps: null, S_conf: 70, S_expl: null }, note: "n" } },
        { id: "m2", project_id: "default", name: "Chat", source: "endpoint", modality: "llm", format: "endpoint",
          sha256: null, manifest: { endpoint_kind: "llm" }, status: "available",
          score_summary: { kind: "llm", n_runs: 3, note: "n",
            families: [{ family: "dan", n_hits: 6, n_evaluated: 20, hit_rate: 0.3, n_probes: 2 }] } },
      ],
      isLoading: false,
      mutate: vi.fn(),
    });
    render(createElement(ModelsPage));
    const blocks = screen.getAllByTestId("score-summary");
    expect(blocks).toHaveLength(2);
    expect(blocks[0]!.textContent).toContain("55.5");
    expect(blocks[0]!.textContent).toContain("Accuracy under attack");
    expect(blocks[0]!.textContent).not.toContain("Perturbation budget needed");
    expect(blocks[1]!.textContent).toContain("dan");
    expect(blocks[1]!.textContent).toContain("30%");
  });

  it("switches to a list view and remembers the choice", () => {
    render(createElement(ModelsPage));
    expect(screen.queryByRole("table")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "List" }));
    const table = screen.getByRole("table");
    expect(table.textContent).toContain("Model");
    expect(screen.getByRole("link", { name: "Model" }).getAttribute("href")).toBe("/models/m1");
    expect(localStorage.getItem("redsim_models_view")).toBe("list");
    fireEvent.click(screen.getByRole("button", { name: "Cards" }));
    expect(screen.queryByRole("table")).toBeNull();
    expect(localStorage.getItem("redsim_models_view")).toBe("cards");
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
