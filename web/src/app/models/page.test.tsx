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
    // Sorted by name, so "Chat" (the LLM row) comes before "Model".
    const blocks = screen.getAllByTestId("score-summary").reverse();
    expect(blocks).toHaveLength(2);
    // Collapsed by default: the headline and the count show, the categories do not.
    expect(blocks[0]!.textContent).toContain("55.5");
    expect(blocks[0]!.textContent).toContain("2 campaigns");
    expect(blocks[0]!.textContent).not.toContain("Accuracy under attack");
    fireEvent.click(blocks[0]!.querySelector("button")!);
    expect(blocks[0]!.textContent).toContain("Accuracy under attack");
    expect(blocks[0]!.textContent).not.toContain("Perturbation budget needed");
    expect(blocks[1]!.textContent).not.toContain("30%");
    fireEvent.click(blocks[1]!.querySelector("button")!);
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

  const catalog = () =>
    useModels.mockReturnValue({
      data: [
        { id: "m1", project_id: "default", name: "Vehicles", source: "bundled", modality: "image", format: "onnx",
          sha256: null, manifest: { clean_accuracy: 0.76 }, status: "available",
          score_summary: { kind: "mri", n_campaigns: 1, mri_mean: 55, subscores_mean: {}, note: "n" } },
        { id: "m2", project_id: "default", name: "URL trees", source: "bundled", modality: "tabular",
          format: "sklearn_joblib", sha256: null, manifest: { clean_accuracy: 0.9 }, status: "available",
          score_summary: { kind: "mri", n_campaigns: 1, mri_mean: 72, subscores_mean: {}, note: "n" } },
        { id: "m3", project_id: "default", name: "Upload", source: "upload", modality: "image", format: "onnx",
          sha256: null, manifest: {}, status: "refused" },
      ],
      isLoading: false,
      mutate: vi.fn(),
    });

  it("filters the catalog by domain, status and text and reports the count", () => {
    catalog();
    render(createElement(ModelsPage));
    expect(screen.getByTestId("models-count").textContent).toBe("3 models");
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
    fireEvent.change(screen.getByLabelText("domain"), { target: { value: "tabular" } });
    expect(screen.getAllByRole("article")).toHaveLength(1);
    expect(screen.getByText("URL trees")).toBeTruthy();
    expect(screen.getByTestId("models-count").textContent).toBe("1 of 3 models");
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getAllByRole("article")).toHaveLength(3);
    fireEvent.change(screen.getByLabelText("status"), { target: { value: "refused" } });
    expect(screen.getAllByRole("article").map((a) => a.textContent)).toEqual([
      expect.stringContaining("Upload"),
    ]);
    fireEvent.change(screen.getByLabelText("search"), { target: { value: "nothing here" } });
    expect(screen.queryAllByRole("article")).toHaveLength(0);
    expect(screen.getByText("No models match")).toBeTruthy();
  });

  it("sorts the cards from the toolbar and remembers the order", () => {
    catalog();
    render(createElement(ModelsPage));
    const names = () => screen.getAllByRole("article").map((a) => a.querySelector(".text-lg")!.textContent);
    expect(names()).toEqual(["Upload", "URL trees", "Vehicles"]);
    fireEvent.change(screen.getByLabelText("sort"), { target: { value: "score:desc" } });
    expect(names()).toEqual(["URL trees", "Vehicles", "Upload"]);
    expect(localStorage.getItem("redsim_models_sort")).toBe("score:desc");
    fireEvent.change(screen.getByLabelText("sort"), { target: { value: "clean_accuracy:asc" } });
    expect(names()).toEqual(["Vehicles", "URL trees", "Upload"]);
  });

  it("says when a numeric sort has too few values to reorder the rows", () => {
    catalog();
    render(createElement(ModelsPage));
    expect(screen.queryByTestId("sort-coverage")).toBeNull();
    fireEvent.change(screen.getByLabelText("sort"), { target: { value: "clean_accuracy:desc" } });
    expect(screen.getByTestId("sort-coverage").textContent).toBe(
      "Clean accuracy is known for 2 of 3 models. Rows without one follow in name order. The asset manifest records it.",
    );
    // Filter down to the one row without a metric: the note says nothing can move.
    fireEvent.change(screen.getByLabelText("status"), { target: { value: "refused" } });
    expect(screen.getByTestId("sort-coverage").textContent).toMatch(/^Clean accuracy is known for 0 of 1 model\. Nothing to order yet/);
    fireEvent.change(screen.getByLabelText("sort"), { target: { value: "name:asc" } });
    expect(screen.queryByTestId("sort-coverage")).toBeNull();
  });

  it("sorts the list view from its column headers", () => {
    catalog();
    localStorage.setItem("redsim_models_view", "list");
    render(createElement(ModelsPage));
    const cells = () =>
      within(screen.getByRole("table")).getAllByRole("link").map((a) => a.textContent);
    expect(cells()).toEqual(["Upload", "URL trees", "Vehicles"]);
    const header = screen.getByRole("columnheader", { name: /^Name/ });
    expect(header.getAttribute("aria-sort")).toBe("ascending");
    fireEvent.click(within(header).getByRole("button"));
    expect(header.getAttribute("aria-sort")).toBe("descending");
    expect(cells()).toEqual(["Vehicles", "URL trees", "Upload"]);
    const source = screen.getByRole("columnheader", { name: /^Source/ });
    fireEvent.click(within(source).getByRole("button"));
    expect(source.getAttribute("aria-sort")).toBe("ascending");
    expect(cells()).toEqual(["URL trees", "Vehicles", "Upload"]);
    expect(screen.getByRole("columnheader", { name: /^Name/ }).getAttribute("aria-sort")).toBe("none");
    expect((screen.getByLabelText("sort") as HTMLSelectElement).value).toBe("source:asc");
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
    // The status chip on the card; the status filter offers the same word as an option.
    expect(within(screen.getByRole("article")).getByText("available")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Add model" }));
    expect(
      screen.getByRole("button", { name: /connect endpoint/i }),
    ).toHaveProperty("disabled", true);
  });
});
