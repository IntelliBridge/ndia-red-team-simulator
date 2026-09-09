import { describe, expect, it } from "vitest";
import type { ModelTarget } from "@/lib/api";
import {
  EMPTY_FILTERS,
  facetValues,
  filterModels,
  hasActiveFilters,
  modelCleanAccuracy,
  modelDomain,
  modelScore,
  parseSort,
  sortModels,
  sortValue,
} from "./model-list";

function row(over: Partial<ModelTarget> & { id: string }): ModelTarget {
  return {
    project_id: "default",
    name: over.id,
    source: "bundled",
    modality: "image",
    format: "onnx",
    sha256: null,
    manifest: {},
    status: "available",
    ...over,
  } as ModelTarget;
}

const vehicles = row({
  id: "vehicles_cnn-1",
  name: "Vehicles CNN",
  manifest: { clean_accuracy: { value: 0.7687, n: 1621 } },
  score_summary: { kind: "mri", n_campaigns: 2, mri_mean: 55.5, subscores_mean: {}, note: "n" },
});
const urls = row({
  id: "url_trees-1",
  name: "URL trees",
  modality: "tabular",
  format: "sklearn_joblib",
  manifest: { clean_accuracy: 0.9087 },
  score_summary: { kind: "mri", n_campaigns: 1, mri_mean: 72, subscores_mean: {}, note: "n" },
});
const upload = row({
  id: "up-1",
  name: "analyst upload",
  source: "upload",
  status: "refused",
});
const chat = row({
  id: "llm-1",
  name: "Chat",
  source: "endpoint",
  modality: "llm",
  format: "endpoint",
  manifest: { endpoint_kind: "llm", model_id: "openai/gpt-4o" },
  score_summary: { kind: "llm", n_runs: 1, families: [], note: "n" },
});
const all = [vehicles, urls, upload, chat];

describe("model-list", () => {
  it("reads the domain, score and clean accuracy off a row", () => {
    expect(modelDomain(chat)).toBe("llm");
    expect(modelDomain(urls)).toBe("tabular");
    expect(modelScore(vehicles)).toBe(55.5);
    expect(modelScore(chat)).toBeNull();
    expect(modelScore(upload)).toBeNull();
    expect(modelCleanAccuracy(vehicles)).toBe(0.7687);
    expect(modelCleanAccuracy(urls)).toBe(0.9087);
    expect(modelCleanAccuracy(upload)).toBeNull();
  });

  it("derives sorted facet values from the rows", () => {
    expect(facetValues(all, modelDomain)).toEqual(["image", "llm", "tabular"]);
    expect(facetValues(all, (m) => m.status)).toEqual(["available", "refused"]);
    expect(facetValues(all, (m) => m.source)).toEqual(["bundled", "endpoint", "upload"]);
  });

  it("filters by domain, status, source and a text query", () => {
    expect(filterModels(all, { ...EMPTY_FILTERS, domain: "llm" })).toEqual([chat]);
    expect(filterModels(all, { ...EMPTY_FILTERS, status: "refused" })).toEqual([upload]);
    expect(filterModels(all, { ...EMPTY_FILTERS, source: "bundled" })).toEqual([vehicles, urls]);
    expect(filterModels(all, { ...EMPTY_FILTERS, query: "  URL " })).toEqual([urls]);
    expect(filterModels(all, { ...EMPTY_FILTERS, query: "gpt-4o" })).toEqual([chat]);
    expect(filterModels(all, { ...EMPTY_FILTERS, query: "up-1" })).toEqual([upload]);
    expect(filterModels(all, { ...EMPTY_FILTERS, query: "zzz" })).toEqual([]);
    expect(filterModels(all, { ...EMPTY_FILTERS, domain: "image", source: "upload" })).toEqual([upload]);
  });

  it("knows when a filter is active", () => {
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, query: "   " })).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, status: "available" })).toBe(true);
  });

  it("sorts by name in both directions without mutating the input", () => {
    const asc = sortModels(all, { key: "name", direction: "asc" });
    expect(asc.map((m) => m.id)).toEqual(["up-1", "llm-1", "url_trees-1", "vehicles_cnn-1"]);
    const desc = sortModels(all, { key: "name", direction: "desc" });
    expect(desc.map((m) => m.id)).toEqual(["vehicles_cnn-1", "url_trees-1", "llm-1", "up-1"]);
    expect(all.map((m) => m.id)).toEqual(["vehicles_cnn-1", "url_trees-1", "up-1", "llm-1"]);
  });

  it("puts unscored rows last for a numeric sort in either direction", () => {
    const desc = sortModels(all, { key: "score", direction: "desc" });
    expect(desc.map((m) => m.id)).toEqual(["url_trees-1", "vehicles_cnn-1", "up-1", "llm-1"]);
    const asc = sortModels(all, { key: "score", direction: "asc" });
    expect(asc.map((m) => m.id)).toEqual(["vehicles_cnn-1", "url_trees-1", "up-1", "llm-1"]);
    const acc = sortModels(all, { key: "clean_accuracy", direction: "desc" });
    expect(acc.map((m) => m.id)).toEqual(["url_trees-1", "vehicles_cnn-1", "up-1", "llm-1"]);
  });

  it("sorts text facets and breaks ties by name", () => {
    const byDomain = sortModels(all, { key: "domain", direction: "asc" });
    expect(byDomain.map((m) => m.id)).toEqual(["up-1", "vehicles_cnn-1", "llm-1", "url_trees-1"]);
    const bySource = sortModels(all, { key: "source", direction: "desc" });
    expect(bySource.map((m) => m.id)).toEqual(["up-1", "llm-1", "url_trees-1", "vehicles_cnn-1"]);
  });

  it("round-trips the sort value and falls back to the default", () => {
    expect(sortValue(parseSort("score:desc"))).toBe("score:desc");
    expect(parseSort("bogus")).toEqual({ key: "name", direction: "asc" });
    expect(parseSort(null)).toEqual({ key: "name", direction: "asc" });
  });
});
