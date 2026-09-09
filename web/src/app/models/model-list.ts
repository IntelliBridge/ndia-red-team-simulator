// Filter and sort for the /models catalog. Pure functions over the rows
// GET /v1/models returns, so the page and its tests share one rule set.

import type { ModelTarget } from "@/lib/api";
import { modelDisplayName } from "@/lib/api";
import { isLlmTarget } from "@/lib/llm";
import {
  coverageNote,
  coverageOf,
  facetValues as facetValuesOf,
  numericOrder,
  stableSort,
  textOrder,
  type Comparator,
  type SortCoverage as Coverage,
  type SortDirection as Direction,
} from "@/lib/list-sort";

export type ModelFilters = {
  /** Case-insensitive match on the display name, the id, or the LLM model id. */
  query: string;
  /** "" for every domain, else image | tabular | text | detection | llm. */
  domain: string;
  /** "" for every status. */
  status: string;
  /** "" for every source. */
  source: string;
};

export const EMPTY_FILTERS: ModelFilters = { query: "", domain: "", status: "", source: "" };

export type SortKey =
  | "name"
  | "domain"
  | "status"
  | "source"
  | "score"
  | "clean_accuracy";

export type SortDirection = Direction;

export type ModelSort = { key: SortKey; direction: SortDirection };

export const DEFAULT_SORT: ModelSort = { key: "name", direction: "asc" };

/** The sort choices offered by the toolbar, in display order. */
export const SORT_OPTIONS: { value: string; label: string; sort: ModelSort }[] = [
  { value: "name:asc", label: "Name A to Z", sort: { key: "name", direction: "asc" } },
  { value: "name:desc", label: "Name Z to A", sort: { key: "name", direction: "desc" } },
  { value: "score:desc", label: "Robustness index, high to low", sort: { key: "score", direction: "desc" } },
  { value: "score:asc", label: "Robustness index, low to high", sort: { key: "score", direction: "asc" } },
  {
    value: "clean_accuracy:desc",
    label: "Clean accuracy, high to low",
    sort: { key: "clean_accuracy", direction: "desc" },
  },
  {
    value: "clean_accuracy:asc",
    label: "Clean accuracy, low to high",
    sort: { key: "clean_accuracy", direction: "asc" },
  },
  { value: "domain:asc", label: "Domain", sort: { key: "domain", direction: "asc" } },
  { value: "status:asc", label: "Status", sort: { key: "status", direction: "asc" } },
  { value: "source:asc", label: "Source", sort: { key: "source", direction: "asc" } },
];

export function sortValue(sort: ModelSort): string {
  return `${sort.key}:${sort.direction}`;
}

export function parseSort(value: string | null | undefined): ModelSort {
  const found = SORT_OPTIONS.find((o) => o.value === value);
  return found ? found.sort : DEFAULT_SORT;
}

/** The domain shown for a row: "llm" for an LLM target, else its modality. */
export function modelDomain(m: ModelTarget): string {
  return isLlmTarget(m) ? "llm" : m.modality;
}

/** The mean robustness index of a scored classifier; null for LLM targets and unscored rows. */
export function modelScore(m: ModelTarget): number | null {
  const s = m.score_summary;
  if (!s || s.kind !== "mri") return null;
  return typeof s.mri_mean === "number" ? s.mri_mean : null;
}

/** The manifest clean accuracy as a number; null when the manifest has none. */
export function modelCleanAccuracy(m: ModelTarget): number | null {
  const acc = m.manifest?.clean_accuracy;
  if (typeof acc === "number") return acc;
  if (acc && typeof acc === "object" && typeof (acc as { value?: unknown }).value === "number") {
    return (acc as { value: number }).value;
  }
  return null;
}

/** Distinct values of one facet across the rows, sorted, for the filter selects. */
export function facetValues(models: ModelTarget[], pick: (m: ModelTarget) => string): string[] {
  return facetValuesOf(models, pick);
}

export function filterModels(models: ModelTarget[], filters: ModelFilters): ModelTarget[] {
  const q = filters.query.trim().toLowerCase();
  return models.filter((m) => {
    if (filters.domain && modelDomain(m) !== filters.domain) return false;
    if (filters.status && m.status !== filters.status) return false;
    if (filters.source && m.source !== filters.source) return false;
    if (!q) return true;
    const modelId = typeof m.manifest?.model_id === "string" ? m.manifest.model_id : "";
    const hay = [modelDisplayName(m), m.name, m.id, modelId].join(" ").toLowerCase();
    return hay.includes(q);
  });
}

export function hasActiveFilters(filters: ModelFilters): boolean {
  return Boolean(filters.query.trim() || filters.domain || filters.status || filters.source);
}

/** The coverage of a numeric sort over the shown rows; null for a text sort. */
export type SortCoverage = Coverage;

export function sortCoverage(models: ModelTarget[], sort: ModelSort): SortCoverage | null {
  if (sort.key === "score") {
    return coverageOf(models, modelScore, "The robustness index", "A scored campaign records it.");
  }
  if (sort.key === "clean_accuracy") {
    return coverageOf(models, modelCleanAccuracy, "Clean accuracy", "The asset manifest records it.");
  }
  return null;
}

/** The toolbar note for a numeric sort; empty when every row can move. */
export function sortCoverageNote(coverage: SortCoverage | null): string {
  return coverageNote(coverage, "model", "name order");
}

/**
 * A stable sort. Text keys compare case-insensitively. Numeric keys put rows
 * without a value last in either direction, so unscored models never lead
 * a "high to low" list. Ties fall back to the display name.
 */
export function sortModels(models: ModelTarget[], sort: ModelSort): ModelTarget[] {
  const byName: Comparator<ModelTarget> = (a, b) =>
    modelDisplayName(a).localeCompare(modelDisplayName(b), undefined, { sensitivity: "base" });
  const compare: Comparator<ModelTarget> = {
    name: (a: ModelTarget, b: ModelTarget) => byName(a, b) * (sort.direction === "asc" ? 1 : -1),
    domain: textOrder(modelDomain, sort.direction, byName),
    status: textOrder((m: ModelTarget) => m.status, sort.direction, byName),
    source: textOrder((m: ModelTarget) => m.source, sort.direction, byName),
    score: numericOrder(modelScore, sort.direction, byName),
    clean_accuracy: numericOrder(modelCleanAccuracy, sort.direction, byName),
  }[sort.key];
  return stableSort(models, compare);
}
