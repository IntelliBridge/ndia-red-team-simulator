// Filter and sort for the /findings list. Pure functions over the rows
// GET /v1/findings returns, so the page and its tests share one rule set.
// Severity stays a server-side filter (the SWR key); everything here runs on
// the rows already fetched.

import type { Finding } from "@/lib/api";
import { findingModel } from "@/lib/finding-description";
import {
  coverageNote,
  coverageOf,
  numericOrder,
  stableSort,
  textOrder,
  type Comparator,
  type SortCoverage,
  type SortDirection,
} from "@/lib/list-sort";

export type FindingFilters = {
  /** Case-insensitive match on the title, the ids, the model, the attack or probe. */
  query: string;
  /** "" for every status. */
  status: string;
  /** "" for every model label. */
  model: string;
  /** "" for every attack or probe id. */
  attack: string;
  /** "" for every source tool. */
  source: string;
};

export const EMPTY_FINDING_FILTERS: FindingFilters = { query: "", status: "", model: "", attack: "", source: "" };

export type FindingSortKey = "severity" | "title" | "status" | "model" | "attack" | "asr" | "first_eps";

export type FindingSort = { key: FindingSortKey; direction: SortDirection };

export const DEFAULT_FINDING_SORT: FindingSort = { key: "severity", direction: "desc" };

/** The sort choices offered by the toolbar, in display order. */
export const FINDING_SORT_OPTIONS: { value: string; label: string; sort: FindingSort }[] = [
  { value: "severity:desc", label: "Severity, high to low", sort: { key: "severity", direction: "desc" } },
  { value: "severity:asc", label: "Severity, low to high", sort: { key: "severity", direction: "asc" } },
  { value: "title:asc", label: "Title A to Z", sort: { key: "title", direction: "asc" } },
  { value: "title:desc", label: "Title Z to A", sort: { key: "title", direction: "desc" } },
  { value: "asr:desc", label: "Attack success rate, high to low", sort: { key: "asr", direction: "desc" } },
  { value: "asr:asc", label: "Attack success rate, low to high", sort: { key: "asr", direction: "asc" } },
  { value: "first_eps:asc", label: "First successful eps, low to high", sort: { key: "first_eps", direction: "asc" } },
  { value: "first_eps:desc", label: "First successful eps, high to low", sort: { key: "first_eps", direction: "desc" } },
  { value: "status:asc", label: "Status", sort: { key: "status", direction: "asc" } },
  { value: "model:asc", label: "Model", sort: { key: "model", direction: "asc" } },
  { value: "attack:asc", label: "Attack or probe", sort: { key: "attack", direction: "asc" } },
];

export function findingSortValue(sort: FindingSort): string {
  return `${sort.key}:${sort.direction}`;
}

export function parseFindingSort(value: string | null | undefined): FindingSort {
  const found = FINDING_SORT_OPTIONS.find((o) => o.value === value);
  return found ? found.sort : DEFAULT_FINDING_SORT;
}

/** Severity as a rank for ordering; an unknown label sorts below `info`. */
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function severityRank(f: Finding): number {
  return SEVERITY_RANK[f.severity] ?? -1;
}

export function findingTitle(f: Finding): string {
  return f.schema_blob.title ?? f.id;
}

/** The model label the card shows; "" when the finding names none. */
export function findingModelLabel(f: Finding): string {
  return findingModel(f.schema_blob)?.label ?? "";
}

/** The attack id of an ML finding or the probe id of an LLM finding; "" when neither. */
export function findingAttack(f: Finding): string {
  return f.schema_blob.ml?.attack_id ?? f.schema_blob.attack_id ?? f.schema_blob.llm?.probe_id ?? "";
}

/**
 * The attack success rate at the reference eps of an ML finding, or the hit
 * rate (hits over evaluated replies) of an LLM finding, in [0, 1]; null when
 * the finding records neither.
 */
export function findingAsr(f: Finding): number | null {
  const ml = f.schema_blob.ml;
  if (ml && typeof ml.asr_at_reference === "number") return ml.asr_at_reference;
  const llm = f.schema_blob.llm;
  if (llm && typeof llm.n_hits === "number" && typeof llm.n_evaluated === "number" && llm.n_evaluated > 0) {
    return llm.n_hits / llm.n_evaluated;
  }
  return null;
}

/** The smallest eps at which the attack first succeeded; null when it never did or is not recorded. */
export function findingFirstEps(f: Finding): number | null {
  const fromMl = f.schema_blob.ml?.first_success_eps;
  if (typeof fromMl === "number") return fromMl;
  const fromBlob = f.schema_blob.first_success_eps;
  return typeof fromBlob === "number" ? fromBlob : null;
}

export function filterFindings(findings: Finding[], filters: FindingFilters): Finding[] {
  const q = filters.query.trim().toLowerCase();
  return findings.filter((f) => {
    if (filters.status && f.status !== filters.status) return false;
    if (filters.model && findingModelLabel(f) !== filters.model) return false;
    if (filters.attack && findingAttack(f) !== filters.attack) return false;
    if (filters.source && (f.source_tool ?? "") !== filters.source) return false;
    if (!q) return true;
    const hay = [findingTitle(f), f.id, f.run_id, findingModelLabel(f), findingAttack(f), f.source_tool ?? ""]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

export function hasActiveFindingFilters(filters: FindingFilters): boolean {
  return Boolean(filters.query.trim() || filters.status || filters.model || filters.attack || filters.source);
}

/** The coverage of a numeric sort over the shown rows; null for a text sort. */
export function findingSortCoverage(findings: Finding[], sort: FindingSort): SortCoverage | null {
  if (sort.key === "asr") {
    return coverageOf(
      findings,
      findingAsr,
      "The attack success rate",
      "An attack campaign or a probe run records it.",
    );
  }
  if (sort.key === "first_eps") {
    return coverageOf(
      findings,
      findingFirstEps,
      "The first successful eps",
      "An attack campaign records it when an attack succeeds on the grid.",
    );
  }
  return null;
}

export function findingSortCoverageNote(coverage: SortCoverage | null): string {
  return coverageNote(coverage, "finding", "severity order");
}

/**
 * A stable sort. Severity is the tie-break for every other key, then the
 * title, so equal rows keep a readable order; numeric keys put rows without
 * a value last in either direction.
 */
export function sortFindings(findings: Finding[], sort: FindingSort): Finding[] {
  const byTitle: Comparator<Finding> = (a, b) =>
    findingTitle(a).localeCompare(findingTitle(b), undefined, { sensitivity: "base" });
  const bySeverity: Comparator<Finding> = (a, b) => severityRank(b) - severityRank(a) || byTitle(a, b);
  const compare: Comparator<Finding> = {
    severity: (a: Finding, b: Finding) =>
      (severityRank(a) - severityRank(b)) * (sort.direction === "asc" ? 1 : -1) || byTitle(a, b),
    title: textOrder(findingTitle, sort.direction, bySeverity),
    status: textOrder((f: Finding) => f.status, sort.direction, bySeverity),
    model: textOrder(findingModelLabel, sort.direction, bySeverity),
    attack: textOrder(findingAttack, sort.direction, bySeverity),
    asr: numericOrder(findingAsr, sort.direction, bySeverity),
    first_eps: numericOrder(findingFirstEps, sort.direction, bySeverity),
  }[sort.key];
  return stableSort(findings, compare);
}
