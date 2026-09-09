import { describe, expect, it } from "vitest";
import type { Finding } from "@/lib/api";
import {
  EMPTY_FINDING_FILTERS,
  filterFindings,
  findingAsr,
  findingAttack,
  findingFirstEps,
  findingModelLabel,
  findingSortCoverage,
  findingSortCoverageNote,
  findingSortValue,
  hasActiveFindingFilters,
  parseFindingSort,
  severityRank,
  sortFindings,
} from "./finding-list";

function row(over: Partial<Finding> & { id: string }): Finding {
  return {
    run_id: `run-${over.id}`,
    project_id: "default",
    severity: "medium",
    status: "open",
    source_tool: "ml-campaign",
    validation_state: "unvalidated",
    dedup_key: null,
    schema_blob: {},
    ...over,
  } as Finding;
}

const pgd = row({
  id: "f-1",
  schema_blob: {
    title: "PGD flips vehicles",
    target: "bundled:vehicles_cnn",
    affected_component: "vehicles_cnn-1",
    ml: { attack_id: "pgd", asr_at_reference: 0.62, first_success_eps: 0.03 } as never,
  },
});
const fgsm = row({
  id: "f-2",
  severity: "critical",
  schema_blob: {
    title: "FGSM flips URL trees",
    target: "bundled:url_trees",
    ml: { attack_id: "fgsm", asr_at_reference: 0.91, first_success_eps: 0.01 } as never,
  },
});
const dan = row({
  id: "f-3",
  severity: "low",
  status: "false_positive",
  source_tool: "ml-llm-probe",
  schema_blob: {
    title: "DAN jailbreak",
    target: "openai/gpt-4o via pythia.example (red)",
    llm: { probe_id: "dan.Dan_11_0", n_hits: 2, n_evaluated: 20 },
  },
});
const bare = row({ id: "f-4", severity: "weird", source_tool: null, schema_blob: {} });
const all = [pgd, fgsm, dan, bare];

describe("finding-list", () => {
  it("reads the facets and metrics off a row", () => {
    expect(severityRank(fgsm)).toBe(4);
    expect(severityRank(bare)).toBe(-1);
    expect(findingModelLabel(pgd)).toBe("vehicles_cnn");
    expect(findingModelLabel(dan)).toBe("openai/gpt-4o");
    expect(findingModelLabel(bare)).toBe("");
    expect(findingAttack(pgd)).toBe("pgd");
    expect(findingAttack(dan)).toBe("dan.Dan_11_0");
    expect(findingAttack(bare)).toBe("");
    expect(findingAsr(fgsm)).toBe(0.91);
    expect(findingAsr(dan)).toBe(0.1);
    expect(findingAsr(bare)).toBeNull();
    expect(findingFirstEps(pgd)).toBe(0.03);
    expect(findingFirstEps(dan)).toBeNull();
  });

  it("filters by status, model, attack, source and a text query", () => {
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, status: "false_positive" })).toEqual([dan]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, model: "url_trees" })).toEqual([fgsm]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, attack: "pgd" })).toEqual([pgd]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, source: "ml-llm-probe" })).toEqual([dan]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, query: " URL " })).toEqual([fgsm]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, query: "run-f-4" })).toEqual([bare]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, query: "gpt-4o" })).toEqual([dan]);
    expect(filterFindings(all, { ...EMPTY_FINDING_FILTERS, query: "zzz" })).toEqual([]);
    expect(hasActiveFindingFilters(EMPTY_FINDING_FILTERS)).toBe(false);
    expect(hasActiveFindingFilters({ ...EMPTY_FINDING_FILTERS, query: "  " })).toBe(false);
    expect(hasActiveFindingFilters({ ...EMPTY_FINDING_FILTERS, model: "x" })).toBe(true);
  });

  it("sorts by severity with a title tie-break, in both directions", () => {
    const ids = (rows: Finding[]) => rows.map((f) => f.id);
    expect(ids(sortFindings(all, { key: "severity", direction: "desc" }))).toEqual(["f-2", "f-1", "f-3", "f-4"]);
    expect(ids(sortFindings(all, { key: "severity", direction: "asc" }))).toEqual(["f-4", "f-3", "f-1", "f-2"]);
    expect(ids(all)).toEqual(["f-1", "f-2", "f-3", "f-4"]);
  });

  it("sorts text keys and falls back to severity", () => {
    const ids = (rows: Finding[]) => rows.map((f) => f.id);
    expect(ids(sortFindings(all, { key: "title", direction: "asc" }))).toEqual(["f-3", "f-4", "f-2", "f-1"]);
    // Two open rows tie on status: the critical one leads.
    expect(ids(sortFindings(all, { key: "status", direction: "asc" }))).toEqual(["f-3", "f-2", "f-1", "f-4"]);
  });

  it("puts rows without a metric last in either numeric direction", () => {
    const ids = (rows: Finding[]) => rows.map((f) => f.id);
    expect(ids(sortFindings(all, { key: "asr", direction: "desc" }))).toEqual(["f-2", "f-1", "f-3", "f-4"]);
    expect(ids(sortFindings(all, { key: "asr", direction: "asc" }))).toEqual(["f-3", "f-1", "f-2", "f-4"]);
    expect(ids(sortFindings(all, { key: "first_eps", direction: "asc" }))).toEqual(["f-2", "f-1", "f-3", "f-4"]);
    expect(ids(sortFindings(all, { key: "first_eps", direction: "desc" }))).toEqual(["f-1", "f-2", "f-3", "f-4"]);
  });

  it("reports the coverage of a numeric sort", () => {
    expect(findingSortCoverage(all, { key: "title", direction: "asc" })).toBeNull();
    const asr = findingSortCoverage(all, { key: "asr", direction: "desc" });
    expect(asr).toMatchObject({ withValue: 3, total: 4 });
    expect(findingSortCoverageNote(asr)).toBe(
      "The attack success rate is known for 3 of 4 findings. Rows without one follow in severity order. An attack campaign or a probe run records it.",
    );
    expect(findingSortCoverageNote(findingSortCoverage([bare], { key: "first_eps", direction: "asc" }))).toMatch(
      /^The first successful eps is known for 0 of 1 finding\. Nothing to order yet/,
    );
    expect(findingSortCoverageNote(findingSortCoverage([pgd, fgsm], { key: "asr", direction: "asc" }))).toBe("");
  });

  it("round-trips the sort value and falls back to the default", () => {
    expect(findingSortValue(parseFindingSort("asr:desc"))).toBe("asr:desc");
    expect(parseFindingSort("bogus")).toEqual({ key: "severity", direction: "desc" });
    expect(parseFindingSort(null)).toEqual({ key: "severity", direction: "desc" });
  });
});
