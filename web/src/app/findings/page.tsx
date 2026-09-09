"use client";

// /findings — cross-run findings list.
//
// Fixes the /findings 404 (the nav linked here but only /findings/[id]
// existed). SWR-backed list over GET /v1/findings with a server-side
// severity filter; reuses the design-system Table + SeverityChip so the
// row styling matches the run-detail findings table. Theming is via
// semantic tokens (no hardcoded slate/sky) and the table carries a
// caption + scope for a11y.

import { useEffect, useState } from "react";
import useSWR from "swr";

import { PanelSection } from "@redsim/design-system";
import { api, type Finding } from "@/lib/api";
import { facetValues } from "@/lib/list-sort";
import { FindingSummaryCard } from "@/components/finding-summary-card";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import {
  DEFAULT_FINDING_SORT,
  EMPTY_FINDING_FILTERS,
  FINDING_SORT_OPTIONS,
  filterFindings,
  findingAttack,
  findingModelLabel,
  findingSortCoverage,
  findingSortCoverageNote,
  findingSortValue,
  hasActiveFindingFilters,
  parseFindingSort,
  sortFindings,
  type FindingFilters,
  type FindingSort,
} from "./finding-list";

const fetcher = (path: string) =>
  api<{ findings: Finding[]; count: number }>(path);

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const SORT_KEY = "redsim_findings_sort";

export default function FindingsPage() {
  const authed = useRequireAuth();
  const [severity, setSeverity] = useState<string>("");

  const query = severity
    ? `/v1/findings?severity=${encodeURIComponent(severity)}`
    : "/v1/findings";
  const { data, error, isLoading } = useSWR(authed ? query : null, fetcher);
  // Client-side filters live for the page; the sort order is remembered per browser.
  const [filters, setFilters] = useState<FindingFilters>(EMPTY_FINDING_FILTERS);
  const [sort, setSort] = useState<FindingSort>(DEFAULT_FINDING_SORT);
  useEffect(() => {
    try {
      setSort(parseFindingSort(window.localStorage.getItem(SORT_KEY)));
    } catch {
      // storage unavailable: keep the default
    }
  }, []);
  const chooseSort = (next: FindingSort) => {
    setSort(next);
    try {
      window.localStorage.setItem(SORT_KEY, findingSortValue(next));
    } catch {
      // storage unavailable: the choice lasts for this page only
    }
  };
  const setFilter = (patch: Partial<FindingFilters>) => setFilters((f) => ({ ...f, ...patch }));

  if (!authed)
    return <p className="text-muted-foreground">Signing in…</p>;

  const findings = data?.findings ?? [];
  const statuses = facetValues(findings, (f) => f.status);
  const models = facetValues(findings, findingModelLabel);
  const attacks = facetValues(findings, findingAttack);
  const sources = facetValues(findings, (f) => f.source_tool);
  const shown = sortFindings(filterFindings(findings, filters), sort);
  const filtering = hasActiveFindingFilters(filters);
  const coverageNote = findingSortCoverageNote(findingSortCoverage(shown, sort));
  const selectClass = "rounded-sm border border-input bg-background px-3 py-1.5";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Findings</h1>
      </div>
      <div
        className="flex flex-wrap items-end gap-3 rounded-sm border border-border bg-card p-3 text-sm"
        role="search"
        aria-label="Filter and sort findings"
      >
        <label className="flex min-w-[12rem] flex-1 flex-col gap-1">
          <span className="redsim-kicker">search</span>
          <input
            type="search"
            value={filters.query}
            onChange={(e) => setFilter({ query: e.target.value })}
            placeholder="title, id, run, model, attack or probe"
            className={selectClass}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="redsim-kicker">severity</span>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className={selectClass}
          >
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        {findings.length > 0 && (
          <>
            <label className="flex flex-col gap-1">
              <span className="redsim-kicker">status</span>
              <select value={filters.status} onChange={(e) => setFilter({ status: e.target.value })} className={selectClass}>
                <option value="">All</option>
                {statuses.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="redsim-kicker">model</span>
              <select value={filters.model} onChange={(e) => setFilter({ model: e.target.value })} className={selectClass}>
                <option value="">All</option>
                {models.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="redsim-kicker">attack or probe</span>
              <select value={filters.attack} onChange={(e) => setFilter({ attack: e.target.value })} className={selectClass}>
                <option value="">All</option>
                {attacks.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="redsim-kicker">source</span>
              <select value={filters.source} onChange={(e) => setFilter({ source: e.target.value })} className={selectClass}>
                <option value="">All</option>
                {sources.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="redsim-kicker">sort</span>
              <select
                value={findingSortValue(sort)}
                onChange={(e) => chooseSort(parseFindingSort(e.target.value))}
                className={selectClass}
              >
                {FINDING_SORT_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex flex-wrap items-center gap-3 pb-1.5 text-xs text-muted-foreground">
              <span aria-live="polite" data-testid="findings-count">
                {filtering ? `${shown.length} of ${findings.length}` : findings.length} finding
                {findings.length === 1 ? "" : "s"}
              </span>
              {filtering && (
                <button type="button" className="redsim-ghost px-2 py-1" onClick={() => setFilters(EMPTY_FINDING_FILTERS)}>
                  Clear filters
                </button>
              )}
            </div>
            {coverageNote && (
              <p className="basis-full text-xs text-muted-foreground" role="status" data-testid="sort-coverage">
                {coverageNote}
              </p>
            )}
          </>
        )}
      </div>

      {isLoading && <p className="text-muted-foreground">Loading…</p>}
      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load findings: {String(error)}
        </p>
      )}
      {!isLoading && !error && findings.length === 0 && (
        <p className="text-muted-foreground">
          No findings{severity ? ` at ${severity} severity` : ""} yet.
        </p>
      )}
      {findings.length > 0 && shown.length === 0 && (
        <PanelSection title="No findings match" eyebrow="filtered">
          <p className="text-sm text-muted-foreground">
            No finding matches these filters. Clear a filter to widen the list.
          </p>
        </PanelSection>
      )}
      {shown.length > 0 && (
        <ul className="space-y-3" aria-label="Findings across all accessible runs">
          {shown.map((f: Finding) => (
            <FindingSummaryCard key={f.id} finding={f} />
          ))}
        </ul>
      )}
    </div>
  );
}
