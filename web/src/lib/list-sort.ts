// Shared sort rules for the catalog pages (/models, /findings). Pure
// functions, so a page and its tests read the same definitions.

export type SortDirection = "asc" | "desc";

export type Comparator<T> = (a: T, b: T) => number;

/** Case-insensitive text order on a picked string; ties fall to `tie`. */
export function textOrder<T>(pick: (row: T) => string, dir: SortDirection, tie: Comparator<T>): Comparator<T> {
  const sign = dir === "asc" ? 1 : -1;
  return (a, b) => {
    const cmp = pick(a).localeCompare(pick(b), undefined, { sensitivity: "base" });
    return cmp !== 0 ? cmp * sign : tie(a, b);
  };
}

/**
 * Numeric order on a picked value. Rows without a value go last in either
 * direction, so an unscored row never leads a "high to low" list; ties and
 * value-less pairs fall to `tie`.
 */
export function numericOrder<T>(
  pick: (row: T) => number | null,
  dir: SortDirection,
  tie: Comparator<T>,
): Comparator<T> {
  const sign = dir === "asc" ? 1 : -1;
  return (a, b) => {
    const va = pick(a);
    const vb = pick(b);
    if (va === null && vb === null) return tie(a, b);
    if (va === null) return 1;
    if (vb === null) return -1;
    return va !== vb ? (va - vb) * sign : tie(a, b);
  };
}

/** A stable sort that never mutates its input. */
export function stableSort<T>(rows: T[], compare: Comparator<T>): T[] {
  return rows
    .map((row, index) => [row, index] as const)
    .sort(([a, ia], [b, ib]) => compare(a, b) || ia - ib)
    .map(([row]) => row);
}

/** Distinct, sorted values of one facet across the rows, for a filter select. */
export function facetValues<T>(rows: T[], pick: (row: T) => string | null | undefined): string[] {
  return Array.from(new Set(rows.map(pick).filter((v): v is string => Boolean(v)))).sort();
}

/** How many of the shown rows carry the metric a numeric sort orders by. */
export type SortCoverage = {
  /** Rows that carry the metric. */
  withValue: number;
  total: number;
  /** The metric as a sentence subject, for the toolbar note. */
  metric: string;
  /** Where the metric comes from, as a full sentence. */
  source: string;
};

export function coverageOf<T>(
  rows: T[],
  pick: (row: T) => number | null,
  metric: string,
  source: string,
): SortCoverage {
  return { withValue: rows.filter((r) => pick(r) !== null).length, total: rows.length, metric, source };
}

/**
 * The toolbar note for a numeric sort: says how many rows carry the metric
 * when not all of them do, so an order that cannot change is not read as a
 * broken control. Empty when every row can move or there are no rows.
 * `noun` names the rows ("model", "finding"); `fallback` names the order the
 * rows without a value keep ("name order").
 */
export function coverageNote(coverage: SortCoverage | null, noun: string, fallback: string): string {
  if (!coverage || coverage.total === 0) return "";
  const { withValue, total, metric, source } = coverage;
  if (withValue === total) return "";
  const known = `${metric} is known for ${withValue} of ${total} ${noun}${total === 1 ? "" : "s"}.`;
  const effect =
    withValue < 2
      ? `Nothing to order yet, so the rows stay in ${fallback}.`
      : `Rows without one follow in ${fallback}.`;
  return `${known} ${effect} ${source}`;
}
