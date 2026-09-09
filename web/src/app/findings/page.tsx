"use client";

// /findings — cross-run findings list.
//
// Fixes the /findings 404 (the nav linked here but only /findings/[id]
// existed). SWR-backed list over GET /v1/findings with a server-side
// severity filter; reuses the design-system Table + SeverityChip so the
// row styling matches the run-detail findings table. Theming is via
// semantic tokens (no hardcoded slate/sky) and the table carries a
// caption + scope for a11y.

import { useState } from "react";
import useSWR from "swr";

import { SeverityChip } from "@redsim/design-system";
import { api, type Finding } from "@/lib/api";
import { FindingSummaryCard } from "@/components/finding-summary-card";
import { useRequireAuth } from "@/hooks/useRequireAuth";

const fetcher = (path: string) =>
  api<{ findings: Finding[]; count: number }>(path);

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;


export default function FindingsPage() {
  const authed = useRequireAuth();
  const [severity, setSeverity] = useState<string>("");

  const query = severity
    ? `/v1/findings?severity=${encodeURIComponent(severity)}`
    : "/v1/findings";
  const { data, error, isLoading } = useSWR(authed ? query : null, fetcher);

  if (!authed)
    return <p className="text-muted-foreground">Signing in…</p>;

  const findings = data?.findings ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Severity</span>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-sm"
          >
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
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
      {findings.length > 0 && (
        <ul className="space-y-3" aria-label="Findings across all accessible runs">
          {findings.map((f: Finding) => (
            <FindingSummaryCard key={f.id} finding={f} />
          ))}
        </ul>
      )}
    </div>
  );
}
