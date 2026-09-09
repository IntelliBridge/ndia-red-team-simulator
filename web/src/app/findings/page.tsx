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
import { findingLead } from "@/lib/finding-description";
import { rowLink } from "@/lib/row-link";
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
          {findings.map((f: Finding) => {
            const lead = findingLead(f.schema_blob.description, 600);
            return (
              <li
                key={f.id}
                {...rowLink(`/findings/${f.id}`)}
                className={`rounded-md border border-border bg-card p-4 ${rowLink("").className}`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip level={f.severity} />
                  <span className="text-base font-medium">{f.schema_blob.title ?? "—"}</span>
                  <span className="ml-auto rounded-sm border border-border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    {f.status}
                  </span>
                </div>
                {lead && (
                  <p className="mt-2 max-w-4xl text-sm leading-relaxed text-foreground/90">{lead}</p>
                )}
                {!lead && f.schema_blob.description && (
                  <p className="mt-2 max-w-4xl text-sm leading-relaxed text-muted-foreground">
                    {f.schema_blob.description}
                  </p>
                )}
                <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-xs">
                  <div>
                    <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Finding</dt>
                    <dd className="whitespace-nowrap font-mono">
                      <a className="text-primary underline" href={`/findings/${f.id}`}>
                        {f.id}
                      </a>
                    </dd>
                  </div>
                  <div>
                    <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Run</dt>
                    <dd className="whitespace-nowrap font-mono">
                      <a className="text-primary underline" href={`/runs/${f.run_id}`}>
                        {f.run_id}
                      </a>
                    </dd>
                  </div>
                  <div>
                    <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Attack or probe</dt>
                    <dd>{f.schema_blob.ml?.attack_id ?? f.schema_blob.llm?.probe_id ?? "—"}</dd>
                  </div>
                  <div>
                    <dt className="redsim-kicker uppercase tracking-wide text-muted-foreground">Source</dt>
                    <dd className="text-muted-foreground">{f.source_tool ?? "—"}</dd>
                  </div>
                </dl>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
