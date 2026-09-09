"use client";

import { useState } from "react";
import useSWR from "swr";

import {
  centsToUsd,
  getOrgCost,
  resolveOrgId,
  type OrgCost,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

const DAYS_OPTIONS = [7, 30, 90] as const;

// SWR key is a tuple [orgId, days]; the fetcher destructures it so the
// days selector forces a refetch when it changes.
const fetcher = ([orgId, days]: [string, number]): Promise<OrgCost> =>
  getOrgCost(orgId, days);

function StatCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className="redsim-stat">
      <div className="redsim-kicker">{label}</div>
      <div className={`redsim-numeral text-3xl ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

function ByDayChart({ byDay }: { byDay: Record<string, number> }) {
  const entries = Object.entries(byDay).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  const max = entries.reduce((m, [, c]) => Math.max(m, c), 0);

  if (entries.length === 0) {
    return (
      <p className="text-sm text-ink-3">No daily usage in range.</p>
    );
  }

  return (
    <div
      className="flex h-40 items-end gap-1"
      role="img"
      aria-label="Spend by day"
    >
      {entries.map(([day, cents]) => {
        // Scale to the tallest bar; floor at 2% so non-zero days stay visible.
        const pct = max > 0 ? Math.max((cents / max) * 100, 2) : 0;
        return (
          <div
            key={day}
            className="flex flex-1 flex-col items-center justify-end"
            title={`${day}: ${centsToUsd(cents)}`}
          >
            <div
              data-testid="bar"
              data-day={day}
              className="w-full bg-data-adv"
              style={{ height: `${pct}%` }}
            />
          </div>
        );
      })}
    </div>
  );
}

function BreakdownTable({
  caption,
  keyLabel,
  rows,
}: {
  caption: string;
  keyLabel: string;
  rows: Record<string, number>;
}) {
  const sorted = Object.entries(rows).sort(([, a], [, b]) => b - a);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <caption className="sr-only">Spend by {caption}</caption>
        <thead className="text-left">
          <tr className="border-b border-line-strong">
            <th scope="col" className="px-3 py-2">
              {keyLabel}
            </th>
            <th scope="col" className="px-3 py-2 text-right">
              Spend
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td
                colSpan={2}
                className="px-3 py-4 text-center text-ink-3"
              >
                No {caption} usage in range.
              </td>
            </tr>
          ) : (
            sorted.map(([name, cents]) => (
              <tr key={name} className="border-b border-line last:border-0">
                <td className="px-3 py-2.5 font-mono text-xs">{name}</td>
                <td className="px-3 py-2.5 text-right tabular-nums text-ink-1">{centsToUsd(cents)}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function CostPage() {
  const authed = useRequireAuth();
  const { projects, isLoading: projectsLoading, error: projectsError } =
    useRoles();
  const [days, setDays] = useState<number>(30);

  // Resolve which tenant to show from the membership list (falls back to
  // "default" when the caller has no projects). See resolveOrgId().
  const orgId = resolveOrgId(projects);

  const {
    data,
    error: costError,
    isLoading: costLoading,
  } = useSWR<OrgCost>(
    authed && !projectsLoading ? [orgId, days] : null,
    fetcher,
  );

  if (!authed)
    return <p className="text-ink-3">Signing in…</p>;

  const error = projectsError ?? costError;
  if (error)
    return (
      <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load cost: {String(error)}
      </p>
    );

  if (projectsLoading || costLoading || !data)
    return <p className="text-ink-3">Loading…</p>;

  const { total_cents, call_count, by_day, by_model, by_task, budget } = data;
  const cap =
    budget.monthly_cap_cents == null
      ? "Uncapped"
      : centsToUsd(budget.monthly_cap_cents);
  const remaining =
    budget.remaining_cents == null
      ? "Uncapped"
      : centsToUsd(budget.remaining_cents);
  const remainingNegative =
    budget.remaining_cents != null && budget.remaining_cents <= 0;
  const noUsage = total_cents === 0 && call_count === 0;

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1>Cost</h1>
          <p className="mt-1 text-sm text-ink-3">
            Per-tenant LLM spend for org{" "}
            <span className="font-mono">{orgId}</span> over the last {days}{" "}
            days.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-ink-3">
          <span>Window</span>
          <select
            aria-label="Days window"
            className="redsim-input w-auto py-1.5"
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          >
            {DAYS_OPTIONS.map((d) => (
              <option key={d} value={d}>
                {d} days
              </option>
            ))}
          </select>
        </label>
      </header>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
        <StatCard label="Total spend" value={centsToUsd(total_cents)} />
        <StatCard label="Call count" value={call_count.toLocaleString()} />
        <div className="redsim-stat">
          <div className="redsim-kicker">Budget</div>
          <dl className="mt-2 space-y-1 text-sm">
            <div className="flex justify-between gap-3">
              <dt className="text-ink-3">Monthly cap</dt>
              <dd className="m-0 tabular-nums text-ink-1">{cap}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-3">Month to date</dt>
              <dd className="m-0 tabular-nums text-ink-1">
                {centsToUsd(budget.month_spent_cents)}
              </dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-3">Remaining</dt>
              <dd
                className={`m-0 tabular-nums ${
                  remainingNegative ? "font-medium text-destructive" : "text-ink-1"
                }`}
              >
                {remainingNegative ? `over budget — ${remaining}` : remaining}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      {noUsage ? (
        <p className="text-sm text-ink-3">
          No usage recorded for this org in the selected window.
        </p>
      ) : (
        <>
          <section className="redsim-sheet">
            <h2 className="redsim-sheet-label">Spend by day</h2>
            <div className="redsim-sheet-body">
              <ByDayChart byDay={by_day} />
            </div>
          </section>

          <section className="redsim-sheet">
            <h2 className="redsim-sheet-label">
              Spend by model and task
              <small className="redsim-sheet-note">Largest first</small>
            </h2>
            <div className="redsim-sheet-body grid grid-cols-1 gap-6 lg:grid-cols-2">
              <BreakdownTable
                caption="model"
                keyLabel="Model"
                rows={by_model}
              />
              <BreakdownTable caption="task" keyLabel="Task" rows={by_task} />
            </div>
          </section>
        </>
      )}
    </div>
  );
}
