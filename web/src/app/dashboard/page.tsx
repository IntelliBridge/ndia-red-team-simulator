"use client";
import Link from "next/link";
import useSWR from "swr";
import { RunStatusBadge } from "@redsim/design-system";
import { api, type Finding, type ModelTarget, type Run } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { FindingSummaryCard } from "@/components/finding-summary-card";
import { rowLink } from "@/lib/row-link";

// One fetcher per list. Each is optional on the page: a list that fails or is
// still loading leaves its tiles at "—" and never blocks the others.
const runsFetcher = (path: string) => api<{ runs: Run[]; count: number }>(path);
const modelsFetcher = (path: string) => api<{ models: ModelTarget[]; count: number }>(path);
const findingsFetcher = (path: string) => api<{ findings: Finding[]; count: number }>(path);

const RUN_STATUS_ORDER = ["running", "queued", "succeeded", "partial", "failed", "cancelled"] as const;
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
// Status colours are reserved for state and always travel with the label and
// the count beside them (never colour alone).
const SEVERITY_BAR: Record<string, string> = {
  critical: "bg-red-600 dark:bg-red-500",
  high: "bg-orange-500 dark:bg-orange-400",
  medium: "bg-amber-500 dark:bg-amber-400",
  low: "bg-emerald-600 dark:bg-emerald-500",
  info: "bg-sky-500 dark:bg-sky-400",
};

/** Count rows by a key, in a fixed display order, unknown values last. */
function countBy<T>(rows: readonly T[], key: (row: T) => string, order: readonly string[]) {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const k = key(row) || "unknown";
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const known = order.filter((k) => counts.has(k)).map((k) => [k, counts.get(k) ?? 0] as const);
  const rest = [...counts.keys()].filter((k) => !order.includes(k)).sort().map((k) => [k, counts.get(k) ?? 0] as const);
  return [...known, ...rest];
}

/** Runs created per day over the last `days` days, oldest first, zero-filled. */
function runsPerDay(runs: readonly Run[], days = 14, now = new Date()): { day: string; count: number }[] {
  const buckets = new Map<string, number>();
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(now);
    d.setUTCHours(0, 0, 0, 0);
    d.setUTCDate(d.getUTCDate() - i);
    buckets.set(d.toISOString().slice(0, 10), 0);
  }
  for (const run of runs) {
    const day = run.created_at.slice(0, 10);
    if (buckets.has(day)) buckets.set(day, (buckets.get(day) ?? 0) + 1);
  }
  return [...buckets.entries()].map(([day, count]) => ({ day, count }));
}

function StatTile({ label, value, sub, href }: { label: string; value: string; sub?: string; href: string }) {
  return (
    <Link
      href={href}
      className="block rounded-md border border-border bg-card p-4 transition-colors hover:bg-muted"
    >
      <div className="redsim-kicker text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1 text-3xl font-semibold tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </Link>
  );
}

function BarRows({
  rows,
  colorFor,
  ariaLabel,
}: {
  rows: readonly (readonly [string, number])[];
  colorFor?: (key: string) => string;
  ariaLabel: string;
}) {
  const max = Math.max(1, ...rows.map(([, n]) => n));
  if (rows.length === 0) return <p className="text-sm text-muted-foreground">Nothing recorded yet.</p>;
  return (
    <ul className="space-y-2" aria-label={ariaLabel}>
      {rows.map(([key, n]) => (
        <li key={key} className="grid grid-cols-[7rem_1fr_3rem] items-center gap-3 text-sm">
          <span className="truncate capitalize">{key}</span>
          <span className="h-3 rounded-sm bg-muted" aria-hidden="true">
            <span
              className={`block h-3 rounded-sm ${colorFor ? colorFor(key) : "bg-primary"}`}
              style={{ width: `${Math.max(2, Math.round((n / max) * 100))}%` }}
            />
          </span>
          <span className="text-right tabular-nums">{n}</span>
        </li>
      ))}
    </ul>
  );
}

function Panel({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="rounded-md border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

export default function DashboardPage() {
  const authed = useRequireAuth();
  // Models and findings refresh on the same cadence as runs. The runs hook is
  // called last so its arguments are the ones a test reads back.
  const models = useSWR(authed ? "/v1/models" : null, modelsFetcher, { refreshInterval: 15000 });
  const findings = useSWR(authed ? "/v1/findings" : null, findingsFetcher, { refreshInterval: 15000 });
  // Poll every 15s so the dashboard tracks newly queued/finished runs
  // without a manual refresh (the run-detail view has its own live feed).
  const { data, error, isLoading } = useSWR(authed ? "/v1/runs" : null, runsFetcher, { refreshInterval: 15000 });
  if (!authed) return <p className="text-muted-foreground">Signing in…</p>;

  const runs: Run[] = Array.isArray(data?.runs) ? data.runs : [];
  const modelRows: ModelTarget[] = Array.isArray(models.data?.models) ? models.data.models : [];
  const findingRows: Finding[] = Array.isArray(findings.data?.findings) ? findings.data.findings : [];

  const registered = modelRows.filter((m) => (m as { registered?: boolean }).registered !== false);
  const available = registered.filter((m) => m.status === "available");
  const active = runs.filter((r) => r.status === "running" || r.status === "queued");
  const openFindings = findingRows.filter((f) => f.status === "open" || f.status === "fixing");
  const severe = findingRows
    .filter((f) => (f.severity === "critical" || f.severity === "high") && f.status !== "false_positive")
    .sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "critical" ? -1 : 1))
    .slice(0, 8);
  const runStatus = countBy(runs, (r) => r.status, RUN_STATUS_ORDER);
  const severity = countBy(findingRows, (f) => f.severity, SEVERITY_ORDER);
  const perDay = runsPerDay(runs);
  const perDayMax = Math.max(1, ...perDay.map((d) => d.count));
  const recent = [...runs].slice(0, 10);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Dashboard</h1>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Registered models"
          value={models.data ? String(registered.length) : "—"}
          sub={models.data ? `${available.length} available to attack` : models.error ? "failed to load" : "loading"}
          href="/models"
        />
        <StatTile
          label="Runs"
          value={data ? String(runs.length) : "—"}
          sub={data ? `${active.length} running or queued` : error ? "failed to load" : "loading"}
          href="/runs"
        />
        <StatTile
          label="Open findings"
          value={findings.data ? String(openFindings.length) : "—"}
          sub={findings.data ? `${findingRows.length} recorded in all` : findings.error ? "failed to load" : "loading"}
          href="/findings"
        />
        <StatTile
          label="High or critical"
          value={findings.data ? String(findingRows.filter((f) => f.severity === "critical" || f.severity === "high").length) : "—"}
          sub={findings.data ? `${findingRows.filter((f) => f.severity === "critical").length} critical` : findings.error ? "failed to load" : "loading"}
          href="/findings?severity=high"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Runs by status">
          <BarRows rows={runStatus} ariaLabel="Runs by status" />
        </Panel>
        <Panel title="Findings by severity">
          <BarRows rows={severity} colorFor={(k) => SEVERITY_BAR[k] ?? "bg-primary"} ariaLabel="Findings by severity" />
        </Panel>
        <Panel title="Runs started, last 14 days">
          <div className="flex h-24 items-end gap-1" role="img" aria-label={`Runs per day: ${perDay.map((d) => `${d.day} ${d.count}`).join(", ")}`}>
            {perDay.map((d) => (
              <div key={d.day} className="group relative flex-1" title={`${d.day}: ${d.count}`}>
                <div
                  className="w-full rounded-t-sm bg-primary"
                  style={{ height: `${Math.max(d.count === 0 ? 2 : 8, Math.round((d.count / perDayMax) * 96))}px` }}
                />
              </div>
            ))}
          </div>
          <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
            <span>{perDay[0]?.day.slice(5)}</span>
            <span>{perDay[perDay.length - 1]?.day.slice(5)}</span>
          </div>
        </Panel>
      </div>

      <Panel
        title="High and critical findings"
        action={<Link className="text-xs text-primary underline" href="/findings">All findings</Link>}
      >
        {severe.length === 0 ? (
          <p className="text-sm text-muted-foreground">No high or critical findings recorded.</p>
        ) : (
          <ul className="space-y-3">
            {severe.map((f) => (
              <FindingSummaryCard key={f.id} finding={f} leadMax={280} />
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Recent runs" action={<Link className="text-xs text-primary underline" href="/runs">All runs</Link>}>
        {isLoading && <p className="text-muted-foreground">Loading…</p>}
        {error && (
          <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            Failed to load runs: {String(error)}
          </p>
        )}
        {!isLoading && !error && runs.length === 0 && (
          <p className="text-muted-foreground">
            No runs yet. Head to{" "}
            <Link className="text-primary underline" href="/models">
              /models
            </Link>{" "}
            to register a target and start one.
          </p>
        )}
        {recent.length > 0 && (
          <div className="overflow-hidden rounded-md border border-border">
            <table className="w-full text-sm">
              <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">Run</th>
                  <th className="px-3 py-2">Project</th>
                  <th className="px-3 py-2">Scanner</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Created</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((r) => (
                  <tr key={r.id} {...rowLink(`/runs/${r.id}`)} className={`border-t border-border ${rowLink("").className}`}>
                    <td className="px-3 py-2 font-mono text-xs">
                      <a className="text-primary underline" href={`/runs/${r.id}`}>
                        {r.id}
                      </a>
                    </td>
                    <td className="px-3 py-2">{r.project_id}</td>
                    <td className="px-3 py-2">{r.scanner ?? "—"}</td>
                    <td className="px-3 py-2">
                      <RunStatusBadge status={r.status} />
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">{new Date(r.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
