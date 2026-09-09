"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { RunStatusBadge } from "@redsim/design-system";
import { api, type Finding, type ModelTarget, type Run } from "@/lib/api";
import { getEmail, logout } from "@/lib/auth";
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
    <Link href={href} className="redsim-stat">
      <div className="redsim-kicker">{label}</div>
      <div className="redsim-numeral">{value}</div>
      {sub && <div className="redsim-stat-note">{sub}</div>}
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
  if (rows.length === 0) return <p className="text-sm text-ink-3">Nothing recorded yet.</p>;
  return (
    <ul className="m-0 list-none space-y-2.5 p-0" aria-label={ariaLabel}>
      {rows.map(([key, n]) => (
        <li key={key} className="grid grid-cols-[6.5rem_1fr_3rem] items-center gap-3 text-sm">
          <span className="truncate text-xs capitalize text-ink-2">{key}</span>
          <span className="relative block h-px w-full bg-line-strong" aria-hidden="true">
            <span
              className={`absolute left-0 top-1/2 block h-[3px] -translate-y-1/2 ${colorFor ? colorFor(key) : "bg-data-adv"}`}
              style={{ width: `${Math.max(2, Math.round((n / max) * 100))}%` }}
            />
          </span>
          <span className="text-right text-xs tabular-nums text-ink-1">{n}</span>
        </li>
      ))}
    </ul>
  );
}

function Panel({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="redsim-sheet">
      <h2 className="redsim-sheet-label">
        {title}
        {action && <small className="redsim-sheet-note">{action}</small>}
      </h2>
      <div className="redsim-sheet-body">{children}</div>
    </section>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const authed = useRequireAuth();
  // Models and findings refresh on the same cadence as runs. The runs hook is
  // called last so its arguments are the ones a test reads back.
  const models = useSWR(authed ? "/v1/models" : null, modelsFetcher, { refreshInterval: 15000 });
  const findings = useSWR(authed ? "/v1/findings" : null, findingsFetcher, { refreshInterval: 15000 });
  // Poll every 15s so the dashboard tracks newly queued/finished runs
  // without a manual refresh (the run-detail view has its own live feed).
  const { data, error, isLoading } = useSWR(authed ? "/v1/runs" : null, runsFetcher, { refreshInterval: 15000 });
  if (!authed) return <p className="text-ink-3">Signing in…</p>;

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

  // Awaited, so the redirect follows both the Better Auth sign-out and the
  // redsim cookie clear rather than racing them.
  const signOut = async () => {
    await logout();
    router.push("/login");
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1>Dashboard</h1>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-ink-3">{getEmail() ?? "(session)"}</span>
          <button onClick={signOut} className="redsim-ghost redsim-btn-sm">
            Sign out
          </button>
        </div>
      </div>

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
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

      <Panel title="Activity">
        <div className="grid gap-8 md:grid-cols-3">
          <div>
            <h3 className="redsim-kicker mb-3">Runs by status</h3>
            <BarRows rows={runStatus} ariaLabel="Runs by status" />
          </div>
          <div>
            <h3 className="redsim-kicker mb-3">Findings by severity</h3>
            <BarRows rows={severity} colorFor={(k) => SEVERITY_BAR[k] ?? "bg-data-adv"} ariaLabel="Findings by severity" />
          </div>
          <div>
            <h3 className="redsim-kicker mb-3">Runs started, last 14 days</h3>
            <div className="flex h-24 items-end gap-1 border-b border-line-strong" role="img" aria-label={`Runs per day: ${perDay.map((d) => `${d.day} ${d.count}`).join(", ")}`}>
              {perDay.map((d) => (
                <div key={d.day} className="group relative flex-1" title={`${d.day}: ${d.count}`}>
                  <div
                    className={d.count === 0 ? "w-full bg-line-strong" : "w-full bg-data-adv"}
                    style={{ height: `${Math.max(d.count === 0 ? 1 : 8, Math.round((d.count / perDayMax) * 96))}px` }}
                  />
                </div>
              ))}
            </div>
            <div className="mt-1 flex justify-between font-mono text-[10px] text-ink-3">
              <span>{perDay[0]?.day.slice(5)}</span>
              <span>{perDay[perDay.length - 1]?.day.slice(5)}</span>
            </div>
          </div>
        </div>
      </Panel>

      <Panel
        title="High and critical findings"
        action={<Link className="redsim-link text-xs" href="/findings">All findings</Link>}
      >
        {severe.length === 0 ? (
          <p className="text-sm text-ink-3">No high or critical findings recorded.</p>
        ) : (
          <ul className="m-0 list-none border-t border-line p-0">
            {severe.map((f) => (
              <FindingSummaryCard key={f.id} finding={f} leadMax={280} />
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Recent runs" action={<Link className="redsim-link text-xs" href="/runs">All runs</Link>}>
        {isLoading && <p className="text-ink-3">Loading…</p>}
        {error && (
          <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            Failed to load runs: {String(error)}
          </p>
        )}
        {!isLoading && !error && runs.length === 0 && (
          <p className="text-ink-3">
            No runs yet. Head to{" "}
            <Link className="redsim-link" href="/models">
              /models
            </Link>{" "}
            to register a target and start one.
          </p>
        )}
        {recent.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left">
                <tr className="border-b border-line-strong">
                  <th className="px-3 py-2">Run</th>
                  <th className="px-3 py-2">Project</th>
                  <th className="px-3 py-2">Scanner</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Created</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((r) => (
                  <tr key={r.id} {...rowLink(`/runs/${r.id}`)} className={`border-b border-line last:border-0 ${rowLink("").className}`}>
                    <td className="px-3 py-2.5 font-mono text-xs">
                      <a className="redsim-link" href={`/runs/${r.id}`}>
                        {r.id}
                      </a>
                    </td>
                    <td className="px-3 py-2.5">{r.project_id}</td>
                    <td className="px-3 py-2.5">{r.scanner ?? "—"}</td>
                    <td className="px-3 py-2.5">
                      <RunStatusBadge status={r.status} />
                    </td>
                    <td className="px-3 py-2.5 text-ink-3">{new Date(r.created_at).toLocaleString()}</td>
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
