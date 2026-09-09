"use client"

import type { Campaign } from "@/lib/api-types"
import { relativeTime } from "@/lib/utils"
import { useRuns } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { DataTable, type Column } from "@/ui/molecules/data-table"
import { RunStatusBadge } from "@/ui/molecules/run-status-badge"
import { EmptyState, ErrorState } from "@/ui/molecules/states"
import { TableSkeleton } from "@/ui/molecules/skeletons"

export default function DashboardPage() {
  const { data, error, isLoading, mutate } = useRuns()

  const columns: Column<Campaign>[] = [
    { key: "run", header: "Run", render: (r) => <span className="font-mono text-xs">{r.run_id}</span> },
    { key: "project", header: "Project", render: (r) => <span className="text-xs">{r.project}</span> },
    { key: "model", header: "Model", render: (r) => <span className="text-xs">{r.model_name}</span> },
    { key: "attacks", header: "Attacks", render: (r) => <span className="font-mono text-xs">{r.config.attacks.filter((a) => a !== "noise_control").join(", ")}</span> },
    { key: "status", header: "Status", render: (r) => <RunStatusBadge status={r.status} /> },
    { key: "created", header: "Created", render: (r) => <span className="text-xs text-muted">{relativeTime(r.created_at)}</span> },
  ]

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Recent campaigns. No score tiles — the MRI lives only on a run's scorecard." />
      {isLoading && <TableSkeleton cols={6} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && data.length === 0 && <EmptyState title="No campaigns yet" hint="Register a model and launch a campaign to see results here." actionHref="/models" actionLabel="Go to Models" />}
      {data && data.length > 0 && (
        <DataTable columns={columns} rows={data} getRowKey={(r) => r.run_id} rowHref={(r) => `/runs/${r.run_id}`} caption="Recent campaigns" />
      )}
    </div>
  )
}
