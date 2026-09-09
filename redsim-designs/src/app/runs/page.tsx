"use client"

import type { Campaign } from "@/lib/api-types"
import { relativeTime } from "@/lib/utils"
import { useRuns } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { DataTable, type Column } from "@/ui/molecules/data-table"
import { RunStatusBadge } from "@/ui/molecules/run-status-badge"
import { EmptyState, ErrorState } from "@/ui/molecules/states"
import { TableSkeleton } from "@/ui/molecules/skeletons"

export default function RunsPage() {
  const { data, error, isLoading, mutate } = useRuns()

  const columns: Column<Campaign>[] = [
    { key: "run", header: "Run", render: (r) => <span className="font-mono text-xs">{r.run_id}</span> },
    { key: "model", header: "Model", render: (r) => <span className="text-xs">{r.model_name}</span> },
    { key: "attacks", header: "Attacks", render: (r) => <span className="font-mono text-xs">{r.config.attacks.filter((a) => a !== "noise_control").join(", ")}</span> },
    { key: "status", header: "Status", render: (r) => <RunStatusBadge status={r.status} /> },
    { key: "created", header: "Created", render: (r) => <span className="text-xs text-muted">{relativeTime(r.created_at)}</span> },
  ]

  return (
    <div>
      <PageHeader title="Runs" />
      {isLoading && <TableSkeleton cols={5} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && data.length === 0 && <EmptyState title="No runs yet" actionHref="/models" actionLabel="Go to Models" />}
      {data && data.length > 0 && (
        <DataTable columns={columns} rows={data} getRowKey={(r) => r.run_id} rowHref={(r) => `/runs/${r.run_id}`} caption="Runs" />
      )}
    </div>
  )
}
