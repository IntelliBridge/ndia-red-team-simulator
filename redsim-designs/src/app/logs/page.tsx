"use client"

import { useLogs } from "@/lib/hooks"
import { formatDateTime } from "@/lib/utils"
import { PageHeader } from "@/ui/molecules/page-header"
import { ErrorState } from "@/ui/molecules/states"
import { TableSkeleton } from "@/ui/molecules/skeletons"

export default function LogsPage() {
  const { data, error, isLoading, mutate } = useLogs()

  return (
    <div>
      <PageHeader title="Logs" />
      {isLoading && <TableSkeleton cols={3} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && (
        <div className="rounded-lg border border-hairline bg-panel font-mono text-xs">
          {data.map((l, i) => (
            <div key={i} className="flex gap-3 border-b border-hairline px-3 py-1.5 last:border-0">
              <span className="text-muted-2">{formatDateTime(l.ts)}</span>
              <span className={l.level === "ERROR" ? "text-critical" : l.level === "WARN" ? "text-degraded" : "text-primary"}>{l.level}</span>
              <span className="text-foreground">{l.message}</span>
              {l.run_id && <span className="text-muted-2">({l.run_id})</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
