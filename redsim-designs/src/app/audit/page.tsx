"use client"

import { ShieldCheck, ShieldAlert } from "lucide-react"
import { useAudit } from "@/lib/hooks"
import { formatDateTime } from "@/lib/utils"
import { PageHeader } from "@/ui/molecules/page-header"
import { PanelSection } from "@/ui/molecules/panel-section"
import { ErrorState } from "@/ui/molecules/states"
import { TableSkeleton } from "@/ui/molecules/skeletons"

export default function AuditPage() {
  const { data, error, isLoading, mutate } = useAudit()

  return (
    <div>
      <PageHeader title="Audit" subtitle="Hash-chained, tamper-evident log verification." />
      {isLoading && <TableSkeleton cols={5} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && (
        <PanelSection
          title={`Chain ${data.chain_id}`}
          right={
            <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs ${data.verified ? "border-robust/40 bg-robust/10 text-robust" : "border-critical/40 bg-critical/10 text-critical"}`}>
              {data.verified ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />}
              {data.verified ? "verified" : `broken at seq ${data.broken_at}`}
            </span>
          }
        >
          <div className="overflow-x-auto rounded-md border border-hairline">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-hairline bg-panel-2 text-[11px] uppercase tracking-wide text-muted">
                  <th className="px-3 py-2 text-left">Seq</th>
                  <th className="px-3 py-2 text-left">Time</th>
                  <th className="px-3 py-2 text-left">Action</th>
                  <th className="px-3 py-2 text-left">Actor</th>
                  <th className="px-3 py-2 text-left">prev → hash</th>
                </tr>
              </thead>
              <tbody>
                {data.entries.map((e) => (
                  <tr key={e.seq} className="border-b border-hairline last:border-0">
                    <td className="px-3 py-2 font-mono text-xs">{e.seq}</td>
                    <td className="px-3 py-2 text-xs text-muted">{formatDateTime(e.ts)}</td>
                    <td className="px-3 py-2 font-mono text-xs">{e.action}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted">{e.actor}</td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-2">{e.prev_hash} → {e.hash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </PanelSection>
      )}
    </div>
  )
}
