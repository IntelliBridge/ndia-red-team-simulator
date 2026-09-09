"use client"

import { useCost } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { PanelSection } from "@/ui/molecules/panel-section"
import { ErrorState } from "@/ui/molecules/states"
import { DetailSkeleton } from "@/ui/molecules/skeletons"

export default function CostPage() {
  const { data, error, isLoading, mutate } = useCost()

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Cost" subtitle="Daily LLM spend against the org budget." />
      {isLoading && <DetailSkeleton />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && (
        <>
          <PanelSection title="Today">
            <div className="flex items-end gap-2">
              <span className="font-mono text-3xl text-foreground tabular">${data.today_usd.toFixed(2)}</span>
              <span className="mb-1 text-sm text-muted">/ ${data.budget_usd.toFixed(2)} budget</span>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-panel-2">
              <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, (data.today_usd / data.budget_usd) * 100)}%` }} />
            </div>
          </PanelSection>
          <PanelSection title="By run">
            <table className="w-full text-sm">
              <tbody>
                {data.by_run.map((r) => (
                  <tr key={r.run_id} className="border-t border-hairline">
                    <td className="py-1.5 font-mono text-xs">{r.run_id}</td>
                    <td className="py-1.5 text-right font-mono text-xs tabular">${r.usd.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </PanelSection>
        </>
      )}
    </div>
  )
}
