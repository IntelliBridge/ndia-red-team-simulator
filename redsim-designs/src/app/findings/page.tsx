"use client"

import { useState } from "react"
import type { Finding, Severity } from "@/lib/api-types"
import { asr } from "@/lib/utils"
import { useFindings } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { DataTable, type Column } from "@/ui/molecules/data-table"
import { SeverityChip } from "@/ui/molecules/severity-chip"
import { EmptyState, ErrorState } from "@/ui/molecules/states"
import { TableSkeleton } from "@/ui/molecules/skeletons"
import { Select } from "@/ui/atoms/select"

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"]

export default function FindingsPage() {
  const { data, error, isLoading, mutate } = useFindings()
  const [sev, setSev] = useState<string>("")

  const rows = (data ?? []).filter((f) => !sev || f.derived_severity === sev)

  const columns: Column<Finding>[] = [
    { key: "severity", header: "Derived severity", render: (f) => <SeverityChip severity={f.derived_severity} /> },
    { key: "attack", header: "Attack", render: (f) => <span className="font-mono text-xs">{f.attack}</span> },
    { key: "eps", header: "ε at first success", render: (f) => <span className="font-mono text-xs tabular">{f.eps_first_success ?? "—"}</span> },
    { key: "asr", header: "ASR", render: (f) => <span className="font-mono text-xs tabular">{asr(f.asr_flipped, f.asr_clean_correct)}</span> },
    { key: "validation", header: "Validation", render: (f) => <span className="text-xs text-muted">{f.validation_state ?? "—"}</span> },
  ]

  return (
    <div>
      <PageHeader
        title="Findings"
        right={
          <label className="flex items-center gap-2 text-xs text-muted">
            severity
            <Select className="w-36" options={SEVERITIES.map((s) => ({ value: s, label: s }))} placeholder="all" value={sev} onChange={(e) => setSev(e.target.value)} />
          </label>
        }
      />
      {isLoading && <TableSkeleton cols={5} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && rows.length === 0 && <EmptyState title="No findings" hint={sev ? `No ${sev} findings.` : undefined} />}
      {data && rows.length > 0 && (
        <DataTable columns={columns} rows={rows} getRowKey={(f) => f.id} rowHref={(f) => `/findings/${f.id}`} caption="Findings" />
      )}
    </div>
  )
}
