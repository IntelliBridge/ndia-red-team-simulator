"use client"

import { useState } from "react"
import { Plus } from "lucide-react"
import type { ModelTarget } from "@/lib/api-types"
import { fraction, shortSha } from "@/lib/utils"
import { useModels } from "@/lib/hooks"
import { PageHeader } from "@/ui/molecules/page-header"
import { DataTable, type Column } from "@/ui/molecules/data-table"
import { EmptyState, ErrorState } from "@/ui/molecules/states"
import { TableSkeleton } from "@/ui/molecules/skeletons"
import { Button } from "@/ui/atoms/button"
import { LabelBadge } from "@/ui/atoms/label-badge"
import { AddModelDialog } from "@/ui/organisms/add-model-dialog"

const sourceLabel: Record<ModelTarget["source"], string> = {
  bundled: "bundled",
  uploaded: "uploaded",
  endpoint: "endpoint (Phase B)",
}

function StatusCell({ m }: { m: ModelTarget }) {
  if (m.status === "refused") {
    return (
      <span className="text-critical" title={m.refusal_reason}>
        refused
      </span>
    )
  }
  if (m.status === "available") return <span className="text-robust">available</span>
  return <span className="text-degraded">{m.status}</span>
}

export default function ModelsPage() {
  const { data, error, isLoading, mutate } = useModels()
  const [open, setOpen] = useState(false)

  const columns: Column<ModelTarget>[] = [
    { key: "name", header: "Name", render: (m) => <span className="font-medium">{m.name}</span> },
    {
      key: "source",
      header: "Source",
      render: (m) => (
        <LabelBadge variant={m.source === "endpoint" ? "phase-b" : "inferred"}>{sourceLabel[m.source]}</LabelBadge>
      ),
    },
    { key: "modality", header: "Modality", render: (m) => <span className="font-mono text-xs">{m.modality}</span> },
    { key: "format", header: "Format", render: (m) => <span className="font-mono text-xs">{m.format ?? "—"}</span> },
    { key: "sha", header: "sha256", render: (m) => <span className="font-mono text-xs text-muted">{shortSha(m.manifest?.sha256)}</span> },
    {
      key: "acc",
      header: "Clean acc",
      render: (m) =>
        m.manifest?.clean_accuracy ? (
          <span className="font-mono text-xs tabular">{fraction(m.manifest.clean_accuracy.n_correct, m.manifest.clean_accuracy.n)}</span>
        ) : (
          <span className="text-muted-2">—</span>
        ),
    },
    { key: "status", header: "Status", render: (m) => <StatusCell m={m} /> },
  ]

  return (
    <div>
      <PageHeader
        title="Models"
        subtitle="Register a classifier as a campaign target. Open, unclassified data only."
        right={
          <Button variant="primary" size="sm" onClick={() => setOpen(true)}>
            <Plus className="h-4 w-4" /> Add model
          </Button>
        }
      />

      {isLoading && <TableSkeleton cols={7} />}
      {error && <ErrorState error={error} onRetry={() => mutate()} />}
      {data && data.length === 0 && <EmptyState title="No models registered" hint="Add a bundled sample or upload an artifact to get started." />}
      {data && data.length > 0 && (
        <DataTable columns={columns} rows={data} getRowKey={(m) => m.id} rowHref={(m) => `/models/${m.id}`} caption="Registered models" />
      )}

      {open && <AddModelDialog onClose={() => setOpen(false)} onCreated={() => { setOpen(false); mutate() }} />}
    </div>
  )
}
