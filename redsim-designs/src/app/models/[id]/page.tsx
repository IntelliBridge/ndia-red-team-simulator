"use client"

import Link from "next/link"
import { useModel, useRuns } from "@/lib/hooks"
import { shortSha, fraction } from "@/lib/utils"
import { PageHeader } from "@/ui/molecules/page-header"
import { PanelSection } from "@/ui/molecules/panel-section"
import { KeyValueList } from "@/ui/molecules/key-value-list"
import { CompatibilityList } from "@/ui/organisms/compatibility-list"
import { CampaignLauncher } from "@/ui/organisms/campaign-launcher"
import { DataTable, type Column } from "@/ui/molecules/data-table"
import { ErrorState } from "@/ui/molecules/states"
import { DetailSkeleton } from "@/ui/molecules/skeletons"
import { RunStatusBadge } from "@/ui/molecules/run-status-badge"
import type { Campaign } from "@/lib/api-types"

export default function ModelDetailPage({ params }: { params: { id: string } }) {
  const { id } = params
  const { data: model, error, isLoading, mutate } = useModel(id)
  const { data: runs } = useRuns()

  if (isLoading) return <DetailSkeleton />
  if (error) return <ErrorState error={error} onRetry={() => mutate()} />
  if (!model) return null

  const history = (runs ?? []).filter((r) => r.model_id === id)

  const historyCols: Column<Campaign>[] = [
    { key: "run", header: "Run", render: (r) => <span className="font-mono text-xs">{r.run_id}</span> },
    { key: "attacks", header: "Attacks", render: (r) => <span className="font-mono text-xs">{r.config.attacks.filter((a) => a !== "noise_control").join(", ")}</span> },
    { key: "refeps", header: "Reference ε", render: (r) => <span className="font-mono text-xs tabular">{r.reference_eps}</span> },
    { key: "status", header: "Status", render: (r) => <RunStatusBadge status={r.status} /> },
    { key: "scorecard", header: "", render: (r) => <Link href={`/runs/${r.run_id}`} className="text-xs text-primary hover:underline">scorecard</Link> },
  ]

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title={model.name}
        subtitle={<span className="font-mono text-xs">{model.source} · {model.modality} · {model.format ?? "—"}</span>}
      />

      {model.status === "refused" && (
        <div className="rounded-md border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
          Refused — {model.refusal_reason}
          {model.ingest_job_id && <> · <Link className="underline" href={`/logs?job=${model.ingest_job_id}`}>ingest job</Link></>}
        </div>
      )}
      {model.status === "validating" && (
        <div className="rounded-md border border-degraded/40 bg-degraded/10 p-3 text-sm text-degraded">
          Validating{model.ingest_job_id && <> · <Link className="underline" href={`/logs?job=${model.ingest_job_id}`}>ingest job {model.ingest_job_id}</Link></>}
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <PanelSection title="Manifest">
          <KeyValueList
            items={[
              { key: "sha256", value: shortSha(model.manifest?.sha256) },
              { key: "gradients", value: String(model.manifest?.gradients ?? "—") },
              { key: "architecture", value: model.manifest?.architecture ?? "—" },
              { key: "clean accuracy", value: model.manifest?.clean_accuracy ? fraction(model.manifest.clean_accuracy.n_correct, model.manifest.clean_accuracy.n) : "—" },
              { key: "license", value: model.license_statement ?? "—" },
              { key: "dataset", value: model.dataset_id ?? "—" },
            ]}
          />
        </PanelSection>
        <PanelSection title="Dataset compatibility">
          <CompatibilityList
            items={[
              { label: `Modality ${model.modality}`, ok: model.modality !== "not_implemented" },
              { label: "Declared dataset present", ok: !!model.dataset_id, note: model.dataset_id ?? undefined },
              { label: "Differentiable estimator (white-box attacks)", ok: !!model.manifest?.gradients, note: model.manifest?.gradients ? undefined : "black-box attacks only" },
            ]}
          />
        </PanelSection>
      </div>

      <CampaignLauncher model={model} />

      <PanelSection title="Campaign history">
        {history.length === 0 ? (
          <p className="text-sm text-muted">No campaigns for this model yet.</p>
        ) : (
          <DataTable columns={historyCols} rows={history} getRowKey={(r) => r.run_id} caption="Campaign history" />
        )}
      </PanelSection>
    </div>
  )
}
