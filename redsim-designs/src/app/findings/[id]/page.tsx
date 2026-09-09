"use client"

import { useState } from "react"
import Link from "next/link"
import { Wand2 } from "lucide-react"
import { useFinding, useRun, useMeasurement, useObservations, useRecommendations } from "@/lib/hooks"
import { explainFinding } from "@/lib/api"
import { useSession } from "@/lib/session"
import { PanelSection } from "@/ui/molecules/panel-section"
import { FindingCard } from "@/ui/organisms/finding-card"
import { ObservationCard } from "@/ui/organisms/observation-card"
import { RobustnessCurve } from "@/ui/organisms/robustness-curve"
import { RecommendationCard } from "@/ui/organisms/recommendation-card"
import { AuditChainBadge } from "@/ui/molecules/audit-chain-badge"
import { RoleGated } from "@/ui/molecules/role-gated"
import { ErrorState } from "@/ui/molecules/states"
import { DetailSkeleton } from "@/ui/molecules/skeletons"
import { Button } from "@/ui/atoms/button"
import { LabelBadge } from "@/ui/atoms/label-badge"

const ATTRIBUTION_LINE = "Attribution describes model sensitivity; it is not causal proof."

export default function FindingPage({ params }: { params: { id: string } }) {
  const { id } = params
  const { session } = useSession()
  const finding = useFinding(id)
  const runId = finding.data?.run_id ?? ""
  const run = useRun(runId)
  const measurement = useMeasurement(runId)
  const observations = useObservations(runId)
  const recommendations = useRecommendations(runId)
  const [explaining, setExplaining] = useState(false)

  if (finding.isLoading) return <DetailSkeleton />
  if (finding.error) return <ErrorState error={finding.error} onRetry={() => finding.mutate()} />
  if (!finding.data) return null

  const f = finding.data
  const obs = observations.data?.[0]
  const isUrlClassifier = run.data?.config.dataset_id?.includes("url")

  async function explain() {
    setExplaining(true)
    try {
      await explainFinding(f.id, session?.dev ? undefined : undefined)
      observations.mutate()
    } finally {
      setExplaining(false)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <FindingCard finding={f} />

      <div className="grid gap-5 lg:grid-cols-3">
        {/* Pane 1: Input */}
        <PanelSection title="Input" tone="observation">
          {isUrlClassifier ? (
            <div className="flex flex-col gap-2">
              <p className="rounded border border-hairline bg-panel-2/40 p-2 font-mono text-xs text-muted">
                {"https://example-dataset-row.invalid/path?q=sample"}
              </p>
              <p className="text-[11px] text-muted-2">Dataset content, escaped and non-clickable.</p>
              <p className="rounded border border-degraded/40 bg-degraded/10 p-2 text-xs text-degraded">
                feature-space perturbation; realizability not established
              </p>
            </div>
          ) : obs ? (
            <div className="flex flex-col gap-2">
              <ObservationCard obs={obs} />
              <p className="text-[11px] text-muted-2">Original vs adversarial with perturbation magnitude and measured L∞ / L2, beside the noise-control image at the same ε.</p>
            </div>
          ) : (
            <p className="text-sm text-muted">No input observation recorded.</p>
          )}
        </PanelSection>

        {/* Pane 2: Explanation */}
        <PanelSection
          title="Explanation"
          tone="interpretation"
          right={
            !obs ? (
              <RoleGated min="scanner">
                <Button variant="outline" size="sm" onClick={explain} disabled={explaining}>
                  <Wand2 className="h-3.5 w-3.5" /> {explaining ? "Explaining…" : "Explain"}
                </Button>
              </RoleGated>
            ) : undefined
          }
        >
          {obs && !obs.no_explanation_reason ? (
            <div className="flex flex-col gap-3">
              <ObservationCard obs={obs} />
              <p className="inline-flex items-center gap-1 text-xs text-muted">
                <LabelBadge variant="heuristic">heuristic</LabelBadge>
                center-mass shift with noise floor shown in tooltip.
              </p>
              <p className="rounded border border-hairline bg-panel-2/40 p-2 text-xs text-muted">{ATTRIBUTION_LINE}</p>
            </div>
          ) : (
            <p className="text-sm text-muted">No explanation recorded{obs?.no_explanation_reason ? ` (${obs.no_explanation_reason})` : ""}.</p>
          )}
        </PanelSection>

        {/* Pane 3: Candidates */}
        <PanelSection title="Candidates" tone="candidate">
          <div className="flex flex-col gap-3">
            {(recommendations.data ?? []).map((r) => (
              <RecommendationCard key={r.id} rec={r} onVerified={() => recommendations.mutate()} />
            ))}
            {(recommendations.data ?? []).length === 0 && <p className="text-sm text-muted">No candidate recommendations for this finding.</p>}
          </div>
        </PanelSection>
      </div>

      {/* Below panes: curve highlight + audit + back link */}
      <PanelSection title="This attack on the campaign curve" tone="measurement">
        {measurement.data ? (
          <RobustnessCurve measurement={measurement.data} highlightAttack={f.attack} />
        ) : (
          <p className="text-sm text-muted">No measurement available.</p>
        )}
      </PanelSection>

      <div className="flex items-center justify-between">
        <AuditChainBadge chainId={`run:${f.run_id}`} verified />
        <Link href={`/runs/${f.run_id}`} className="text-sm text-primary hover:underline">Back to campaign</Link>
      </div>
    </div>
  )
}
