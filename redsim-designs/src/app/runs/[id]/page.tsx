"use client"

import { useState } from "react"
import Link from "next/link"
import { Download, GitCompare, RotateCcw } from "lucide-react"
import {
  useRun,
  useMeasurement,
  useMri,
  useObservations,
  useInterpretation,
  useRecommendations,
  useProvenance,
  useFindings,
} from "@/lib/hooks"
import { reportUrl, cancelRun } from "@/lib/api"
import { useSession } from "@/lib/session"
import { PageHeader } from "@/ui/molecules/page-header"
import { PanelSection } from "@/ui/molecules/panel-section"
import { KeyValueList } from "@/ui/molecules/key-value-list"
import { RunStatusBadge } from "@/ui/molecules/run-status-badge"
import { SeverityChip } from "@/ui/molecules/severity-chip"
import { LabelBadge } from "@/ui/atoms/label-badge"
import { AuditChainBadge } from "@/ui/molecules/audit-chain-badge"
import { PhaseBControl } from "@/ui/molecules/phase-b-control"
import { RoleGated } from "@/ui/molecules/role-gated"
import { ErrorState } from "@/ui/molecules/states"
import { DetailSkeleton, TableSkeleton } from "@/ui/molecules/skeletons"
import { Button } from "@/ui/atoms/button"
import { MriScorecard } from "@/ui/organisms/mri-scorecard"
import { MeasurementTable } from "@/ui/organisms/measurement-table"
import { RobustnessCurve } from "@/ui/organisms/robustness-curve"
import { ObservationCard } from "@/ui/organisms/observation-card"
import { RecommendationCard } from "@/ui/organisms/recommendation-card"
import { StageTimeline } from "@/ui/organisms/stage-timeline"
import { ReviewerNotes } from "@/ui/organisms/reviewer-notes"
import { CompareDrawer } from "@/ui/organisms/compare-drawer"

export default function RunPage({ params }: { params: { id: string } }) {
  const { id } = params
  const { session } = useSession()
  const run = useRun(id)
  const measurement = useMeasurement(id)
  const mri = useMri(id)
  const observations = useObservations(id)
  const interpretation = useInterpretation(id)
  const recommendations = useRecommendations(id)
  const provenance = useProvenance(id)
  const findings = useFindings(id)
  const [compare, setCompare] = useState(false)

  if (run.isLoading) return <DetailSkeleton />
  if (run.error) return <ErrorState error={run.error} onRetry={() => run.mutate()} />
  if (!run.data) return null

  const c = run.data
  const cfg = c.config
  const partial = c.completeness === "partial"
  const curvePresent = !!measurement.data && measurement.data.rows.some((r) => r.family !== "clean")

  const stages = [
    { name: "queued", status: "done" as const },
    { name: "attacks", status: "done" as const },
    { name: "explain", status: "done" as const },
    { name: "score", status: c.status === "succeeded" ? ("done" as const) : ("running" as const) },
  ]

  return (
    <div className="flex flex-col gap-5">
      {/* Run header */}
      <PageHeader
        title={`Campaign ${c.run_id}`}
        subtitle={<Link href={`/models/${c.model_id}`} className="text-primary hover:underline">{c.model_name}</Link>}
        right={
          <div className="flex items-center gap-2">
            <RunStatusBadge status={c.status} />
            <a href={reportUrl(c.run_id, "md")} className="inline-flex"><Button variant="outline" size="sm"><Download className="h-3.5 w-3.5" /> .md</Button></a>
            <a href={reportUrl(c.run_id, "json")} className="inline-flex"><Button variant="outline" size="sm">.json</Button></a>
            <a href={reportUrl(c.run_id, "html")} className="inline-flex"><Button variant="outline" size="sm">.html</Button></a>
            <RoleGated min="remediator">
              {(c.status === "queued" || c.status === "running") && (
                <Button variant="danger" size="sm" onClick={() => confirm("Cancel this run?") && cancelRun(c.run_id)}>Cancel</Button>
              )}
            </RoleGated>
          </div>
        }
      />

      <PhaseBControl label="Export report as PDF" reason="Phase B: PDF rendering pipeline not yet enabled." />

      <StageTimeline stages={stages} />

      {/* 1. Completeness banner */}
      <div className={`rounded-md border p-3 text-sm ${partial ? "border-degraded/40 bg-degraded/10 text-degraded" : "border-robust/40 bg-robust/10 text-robust"}`}>
        <span className="inline-flex items-center gap-2">
          {partial ? <LabelBadge variant="partial">partial</LabelBadge> : <span className="font-medium">complete</span>}
          {partial && <span className="text-xs">{c.completeness_reason}</span>}
        </span>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
        {/* 3. MRI scorecard */}
        <PanelSection title="MRI scorecard" tone="measurement" right={partial ? <LabelBadge variant="partial">partial</LabelBadge> : undefined}>
          <MriScorecard record={mri.data ?? null} measurement={measurement.data ?? null} curvePresent={curvePresent} />
        </PanelSection>

        {/* 2. Campaign settings — always next to the score */}
        <PanelSection title="Campaign settings">
          <KeyValueList
            columns={1}
            items={[
              { key: "attacks", value: cfg.attacks.join(", ") },
              { key: "ε grid", value: cfg.eps_grid.join(", ") },
              { key: "reference ε", value: cfg.reference_eps },
              { key: "finding threshold", value: cfg.finding_asr_threshold },
              { key: "dataset", value: `${cfg.dataset_id} @ ${cfg.dataset_revision}` },
              { key: "n", value: cfg.n },
              { key: "seed", value: cfg.seed },
              { key: "control", value: String(cfg.noise_control) },
              { key: "explain_k", value: cfg.explain_k },
              { key: "weights", value: `acc ${cfg.scoring_weights.acc} · asr ${cfg.scoring_weights.asr} · eps ${cfg.scoring_weights.eps} · conf ${cfg.scoring_weights.conf} · expl ${cfg.scoring_weights.expl}` },
              { key: "settings_hash", value: c.settings_hash },
              { key: "libraries", value: Object.entries(c.library_versions).map(([k, v]) => `${k} ${v}`).join(", ") },
            ]}
          />
        </PanelSection>
      </div>

      {/* 4. Measurements + robustness curve */}
      <PanelSection title="Measurements" tone="measurement" subtitle="By family. Accuracy as k / n (pct); ASR as flipped / clean-correct.">
          {measurement.isLoading && <TableSkeleton rows={3} cols={4} />}
        {measurement.error && <ErrorState error={measurement.error} onRetry={() => measurement.mutate()} />}
        {measurement.data && (
          <div className="flex flex-col gap-4">
            <MeasurementTable measurement={measurement.data} />
            {curvePresent && (
              <div className="rounded-md border border-hairline bg-panel-2/30 p-3">
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-2">Robustness curve — accuracy vs ε</p>
                <RobustnessCurve measurement={measurement.data} />
              </div>
            )}
          </div>
        )}
      </PanelSection>

      {/* 5. Observations gallery */}
      <PanelSection title="Observations" tone="observation" subtitle="Per explained sample. SHAP + heuristics from the API.">
        {observations.data && observations.data.length > 0 ? (
          <div className="grid gap-3 lg:grid-cols-2">
            {observations.data.map((o) => <ObservationCard key={o.id} obs={o} />)}
          </div>
        ) : (
          <p className="text-sm text-muted">No observations recorded.</p>
        )}
      </PanelSection>

      {/* 6. Interpretation */}
      <PanelSection title="Interpretation" tone="interpretation" subtitle="Deterministic rule outputs.">
        <ul className="flex flex-col gap-2">
          {(interpretation.data ?? []).map((it) => (
            <li key={it.id} className="rounded-md border border-hairline bg-panel p-3">
              <div className="mb-1 flex items-center gap-2">
                <LabelBadge variant="inferred">inferred</LabelBadge>
                <span className="text-[11px] text-muted-2">
                  basis: {it.basis.map((b, i) => (
                    <span key={b}>{i > 0 && ", "}<a href={`#${b}`} className="font-mono text-primary hover:underline">{b}</a></span>
                  ))}
                </span>
              </div>
              <p className="text-sm text-foreground">{it.statement}</p>
            </li>
          ))}
          {(interpretation.data ?? []).length === 0 && <p className="text-sm text-muted">No interpretation statements recorded.</p>}
        </ul>
      </PanelSection>

      {/* 7. Candidate recommendations */}
      <PanelSection title="Candidate recommendations" tone="candidate" subtitle="Rule outputs. Not evaluated until a defense is verified.">
        <div className="flex flex-col gap-3">
          {mri.data?.narrative ? (
            <div className="rounded-md border border-hairline bg-panel-2/40 p-3">
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-2">
                LLM-generated narrative of rule outputs (via Pythia, model {mri.data.narrative_model_id})
              </p>
              <p className="text-xs leading-relaxed text-muted">{mri.data.narrative}</p>
            </div>
          ) : (
            <div className="rounded-md border border-hairline bg-panel-2/40 p-3 text-xs text-muted">
              Narrative unavailable: {mri.data?.narrative_unavailable_reason ?? "Pythia not configured"}; rule outputs shown.
            </div>
          )}
          {(recommendations.data ?? []).map((r) => (
            <RecommendationCard key={r.id} rec={r} onVerified={() => recommendations.mutate()} />
          ))}
          {(recommendations.data ?? []).length === 0 && <p className="text-sm text-muted">No candidate recommendations.</p>}
        </div>
      </PanelSection>

      {/* 8. Limitations */}
      <PanelSection title="Limitations">
        <ul className="list-inside list-disc text-sm text-muted">
          {(mri.data?.limitations ?? []).map((l) => <li key={l}>{l}</li>)}
          {(mri.data?.limitations ?? []).length === 0 && <li>No limitations recorded.</li>}
        </ul>
      </PanelSection>

      {/* 9. Provenance */}
      <PanelSection
        title="Provenance"
        right={
          <RoleGated min="scanner">
            <Link href={`/models/${c.model_id}`}><Button variant="outline" size="sm"><RotateCcw className="h-3.5 w-3.5" /> Rerun with same config</Button></Link>
          </RoleGated>
        }
      >
        {provenance.data && (
          <KeyValueList
            items={[
              { key: "libraries", value: Object.entries(provenance.data.library_versions).map(([k, v]) => `${k} ${v}`).join(", ") },
              { key: "model sha256", value: provenance.data.model_sha256.slice(0, 20) },
              { key: "dataset", value: `${provenance.data.dataset_id} @ ${provenance.data.dataset_revision}` },
              { key: "seed", value: provenance.data.seed },
              { key: "sample_indices_sha256", value: provenance.data.sample_indices_sha256.slice(0, 20) },
              { key: "device", value: provenance.data.device },
              { key: "hostname", value: provenance.data.hostname },
              { key: "nondeterminism", value: provenance.data.nondeterminism.join("; ") || "none" },
            ]}
          />
        )}
      </PanelSection>

      {/* 10. Reviewer notes */}
      <PanelSection title="Reviewer notes">
        <ReviewerNotes runId={c.run_id} />
      </PanelSection>

      {/* 11. Findings table */}
      <PanelSection title="Findings" right={<Button variant="outline" size="sm" onClick={() => setCompare(true)}><GitCompare className="h-3.5 w-3.5" /> Compare</Button>}>
        <div className="overflow-x-auto rounded-md border border-hairline">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-hairline bg-panel-2 text-[11px] uppercase tracking-wide text-muted">
                <th className="px-3 py-2 text-left">Severity</th>
                <th className="px-3 py-2 text-left">Attack</th>
                <th className="px-3 py-2 text-left">ε at first success</th>
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {(findings.data ?? []).map((f) => {
                const isCreator = session?.user === f.created_by
                return (
                  <tr key={f.id} className="border-b border-hairline last:border-0">
                    <td className="px-3 py-2"><Link href={`/findings/${f.id}`}><SeverityChip severity={f.derived_severity} /></Link></td>
                    <td className="px-3 py-2 font-mono text-xs">{f.attack}</td>
                    <td className="px-3 py-2 font-mono text-xs tabular">{f.eps_first_success ?? "—"}</td>
                    <td className="px-3 py-2 text-right">
                      <RoleGated min="approver" fallback={<span className="text-xs text-muted-2">approver only</span>}>
                        <Button variant="ghost" size="sm" disabled={isCreator} title={isCreator ? "The campaign creator cannot dismiss their own finding." : undefined}>
                          Dismiss
                        </Button>
                      </RoleGated>
                    </td>
                  </tr>
                )
              })}
              {(findings.data ?? []).length === 0 && (
                <tr><td colSpan={4} className="px-3 py-4 text-sm text-muted">No findings.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </PanelSection>

      {/* Phase B2 affordances below panel 11 */}
      <div className="grid gap-3 sm:grid-cols-2">
        <PhaseBControl label="Export adversarial dataset" reason="Phase B2, not implemented." />
        <PhaseBControl label="ATLAS coverage" reason="Phase B2, not implemented." />
      </div>

      {/* 13. Audit */}
      <PanelSection title="Audit">
        <AuditChainBadge chainId={`run:${c.run_id}`} verified />
      </PanelSection>

      {compare && <CompareDrawer run={c} onClose={() => setCompare(false)} />}
    </div>
  )
}
