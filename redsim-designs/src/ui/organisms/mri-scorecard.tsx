import type { MRIRecord, Measurement, ScoringWeights } from "@/lib/api-types"
import { cn } from "@/lib/utils"
import { LabelBadge } from "@/ui/atoms/label-badge"
import { DimensionBars } from "./dimension-bars"

const DEFAULT_WEIGHTS: ScoringWeights = { acc: 0.35, asr: 0.25, eps: 0.2, conf: 0.1, expl: 0.1 }

const GRADE_LINE =
  "A grade describes measured behaviour under the declared attack set, ε grid and slice. It is not a readiness, safety, or certification statement, and it does not describe robustness to attacks that were not run."

function weightsDiffer(w: ScoringWeights) {
  return (["acc", "asr", "eps", "conf", "expl"] as const).some((k) => w[k] !== DEFAULT_WEIGHTS[k])
}

/**
 * The single place the per-campaign MRI number appears. Renders the number,
 * grade, and dimension bars ONLY when the score record, per-family measurement,
 * and curve are all present; otherwise "Score unavailable: <reason>" with no
 * number. [spec §15.7, §18.3 panel 3]
 */
export function MriScorecard({
  record,
  measurement,
  curvePresent,
}: {
  record: MRIRecord | null
  measurement: Measurement | null
  curvePresent: boolean
}) {
  const complete = record && !record.reason_unavailable && measurement && measurement.rows.length > 0 && curvePresent
  if (!complete) {
    const reason = record?.reason_unavailable ?? "measurement or robustness curve not available"
    return (
      <div className="flex flex-col gap-1 rounded-md border border-hairline bg-panel-2/40 p-4">
        <span className="text-xs uppercase tracking-wide text-muted-2">Model Robustness Index</span>
        <p className="text-sm text-degraded">Score unavailable: {reason}</p>
      </div>
    )
  }

  const nonDefault = weightsDiffer(record.weights)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start gap-5">
        <div className="flex flex-col">
          <span className="text-[11px] uppercase tracking-wide text-muted-2">Model Robustness Index</span>
          <div className="flex items-end gap-3">
            <span className="font-mono text-5xl font-semibold text-foreground tabular">{record.value}</span>
            <span className="mb-1 rounded border border-hairline bg-panel px-2 py-0.5 font-mono text-lg text-foreground">
              {record.grade}
            </span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 pt-5">
          {record.delta && (
            <span className="inline-flex items-center gap-1 rounded border border-measured/40 bg-measured/10 px-1.5 py-0.5 text-xs text-measured">
              <LabelBadge variant="measured">measured</LabelBadge>
              ΔMRI {record.delta.value > 0 ? "+" : ""}
              {record.delta.value}
            </span>
          )}
          {nonDefault && (
            <span className="rounded border border-degraded/40 bg-degraded/10 px-1.5 py-0.5 text-xs text-degraded">
              non-default weights
            </span>
          )}
        </div>
      </div>

      <DimensionBars dimensions={record.dimensions} />

      <p className={cn("rounded-md border border-hairline bg-panel-2/40 p-3 text-xs leading-relaxed text-muted")}>{GRADE_LINE}</p>
    </div>
  )
}
