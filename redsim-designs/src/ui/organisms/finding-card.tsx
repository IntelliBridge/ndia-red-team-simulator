import type { Finding } from "@/lib/api-types"
import { SeverityChip } from "@/ui/molecules/severity-chip"

/**
 * Finding header. The validation_state chip shows the ML wording verbatim
 * (e.g. "verified: attack no longer crosses threshold at these settings with
 * feature_squeezing"). Never "fixed" or "resolved". [spec §18.4]
 */
export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-hairline bg-panel p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-base font-semibold text-foreground">{finding.title}</h1>
        <SeverityChip severity={finding.derived_severity} />
        <span className="rounded border border-hairline bg-panel-2 px-1.5 py-0.5 text-xs text-muted">{finding.status}</span>
        {finding.validation_state && (
          <span className="rounded border border-inferred/40 bg-inferred/10 px-1.5 py-0.5 text-xs text-inferred">
            {finding.validation_state}
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-1 font-mono text-xs text-muted tabular">
        <span>attack {finding.attack}</span>
        <span>ε at first success {finding.eps_first_success ?? "—"}</span>
        <span>ASR {finding.asr_flipped} / {finding.asr_clean_correct}</span>
      </div>
    </div>
  )
}
