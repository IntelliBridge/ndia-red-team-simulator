import { ImageOff } from "lucide-react"
import type { Observation } from "@/lib/api-types"
import { artifactUrl } from "@/lib/api"
import { LabelBadge } from "@/ui/atoms/label-badge"
import { Tooltip } from "@/ui/atoms/tooltip"

function ArtifactImage({ id, alt }: { id?: string; alt: string }) {
  if (!id) {
    return (
      <div className="flex aspect-square items-center justify-center rounded border border-dashed border-hairline bg-panel-2/40 text-muted-2">
        <ImageOff className="h-5 w-5" />
      </div>
    )
  }
  // Real artifacts come from the API. In fixtures these ids won't resolve; the
  // broken-image fallback is honest — no placeholder heatmap is fabricated.
  return (
    <img
      src={artifactUrl(id) || "/placeholder.svg"}
      alt={alt}
      className="aspect-square w-full rounded border border-hairline bg-panel-2 object-cover"
    />
  )
}

/**
 * One explained sample: clean vs adversarial, SHAP clean/adv, labels,
 * confidences, and center-mass heuristics badged `heuristic`. When no
 * explanation was recorded, shows the reason and draws nothing. [spec §18.3 panel 5]
 */
export function ObservationCard({ obs }: { obs: Observation }) {
  if (obs.no_explanation_reason) {
    return (
      <div className="rounded-md border border-hairline bg-panel p-3 text-xs text-muted">
        No explanation recorded ({obs.no_explanation_reason})
      </div>
    )
  }

  if (obs.kind === "tabular") {
    return (
      <div className="rounded-md border border-hairline bg-panel p-3">
        <FeatureDiff obs={obs} />
        <div className="mt-3 grid grid-cols-2 gap-2">
          <ArtifactImage id={obs.shap_clean_artifact_id} alt="SHAP bar, clean" />
          <ArtifactImage id={obs.shap_beeswarm_artifact_id} alt="SHAP beeswarm" />
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-md border border-hairline bg-panel p-3">
      <div className="grid grid-cols-4 gap-2">
        <Figure label="clean"><ArtifactImage id={obs.clean_artifact_id} alt="clean image" /></Figure>
        <Figure label="adversarial"><ArtifactImage id={obs.adv_artifact_id} alt="adversarial image" /></Figure>
        <Figure label="SHAP clean"><ArtifactImage id={obs.shap_clean_artifact_id} alt="SHAP saliency, clean" /></Figure>
        <Figure label="SHAP adv"><ArtifactImage id={obs.shap_adv_artifact_id} alt="SHAP saliency, adversarial" /></Figure>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <span className="text-muted">true <b className="font-mono text-foreground">{obs.true_label}</b></span>
        <span className="text-muted">clean <b className="font-mono text-foreground">{obs.pred_clean}</b> ({(obs.conf_clean * 100).toFixed(0)}%)</span>
        <span className="text-muted">adv <b className="font-mono text-foreground">{obs.pred_adv}</b> ({(obs.conf_adv * 100).toFixed(0)}%)</span>
        {obs.center_mass_ratio_clean != null && (
          <Tooltip content={obs.metric_note ?? "heuristic on SHAP magnitude concentration"}>
            <span className="inline-flex items-center gap-1 text-muted">
              <LabelBadge variant="heuristic">heuristic</LabelBadge>
              center-mass {obs.center_mass_ratio_clean} → {obs.center_mass_ratio_adv}
            </span>
          </Tooltip>
        )}
      </div>
    </div>
  )
}

function Figure({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <figure className="flex flex-col gap-1">
      {children}
      <figcaption className="text-center text-[10px] uppercase tracking-wide text-muted-2">{label}</figcaption>
    </figure>
  )
}

function FeatureDiff({ obs }: { obs: Observation }) {
  if (!obs.feature_diff?.length) return <p className="text-xs text-muted">No feature diff recorded.</p>
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-[10px] uppercase tracking-wide text-muted-2">
          <th className="py-1 text-left">Feature</th>
          <th className="py-1 text-left">Original</th>
          <th className="py-1 text-left">Adversarial</th>
          <th className="py-1 text-left">Δ</th>
        </tr>
      </thead>
      <tbody>
        {obs.feature_diff.map((f) => (
          <tr key={f.feature} className="border-t border-hairline">
            <td className="py-1 font-mono">{f.feature}</td>
            <td className="py-1 font-mono">{f.original}</td>
            <td className="py-1 font-mono">{f.adversarial}</td>
            <td className="py-1 font-mono">{f.delta}{f.unit ? ` ${f.unit}` : ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
