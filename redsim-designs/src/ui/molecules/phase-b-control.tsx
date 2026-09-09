import { Lock } from "lucide-react"
import { cn } from "@/lib/utils"
import { LabelBadge } from "@/ui/atoms/label-badge"

/**
 * A control that is disabled (never hidden) with an explicit reason. Used for
 * Phase B / B2 affordances and other not-implemented paths. [spec §6, §18.3]
 */
export function PhaseBControl({
  label,
  reason,
  badge = "phase-b",
  className,
}: {
  label: string
  reason: string
  badge?: "phase-b" | "illustrative"
  className?: string
}) {
  return (
    <div
      aria-disabled
      className={cn(
        "flex items-start justify-between gap-3 rounded-md border border-dashed border-hairline bg-panel-2/50 px-3 py-2 opacity-80",
        className,
      )}
    >
      <div className="flex min-w-0 items-center gap-2">
        <Lock className="h-3.5 w-3.5 shrink-0 text-muted-2" />
        <div className="min-w-0">
          <p className="text-sm text-muted">{label}</p>
          <p className="mt-0.5 text-xs text-muted-2">{reason}</p>
        </div>
      </div>
      <LabelBadge variant={badge}>{badge === "phase-b" ? "Phase B" : "illustrative"}</LabelBadge>
    </div>
  )
}
