import type { MRIRecord } from "@/lib/api-types"
import { cn } from "@/lib/utils"

/** The five weighted MRI dimension bars. [spec §18.3 panel 3] */
export function DimensionBars({ dimensions }: { dimensions: MRIRecord["dimensions"] }) {
  return (
    <ul className="flex flex-col gap-2.5">
      {dimensions.map((d) => (
        <li key={d.key} className="flex items-center gap-3">
          <span className="w-40 shrink-0 text-xs text-muted">{d.label}</span>
          <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-panel-2">
            <div
              className={cn(
                "h-full rounded-full",
                d.value >= 70 ? "bg-robust" : d.value >= 45 ? "bg-degraded" : "bg-critical",
              )}
              style={{ width: `${d.value}%` }}
            />
          </div>
          <span className="w-10 shrink-0 text-right font-mono text-xs text-foreground tabular">{d.value}</span>
          <span className="w-14 shrink-0 text-right font-mono text-[11px] text-muted-2 tabular">×{d.weight}</span>
        </li>
      ))}
    </ul>
  )
}
