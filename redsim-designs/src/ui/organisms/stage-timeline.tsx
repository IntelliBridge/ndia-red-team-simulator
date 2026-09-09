import { Check, Circle, Loader2, X } from "lucide-react"
import type { StageFrame } from "@/lib/api-types"
import { cn } from "@/lib/utils"

/** Fed by WebSocket {type:"stage"} frames with a 30s fallback poll. [spec §18.3] */
export function StageTimeline({ stages }: { stages: Pick<StageFrame, "name" | "status">[] }) {
  if (!stages.length) return null
  return (
    <ol className="flex flex-wrap items-center gap-2">
      {stages.map((s, i) => {
        const icon =
          s.status === "done" ? <Check className="h-3.5 w-3.5 text-robust" /> :
          s.status === "running" ? <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" /> :
          s.status === "failed" ? <X className="h-3.5 w-3.5 text-critical" /> :
          <Circle className="h-3.5 w-3.5 text-muted-2" />
        return (
          <li key={s.name} className="flex items-center gap-2">
            <span className={cn("inline-flex items-center gap-1.5 rounded border border-hairline bg-panel px-2 py-1 text-xs", s.status === "running" && "border-primary/40")}>
              {icon}
              <span className="text-foreground">{s.name}</span>
            </span>
            {i < stages.length - 1 && <span className="text-muted-2">→</span>}
          </li>
        )
      })}
    </ol>
  )
}
