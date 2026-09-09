import { cn } from "@/lib/utils"
import type { RunStatus } from "@/lib/api-types"

const map: Record<RunStatus, string> = {
  queued: "text-muted border-hairline bg-panel-2",
  running: "text-primary border-primary/40 bg-primary/10",
  succeeded: "text-robust border-robust/40 bg-robust/10",
  failed: "text-critical border-critical/40 bg-critical/10",
  cancelled: "text-muted border-hairline bg-panel-2",
}

export function RunStatusBadge({ status, className }: { status: RunStatus; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium", map[status], className)}>
      <span className={cn("inline-block h-1.5 w-1.5 rounded-full bg-current", status === "running" && "animate-pulse")} />
      {status}
    </span>
  )
}
