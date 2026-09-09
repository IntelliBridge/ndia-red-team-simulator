import { cn } from "@/lib/utils"
import type { Severity } from "@/lib/api-types"

/** Renders DERIVED severity. Never editable. [spec §15.5] */
const map: Record<Severity, { color: string; label: string }> = {
  critical: { color: "text-critical border-critical/40 bg-critical/10", label: "critical" },
  high: { color: "text-critical border-critical/40 bg-critical/10", label: "high" },
  medium: { color: "text-degraded border-degraded/40 bg-degraded/10", label: "medium" },
  low: { color: "text-robust border-robust/40 bg-robust/10", label: "low" },
}

export function SeverityChip({ severity, className }: { severity: Severity; className?: string }) {
  const cfg = map[severity]
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium", cfg.color, className)}>
      <span className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
      derived: {cfg.label}
    </span>
  )
}
