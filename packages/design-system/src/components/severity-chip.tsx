// Severity chip — color-coded badge for finding severities.
//
// Wraps a small visual badge. The runtime "level" is the lowercased
// severity coming straight off RedsimFinding.severity; unknown values
// fall back to a neutral gray.

import { type HTMLAttributes } from "react";
import { cn } from "../lib/utils";

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "unknown";

// Translucent tints on the navy ground. The ramp runs orange, amber,
// yellow, green, blue: red is the brand accent in this UI and never a
// severity, so `critical` is the deepest orange rather than red.
const TONES: Record<Severity, string> = {
  critical: "border-orange-400/50 bg-orange-500/20 text-orange-200",
  high: "border-amber-400/50 bg-amber-500/15 text-amber-200",
  medium: "border-yellow-400/40 bg-yellow-400/10 text-yellow-200",
  low: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  info: "border-sky-400/40 bg-sky-400/10 text-sky-300",
  unknown: "border-border bg-muted text-muted-foreground",
};

export interface SeverityChipProps extends HTMLAttributes<HTMLSpanElement> {
  level: Severity | (string & {});
}

export function SeverityChip({
  level,
  className,
  ...rest
}: SeverityChipProps) {
  const tone = TONES[(level.toLowerCase() as Severity)] ?? TONES.unknown;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider",
        tone,
        className,
      )}
      {...rest}
    >
      {level.toUpperCase()}
    </span>
  );
}
