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

// Colour-coded by severity (owner request, 2026-09-09): critical red, high
// orange, medium amber, low green, info blue. Translucent tints on the navy
// ground; the label always travels with the colour, never colour alone.
const TONES: Record<Severity, string> = {
  critical: "border-red-500/60 bg-red-500/25 text-red-100",
  high: "border-orange-400/60 bg-orange-500/25 text-orange-100",
  medium: "border-amber-400/50 bg-amber-400/20 text-amber-100",
  low: "border-emerald-400/50 bg-emerald-400/15 text-emerald-200",
  info: "border-sky-400/50 bg-sky-400/15 text-sky-200",
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
