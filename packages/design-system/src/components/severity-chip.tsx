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

const TONES: Record<Severity, string> = {
  critical: "bg-red-100 text-red-900 border-red-200",
  high: "bg-orange-100 text-orange-900 border-orange-200",
  medium: "bg-amber-100 text-amber-900 border-amber-200",
  low: "bg-emerald-100 text-emerald-900 border-emerald-200",
  info: "bg-sky-100 text-sky-900 border-sky-200",
  unknown: "bg-slate-100 text-slate-700 border-slate-200",
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
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        tone,
        className,
      )}
      {...rest}
    >
      {level.toUpperCase()}
    </span>
  );
}
