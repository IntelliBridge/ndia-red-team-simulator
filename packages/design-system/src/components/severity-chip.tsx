// Severity chip — the finding severity as a coloured dot beside its word.
//
// The runtime "level" is the lowercased severity straight off
// RedsimFinding.severity; unknown values fall back to neutral. The colour
// never travels alone: the word is always beside it.

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
// orange, medium amber, low green, info blue.
const DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-emerald-400",
  info: "bg-sky-400",
  unknown: "bg-ink-4",
};
const TEXT: Record<Severity, string> = {
  critical: "text-red-200",
  high: "text-orange-200",
  medium: "text-amber-200",
  low: "text-emerald-200",
  info: "text-sky-200",
  unknown: "text-ink-3",
};

export interface SeverityChipProps extends HTMLAttributes<HTMLSpanElement> {
  level: Severity | (string & {});
}

export function SeverityChip({
  level,
  className,
  ...rest
}: SeverityChipProps) {
  const key = (level.toLowerCase() as Severity) in DOT ? (level.toLowerCase() as Severity) : "unknown";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.04em]",
        TEXT[key],
        className,
      )}
      {...rest}
    >
      <i className={cn("redsim-dot", DOT[key])} aria-hidden="true" />
      {level.toUpperCase()}
    </span>
  );
}
