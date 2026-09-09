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
  critical: "border-critical/40 bg-critical/10 text-critical",
  high: "border-critical/40 bg-critical/10 text-critical",
  medium: "border-degraded/40 bg-degraded/10 text-degraded",
  low: "border-robust/40 bg-robust/10 text-robust",
  info: "border-inferred/40 bg-inferred/10 text-inferred",
  unknown: "border-hairline bg-panel-2 text-muted-foreground",
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
