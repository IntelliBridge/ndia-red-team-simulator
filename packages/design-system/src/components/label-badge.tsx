// LabelBadge — the contract label on a reading: candidate, inferred,
// heuristic, measured, illustrative, partial, phase-b. The wording is part of
// the contract and is shown as written, in a small bordered mark.

import { cn } from "../lib/utils";
export type LabelBadgeVariant =
  | "candidate"
  | "inferred"
  | "heuristic"
  | "measured"
  | "illustrative"
  | "partial"
  | "phase-b";
export interface LabelBadgeProps {
  variant: LabelBadgeVariant;
  className?: string;
  measuredDelta?: number | null;
}
const words: Record<LabelBadgeVariant, string> = {
  candidate: "candidate · not evaluated",
  inferred: "inferred",
  heuristic: "heuristic",
  measured: "measured",
  illustrative: "FIXTURE — illustrative",
  partial: "partial evidence",
  "phase-b": "Phase B · unavailable",
};
const tones: Partial<Record<LabelBadgeVariant, string>> = {
  measured: "border-data-adv/60 text-data-adv",
  illustrative: "border-warning/60 text-warning",
  partial: "border-warning/50 text-warning",
};
export function LabelBadge({
  variant,
  className,
  measuredDelta,
}: LabelBadgeProps) {
  const text =
    variant === "measured" && measuredDelta !== undefined
      ? measuredDelta == null
        ? "candidate · measured at these settings · ΔMRI unavailable"
        : `candidate · measured ΔMRI ${measuredDelta > 0 ? "+" : ""}${measuredDelta} at these settings`
      : words[variant];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-[3px] border border-line-strong px-1.5 py-0.5 text-[11px] font-medium leading-4 text-ink-2",
        tones[variant],
        className,
      )}
    >
      {text}
    </span>
  );
}
