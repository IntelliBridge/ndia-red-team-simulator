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
        "inline-flex rounded-sm border border-border bg-muted px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground",
        className,
      )}
    >
      {text}
    </span>
  );
}
