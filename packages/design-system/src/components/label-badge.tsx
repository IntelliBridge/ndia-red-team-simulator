import { cn } from "../lib/utils";
export type LabelBadgeVariant =
  | "candidate"
  | "inferred"
  | "heuristic"
  | "illustrative"
  | "partial"
  | "phase-b";
export interface LabelBadgeProps {
  variant: LabelBadgeVariant;
  className?: string;
}
const words: Record<LabelBadgeVariant, string> = {
  candidate: "candidate",
  inferred: "inferred",
  heuristic: "heuristic",
  illustrative: "FIXTURE — illustrative",
  partial: "partial evidence",
  "phase-b": "Phase B · unavailable",
};
export function LabelBadge({ variant, className }: LabelBadgeProps) {
  const text = words[variant];
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
