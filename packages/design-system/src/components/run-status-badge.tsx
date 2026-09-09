// RunStatusBadge — the run / job lifecycle state as a dot beside its word.
// A running dot pulses (and holds still under prefers-reduced-motion).
// `failed` is orange, not red: red is the brand accent in this UI.

import { type HTMLAttributes } from "react";
import { cn } from "../lib/utils";

export type RunStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "partial_success"
  | "failed"
  | "cancelled";

const DOT: Record<RunStatus, string> = {
  queued: "bg-ink-4",
  running: "bg-sky-400",
  succeeded: "bg-emerald-400",
  partial_success: "bg-amber-400",
  failed: "bg-orange-400",
  cancelled: "bg-ink-4",
};
const TEXT: Record<RunStatus, string> = {
  queued: "text-ink-3",
  running: "text-sky-200",
  succeeded: "text-emerald-200",
  partial_success: "text-amber-200",
  failed: "text-orange-200",
  cancelled: "text-ink-3 line-through",
};

export interface RunStatusBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  status: RunStatus | (string & {});
}

export function RunStatusBadge({
  status,
  className,
  ...rest
}: RunStatusBadgeProps) {
  const lower = status.toLowerCase() as RunStatus;
  const key: RunStatus = lower in DOT ? lower : "queued";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap text-[13px] font-medium",
        TEXT[key],
        className,
      )}
      aria-label={`run status: ${status}`}
      {...rest}
    >
      <i
        className={cn("redsim-dot", DOT[key])}
        data-live={key === "running" ? "true" : undefined}
        aria-hidden="true"
      />
      {status.toLowerCase().replace("_", " ")}
    </span>
  );
}
