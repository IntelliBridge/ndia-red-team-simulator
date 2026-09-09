// RunStatusBadge — surfaces the run / job lifecycle state.

import { type HTMLAttributes } from "react";
import { cn } from "../lib/utils";

export type RunStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "partial_success"
  | "failed"
  | "cancelled";

// Translucent tints on the navy ground. `failed` is orange, not red: red is
// the brand accent in this UI.
const TONES: Record<RunStatus, string> = {
  queued: "border-border bg-muted text-muted-foreground",
  running: "border-sky-400/40 bg-sky-400/10 text-sky-300",
  succeeded: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  partial_success: "border-amber-400/50 bg-amber-500/15 text-amber-200",
  failed: "border-orange-400/50 bg-orange-500/20 text-orange-200",
  cancelled: "border-border bg-muted text-muted-foreground line-through",
};

export interface RunStatusBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  status: RunStatus | (string & {});
}

export function RunStatusBadge({
  status,
  className,
  ...rest
}: RunStatusBadgeProps) {
  const tone = TONES[(status.toLowerCase() as RunStatus)] ?? TONES.queued;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider",
        tone,
        className,
      )}
      aria-label={`run status: ${status}`}
      {...rest}
    >
      {status.toLowerCase().replace("_", " ")}
    </span>
  );
}
