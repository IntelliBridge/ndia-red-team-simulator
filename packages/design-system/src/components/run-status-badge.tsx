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

const TONES: Record<RunStatus, string> = {
  queued: "border-hairline bg-panel-2 text-muted-foreground",
  running: "border-primary/40 bg-primary/10 text-primary",
  succeeded: "border-robust/40 bg-robust/10 text-robust",
  partial_success: "border-partial/40 bg-partial/10 text-partial",
  failed: "border-critical/40 bg-critical/10 text-critical",
  cancelled: "border-hairline bg-panel-2 text-muted-foreground line-through",
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
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
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
