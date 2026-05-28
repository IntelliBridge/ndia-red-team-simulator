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
  queued: "bg-slate-100 text-slate-700",
  running: "bg-sky-100 text-sky-900",
  succeeded: "bg-emerald-100 text-emerald-900",
  partial_success: "bg-amber-100 text-amber-900",
  failed: "bg-red-100 text-red-900",
  cancelled: "bg-slate-100 text-slate-500 line-through",
};

export interface RunStatusBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  status: string;
}

export function RunStatusBadge({
  status,
  className,
  ...rest
}: RunStatusBadgeProps) {
  const tone =
    TONES[(status.toLowerCase() as RunStatus)] ?? "bg-slate-100 text-slate-700";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium",
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
