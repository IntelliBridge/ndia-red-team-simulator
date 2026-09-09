// StageTimeline — left-rail timeline rendering a run's stage table.
//
// Each entry is { name, mode, success, detail }. Mode tags ("live",
// "fixture", "golden_patch") render as small chips so the user can see
// at a glance whether the pipeline ran for real or against fixtures.

import { cn } from "../lib/utils";

export type StageMode = string;

export interface StageEntry {
  name: string;
  mode: StageMode;
  success: boolean | null;
  detail?: string;
}

export interface StageTimelineProps {
  stages: StageEntry[];
  className?: string;
}

const MODE_TONE: Record<string, string> = {
  live: "bg-sky-400/10 text-sky-300",
  fixture: "bg-amber-500/15 text-amber-200",
  golden_patch: "bg-amber-500/15 text-amber-200",
};

export function StageTimeline({ stages, className }: StageTimelineProps) {
  return (
    <ol className={cn("space-y-3", className)}>
      {stages.map((s) => (
        <li key={s.name} className="flex items-start gap-3">
          <span
            className={cn(
              "mt-1 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-bold",
              // A failed stage is orange, not red: red is the brand accent.
              s.success === true
                ? "bg-emerald-400 text-navy-deepest"
                : s.success === false
                  ? "bg-orange-400 text-navy-deepest"
                  : "bg-amber-400 text-navy-deepest",
            )}
            aria-hidden="true"
          >
            {s.success === true ? "✓" : s.success === false ? "✗" : "…"}
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-foreground">{s.name}</span>
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 text-xs",
                  MODE_TONE[s.mode] ?? "bg-muted text-muted-foreground",
                )}
              >
                {s.mode}
              </span>
            </div>
            {s.detail && (
              <p className="mt-0.5 truncate text-xs text-muted-foreground">{s.detail}</p>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
