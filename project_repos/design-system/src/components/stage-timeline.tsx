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
  success: boolean;
  detail?: string;
}

export interface StageTimelineProps {
  stages: StageEntry[];
  className?: string;
}

const MODE_TONE: Record<string, string> = {
  live: "bg-sky-100 text-sky-900",
  fixture: "bg-amber-100 text-amber-900",
  golden_patch: "bg-amber-100 text-amber-900",
};

export function StageTimeline({ stages, className }: StageTimelineProps) {
  return (
    <ol className={cn("space-y-3", className)}>
      {stages.map((s) => (
        <li key={s.name} className="flex items-start gap-3">
          <span
            className={cn(
              "mt-1 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-bold",
              s.success
                ? "bg-emerald-500 text-white"
                : "bg-red-500 text-white",
            )}
            aria-hidden="true"
          >
            {s.success ? "✓" : "✗"}
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-slate-900">{s.name}</span>
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 text-xs",
                  MODE_TONE[s.mode] ?? "bg-slate-100 text-slate-700",
                )}
              >
                {s.mode}
              </span>
            </div>
            {s.detail && (
              <p className="mt-0.5 truncate text-xs text-slate-600">{s.detail}</p>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
