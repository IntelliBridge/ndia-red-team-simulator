// StageTimeline — a run's stage table as a vertical rule with one mark per
// stage. Each entry is { name, mode, success, detail }. The mode ("live",
// "fixture", "golden_patch") is shown as a small bordered mark so a reader
// sees whether the pipeline ran for real or against fixtures.

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
  live: "border-sky-400/40 text-sky-200",
  fixture: "border-amber-400/50 text-amber-200",
  golden_patch: "border-amber-400/50 text-amber-200",
};

export function StageTimeline({ stages, className }: StageTimelineProps) {
  return (
    <ol className={cn("relative m-0 list-none space-y-0 p-0", className)}>
      <span
        aria-hidden="true"
        className="absolute bottom-2 left-[0.4375rem] top-2 w-px bg-line-strong"
      />
      {stages.map((s) => (
        <li key={s.name} className="relative flex items-start gap-3 py-1.5">
          <span
            className={cn(
              "relative z-10 mt-1 inline-flex h-[15px] w-[15px] shrink-0 items-center justify-center rounded-full border-2 border-ground text-[9px] font-bold text-ground",
              // A failed stage is orange, not red: red is the brand accent.
              s.success === true
                ? "bg-emerald-400"
                : s.success === false
                  ? "bg-orange-400"
                  : "bg-amber-400",
            )}
            aria-hidden="true"
          >
            {s.success === true ? "✓" : s.success === false ? "✗" : ""}
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[13px] text-ink-1">{s.name}</span>
              <span
                className={cn(
                  "rounded-[3px] border px-1.5 py-px text-[11px] leading-4",
                  MODE_TONE[s.mode] ?? "border-line-strong text-ink-3",
                )}
              >
                {s.mode}
              </span>
            </div>
            {s.detail && (
              <p className="m-0 mt-0.5 truncate text-xs text-ink-3">{s.detail}</p>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
