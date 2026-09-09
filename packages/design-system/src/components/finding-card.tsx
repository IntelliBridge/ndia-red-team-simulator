// FindingCard — the header block of a single finding.
//
// Composes SeverityChip and the state marks. Renders severity, id, target,
// title and status; the page decides whether to inline the description or
// link out. No box: it sits on the sheet with a rule beneath it.

import { type ReactNode } from "react";

import { cn } from "../lib/utils";
import { SeverityChip } from "./severity-chip";

export interface FindingCardProps {
  id: string;
  title: string;
  severity: string;
  status: string;
  target?: string | null;
  validationState?: string | null;
  /** Right-hand actions slot (Apply Patch / Verify / etc.) */
  actions?: ReactNode;
  /** Optional description / evidence preview */
  children?: ReactNode;
  className?: string;
}

// `poc_failed` is orange, not red: red is the brand accent in this UI.
const VALIDATION_TONES: Record<string, string> = {
  poc_passed: "border-emerald-400/40 text-emerald-200",
  poc_failed: "border-orange-400/50 text-orange-200",
  inconclusive: "border-amber-400/50 text-amber-200",
  unvalidated: "border-line-strong text-ink-3",
};

export function FindingCard({
  id,
  title,
  severity,
  status,
  target,
  validationState,
  actions,
  children,
  className,
}: FindingCardProps) {
  const validationTone =
    validationState && VALIDATION_TONES[validationState]
      ? VALIDATION_TONES[validationState]
      : "border-line-strong text-ink-3";
  return (
    <div
      className={cn(
        "flex flex-col gap-3 border-b border-line pb-6",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3 text-xs text-ink-3">
            <SeverityChip level={severity} />
            <span className="font-mono">{id}</span>
            {target && (
              <span className="truncate font-mono text-ink-4" title={target}>
                {target}
              </span>
            )}
          </div>
          <h3 className="mt-2 text-[1.375rem] font-semibold leading-tight tracking-tight text-ink-1">
            {title}
          </h3>
        </div>
        {actions && (
          <div className="flex shrink-0 items-center gap-2">{actions}</div>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center rounded-[3px] border border-line-strong px-1.5 py-px text-ink-2">
          status: {status}
        </span>
        {validationState && (
          <span
            className={cn(
              "inline-flex items-center rounded-[3px] border px-1.5 py-px",
              validationTone,
            )}
          >
            {validationState.replace("_", " ")}
          </span>
        )}
      </div>
      {children && (
        <div className="redsim-prose text-base">{children}</div>
      )}
    </div>
  );
}
