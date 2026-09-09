// FindingCard — header card for a single finding row.
//
// Composes SeverityChip and a small status pill. Renders title /
// id / target / status; the page-level component decides whether
// to inline the description or link out.

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

const VALIDATION_TONES: Record<string, string> = {
  poc_passed: "bg-robust/10 text-robust",
  poc_failed: "bg-critical/10 text-critical",
  inconclusive: "bg-degraded/10 text-degraded",
  unvalidated: "bg-panel-2 text-muted-foreground",
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
      : "bg-panel-2 text-muted-foreground";
  return (
    <div
      className={cn(
        "flex flex-col gap-3 rounded-lg border border-hairline bg-panel p-4 shadow-sm",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <SeverityChip level={severity} />
            <span className="font-mono">{id}</span>
            {target && (
              <span className="truncate font-mono opacity-70" title={target}>
                {target}
              </span>
            )}
          </div>
          <h3 className="mt-2 truncate text-lg font-semibold text-foreground">
            {title}
          </h3>
        </div>
        {actions && (
          <div className="flex shrink-0 items-center gap-2">{actions}</div>
        )}
      </div>
      <div className="flex items-center gap-2 text-xs">
        <span className="inline-flex items-center rounded bg-panel-2 px-1.5 py-0.5 text-muted-foreground">
          status: {status}
        </span>
        {validationState && (
          <span
            className={cn(
              "inline-flex items-center rounded px-1.5 py-0.5",
              validationTone,
            )}
          >
            {validationState.replace("_", " ")}
          </span>
        )}
      </div>
      {children && (
        <div className="text-sm text-foreground">{children}</div>
      )}
    </div>
  );
}
