// AuditChainBadge — surfaces verify state for a chain (run or project).
//
// Three states map to colours: verified ✓ (green), broken ✗ (red),
// pending (gray). The chain id and event count are tooltip / aria
// affordances only — the user mostly cares about the ✓.

import { type HTMLAttributes } from "react";
import { cn } from "../lib/utils";

export type ChainVerifyState = "verified" | "broken" | "pending";

const ICON: Record<ChainVerifyState, string> = {
  verified: "✓",
  broken: "✗",
  pending: "…",
};

const TONE: Record<ChainVerifyState, string> = {
  verified: "bg-emerald-100 text-emerald-900 border-emerald-200",
  broken: "bg-red-100 text-red-900 border-red-200",
  pending: "bg-slate-100 text-slate-700 border-slate-200",
};

export interface AuditChainBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  state: ChainVerifyState;
  chainId?: string;
  events?: number;
}

export function AuditChainBadge({
  state,
  chainId,
  events,
  className,
  ...rest
}: AuditChainBadgeProps) {
  const label = `chain ${state}${events !== undefined ? ` (${events} events)` : ""}`;
  return (
    <span
      title={chainId ?? label}
      aria-label={label}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs",
        TONE[state],
        className,
      )}
      {...rest}
    >
      <span aria-hidden="true">{ICON[state]}</span>
      <span>chain</span>
      {events !== undefined && (
        <span className="opacity-70">{events}</span>
      )}
    </span>
  );
}
