// AuditChainBadge — surfaces verify state for a chain (run or project).
//
// Three states map to colours: verified ✓ (green), broken ✗ (orange),
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

// `broken` is orange, not red: red is the brand accent in this UI.
const TONE: Record<ChainVerifyState, string> = {
  verified: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  broken: "border-orange-400/50 bg-orange-500/20 text-orange-200",
  pending: "border-border bg-muted text-muted-foreground",
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
