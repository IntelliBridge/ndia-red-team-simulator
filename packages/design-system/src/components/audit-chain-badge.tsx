// AuditChainBadge — verify state for a hash chain (run or project).
//
// Three states: verified (green), broken (orange), pending (neutral). The
// chain id and event count are tooltip / aria affordances; the glyph and
// the word carry the state.

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
  verified: "border-emerald-400/40 text-emerald-200",
  broken: "border-orange-400/50 text-orange-200",
  pending: "border-line-strong text-ink-3",
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
        "inline-flex items-center gap-1.5 rounded-[3px] border px-2 py-0.5 text-xs font-medium",
        TONE[state],
        className,
      )}
      {...rest}
    >
      <span aria-hidden="true">{ICON[state]}</span>
      <span>chain</span>
      {events !== undefined && (
        <span className="font-mono tabular-nums opacity-70">{events}</span>
      )}
    </span>
  );
}
