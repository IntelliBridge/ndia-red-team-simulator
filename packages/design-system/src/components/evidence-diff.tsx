// EvidenceDiff — render a unified diff with simple +/- line tinting.
//
// Server-rendered HTML; CSS-only colour, no JavaScript. Pairs with
// the F14d CSP that disallows inline scripts.

import { type HTMLAttributes } from "react";
import { cn } from "../lib/utils";

export interface EvidenceDiffProps extends HTMLAttributes<HTMLPreElement> {
  diff: string;
}

export function EvidenceDiff({
  diff,
  className,
  ...rest
}: EvidenceDiffProps) {
  const lines = diff.split("\n");
  return (
    <pre
      className={cn(
        "overflow-x-auto rounded-md border border-border bg-black/40 p-3 text-xs leading-5 text-foreground/90",
        className,
      )}
      {...rest}
    >
      {lines.map((line, i) => {
        let tone = "text-foreground/70";
        if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) {
          tone = "text-sky-300";
        } else if (line.startsWith("+")) {
          tone = "text-emerald-300";
        } else if (line.startsWith("-")) {
          // Removed lines are orange, not red: red is the brand accent.
          tone = "text-orange-300";
        }
        return (
          <span key={i} className={cn("block", tone)}>
            {line || " "}
          </span>
        );
      })}
    </pre>
  );
}
