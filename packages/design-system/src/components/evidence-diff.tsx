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
        "overflow-x-auto rounded-md border border-slate-200 bg-slate-950 p-3 text-xs leading-5 text-slate-100",
        className,
      )}
      {...rest}
    >
      {lines.map((line, i) => {
        let tone = "text-slate-300";
        if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) {
          tone = "text-sky-300";
        } else if (line.startsWith("+")) {
          tone = "text-emerald-300";
        } else if (line.startsWith("-")) {
          tone = "text-red-300";
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
