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
        "overflow-x-auto rounded-md border border-hairline bg-base p-3 text-xs leading-5 text-foreground",
        className,
      )}
      {...rest}
    >
      {lines.map((line, i) => {
        let tone = "text-muted-foreground";
        if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) {
          tone = "text-inferred";
        } else if (line.startsWith("+")) {
          tone = "text-robust";
        } else if (line.startsWith("-")) {
          tone = "text-critical";
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
