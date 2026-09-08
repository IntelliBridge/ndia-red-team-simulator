// Skeleton — shadcn/ui skeleton primitive (new-york-v4).
//
// Ported from the vendored shadcn registry; the `cn` import path is
// adapted and an explicit `React` import is added (the upstream source
// relies on a global React type that this workspace does not provide).
// Dependency-free leaf: a single animated div + cn().

import * as React from "react";

import { cn } from "../lib/utils";

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn("animate-pulse rounded-md bg-accent", className)}
      {...props}
    />
  );
}

export { Skeleton };
