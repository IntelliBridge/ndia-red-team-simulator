import { cn } from "@/lib/utils"

/** Atomic shimmer block. No hooks, so it also renders in server loading.tsx files. */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-md bg-panel-2", className)} />
}
