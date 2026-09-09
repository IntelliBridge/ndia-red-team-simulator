import { cn } from "@/lib/utils"
import { Skeleton } from "@/ui/atoms/skeleton"

/**
 * Shaped loading placeholders. Pure/presentational so they render both inside
 * client pages (SWR `isLoading`) and in route-level `loading.tsx` files.
 */

export function PageHeaderSkeleton() {
  return (
    <div className="mb-5 flex flex-col gap-2">
      <Skeleton className="h-6 w-56" />
      <Skeleton className="h-3.5 w-80" />
    </div>
  )
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div aria-busy className="overflow-hidden rounded-lg border border-hairline">
      <div className="flex gap-4 border-b border-hairline bg-panel-2/50 px-4 py-3">
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={i} className={cn("h-3", i === 0 ? "w-32" : "w-24")} />
        ))}
      </div>
      <div className="divide-y divide-hairline">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="flex items-center gap-4 px-4 py-3.5">
            {Array.from({ length: cols }).map((_, c) => (
              <Skeleton key={c} className={cn("h-3", c === 0 ? "w-40" : "w-20")} />
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

export function CardsSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div aria-busy className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="flex flex-col gap-3 rounded-lg border border-hairline bg-panel p-4">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-3 w-20" />
          <Skeleton className="h-3 w-40" />
        </div>
      ))}
    </div>
  )
}

function PanelSkeleton({ lines = 4 }: { lines?: number }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-hairline bg-panel p-4">
      <Skeleton className="h-3.5 w-28" />
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn("h-3", i === lines - 1 ? "w-2/3" : "w-full")} />
      ))}
    </div>
  )
}

export function DetailSkeleton() {
  return (
    <div aria-busy className="flex flex-col gap-5">
      <div className="flex flex-col gap-2">
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-3.5 w-44" />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <PanelSkeleton lines={5} />
        <PanelSkeleton lines={5} />
      </div>
      <PanelSkeleton lines={6} />
    </div>
  )
}
