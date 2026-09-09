import { cn } from "@/lib/utils"

export function KeyValueList({
  items,
  className,
  columns = 2,
}: {
  items: { key: string; value: React.ReactNode }[]
  className?: string
  columns?: 1 | 2 | 3
}) {
  const cols = columns === 1 ? "grid-cols-1" : columns === 3 ? "grid-cols-1 sm:grid-cols-3" : "grid-cols-1 sm:grid-cols-2"
  return (
    <dl className={cn("grid gap-x-6 gap-y-2.5", cols, className)}>
      {items.map((it) => (
        <div key={it.key} className="flex flex-col gap-0.5">
          <dt className="text-[11px] uppercase tracking-wide text-muted-2">{it.key}</dt>
          <dd className="break-words font-mono text-xs text-foreground tabular">{it.value}</dd>
        </div>
      ))}
    </dl>
  )
}
