import Link from "next/link"
import { cn } from "@/lib/utils"

export interface Column<T> {
  key: string
  header: string
  render: (row: T) => React.ReactNode
  className?: string
}

/** Lightweight semantic table used by list routes. [spec §4] */
export function DataTable<T>({
  columns,
  rows,
  rowHref,
  getRowKey,
  caption,
}: {
  columns: Column<T>[]
  rows: T[]
  rowHref?: (row: T) => string
  getRowKey: (row: T) => string
  caption?: string
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-hairline">
      <table className="w-full border-collapse text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-hairline bg-panel-2">
            {columns.map((c) => (
              <th key={c.key} scope="col" className={cn("px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wide text-muted", c.className)}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const href = rowHref?.(row)
            const content = columns.map((c) => (
              <td key={c.key} className={cn("px-3 py-2.5 align-middle text-foreground", c.className)}>
                {href && c.key === columns[0].key ? (
                  <Link href={href} className="text-primary hover:underline">
                    {c.render(row)}
                  </Link>
                ) : (
                  c.render(row)
                )}
              </td>
            ))
            return (
              <tr key={getRowKey(row)} className="border-b border-hairline last:border-0 hover:bg-panel-2/60">
                {content}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
