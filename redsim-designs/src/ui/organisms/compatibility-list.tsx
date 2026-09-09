import { Check, X } from "lucide-react"

/** Dataset/model compatibility rows on the model detail page. [spec §4] */
export function CompatibilityList({ items }: { items: { label: string; ok: boolean; note?: string }[] }) {
  return (
    <ul className="flex flex-col gap-1.5">
      {items.map((it) => (
        <li key={it.label} className="flex items-center gap-2 text-sm">
          {it.ok ? <Check className="h-4 w-4 text-robust" /> : <X className="h-4 w-4 text-critical" />}
          <span className="text-foreground">{it.label}</span>
          {it.note && <span className="text-xs text-muted">— {it.note}</span>}
        </li>
      ))}
    </ul>
  )
}
