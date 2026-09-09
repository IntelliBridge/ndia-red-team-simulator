"use client"

import { useEffect, useMemo, useState } from "react"
import { useRouter } from "next/navigation"
import { Search } from "lucide-react"
import { NAV } from "@/lib/nav"
import { cn } from "@/lib/utils"

/** ⌘K palette using the same nav list. [spec §18.1] */
export function CommandPalette() {
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [active, setActive] = useState(0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        setOpen((o) => !o)
      }
      if (e.key === "Escape") setOpen(false)
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  const results = useMemo(
    () => NAV.filter((n) => n.label.toLowerCase().includes(query.toLowerCase())),
    [query],
  )

  useEffect(() => setActive(0), [query, open])

  if (!open) return null

  const go = (href: string) => {
    setOpen(false)
    setQuery("")
    router.push(href)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-[15vh]" onClick={() => setOpen(false)}>
      <div
        role="dialog"
        aria-label="Command palette"
        className="w-full max-w-lg overflow-hidden rounded-lg border border-hairline bg-panel shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-hairline px-3">
          <Search className="h-4 w-4 text-muted" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.nativeEvent.isComposing || e.keyCode === 229) return
              if (e.key === "ArrowDown") setActive((a) => Math.min(a + 1, results.length - 1))
              if (e.key === "ArrowUp") setActive((a) => Math.max(a - 1, 0))
              if (e.key === "Enter" && results[active]) go(results[active].href)
            }}
            placeholder="Go to…"
            className="h-11 w-full bg-transparent text-sm text-foreground outline-none placeholder:text-muted-2"
          />
        </div>
        <ul className="max-h-72 overflow-y-auto p-1.5">
          {results.map((r, i) => {
            const Icon = r.icon
            return (
              <li key={r.href}>
                <button
                  type="button"
                  onMouseEnter={() => setActive(i)}
                  onClick={() => go(r.href)}
                  className={cn(
                    "flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm",
                    i === active ? "bg-panel-2 text-foreground" : "text-muted",
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {r.label}
                </button>
              </li>
            )
          })}
          {results.length === 0 && <li className="px-2.5 py-6 text-center text-sm text-muted">No matches</li>}
        </ul>
      </div>
    </div>
  )
}
