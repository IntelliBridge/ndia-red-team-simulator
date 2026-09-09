"use client"

import { useEffect, useState } from "react"
import { Command, Moon, Sun } from "lucide-react"
import type { Role } from "@/lib/api-types"
import { IS_PROD } from "@/lib/env"
import { useSession } from "@/lib/session"
import { Select } from "@/ui/atoms/select"
import { Button } from "@/ui/atoms/button"

const ROLE_OPTS: { value: Role; label: string }[] = [
  { value: "viewer", label: "viewer" },
  { value: "scanner", label: "scanner" },
  { value: "remediator", label: "remediator" },
  { value: "approver", label: "approver" },
  { value: "admin", label: "admin" },
]

export function TopBar() {
  const { session, signOut, setRole } = useSession()
  const [light, setLight] = useState(false)

  useEffect(() => {
    const isLight = document.documentElement.classList.contains("light")
    setLight(isLight)
  }, [])

  const toggleTheme = () => {
    const next = !light
    setLight(next)
    document.documentElement.classList.toggle("light", next)
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-hairline bg-panel px-4">
      <button
        type="button"
        onClick={() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true }))}
        className="hidden items-center gap-2 rounded-md border border-hairline bg-panel-2 px-2.5 py-1.5 text-xs text-muted hover:text-foreground sm:flex"
      >
        <Command className="h-3.5 w-3.5" /> Go to… <kbd className="font-mono text-[10px]">⌘K</kbd>
      </button>
      <div className="flex items-center gap-3">
        {/* Dev-only role switcher; the real authz boundary is the API. */}
        {session?.dev && !IS_PROD && (
          <label className="flex items-center gap-1.5 text-xs text-muted">
            role
            <Select
              className="h-7 w-32"
              options={ROLE_OPTS}
              value={session.role}
              onChange={(e) => setRole(e.target.value as Role)}
            />
          </label>
        )}
        <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label="Toggle theme">
          {light ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
        </Button>
        {session && (
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-muted">{session.user}</span>
            <Button variant="outline" size="sm" onClick={signOut}>Sign out</Button>
          </div>
        )}
      </div>
    </header>
  )
}
