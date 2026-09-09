"use client"

import type { ReactNode } from "react"
import { usePathname } from "next/navigation"
import { FOOTER_DISCLOSURE } from "@/lib/env"
import { SidebarNav } from "./sidebar-nav"
import { TopBar } from "./top-bar"
import { CommandPalette } from "./command-palette"
import { FixtureRibbon } from "@/ui/molecules/fixture-ribbon"

/** Verbatim footer disclosure on every page. [spec §0, §14.5] */
export function AppFooter() {
  return (
    <footer className="border-t border-hairline bg-panel px-4 py-3">
      <p className="text-center text-[11px] leading-relaxed text-muted">{FOOTER_DISCLOSURE}</p>
    </footer>
  )
}

/**
 * Chrome only. Auth is enforced in middleware and the session is seeded by the
 * RSC layout, so the shell renders immediately with no loading gate.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname()

  if (pathname === "/login") {
    return (
      <div className="flex min-h-screen flex-col">
        <FixtureRibbon />
        <main className="flex-1">{children}</main>
        <AppFooter />
      </div>
    )
  }

  return (
    <div className="flex min-h-screen flex-col">
      <FixtureRibbon />
      <div className="flex min-h-0 flex-1">
        <SidebarNav />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-[1400px] p-6">{children}</div>
          </main>
          <AppFooter />
        </div>
      </div>
      <CommandPalette />
    </div>
  )
}
