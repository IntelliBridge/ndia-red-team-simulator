// AppShell: the chrome around every page. Skip link first, then the sidebar
// beside a column of top bar, main and footer, and the command palette
// mounted once at the end. Server-rendered; the sidebar and top bar are the
// client islands that read the pathname.

import type { ReactNode } from "react";

import { NAV_LINKS } from "@/lib/nav";

import { CommandPalette } from "./command-palette";
import { SidebarNav } from "./sidebar-nav";
import { TopBar } from "./top-bar";

/** The standing caveat, verbatim on every page. */
export function AppFooter() {
  return (
    <footer className="border-t border-border bg-card px-6 py-4 text-[11px] leading-relaxed text-muted-foreground">
      <div className="redsim-meta mb-1">
        REDSIM // ADVERSARIAL ML RED-TEAM SIMULATOR
      </div>
      Proof of concept on open, unclassified public data. Results are evidence
      for human review, not a safety, readiness, or certification
      determination.
    </footer>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      {/* Skip link: first focusable element, visually hidden until
          keyboard-focused, so keyboard/screen-reader users can jump past the
          nav straight to the page content. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
      >
        Skip to content
      </a>
      <div className="flex min-h-0 flex-1">
        <SidebarNav />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <main id="main-content" tabIndex={-1} className="flex-1">
            <div className="mx-auto w-full max-w-[1400px] p-6">{children}</div>
          </main>
          <AppFooter />
        </div>
      </div>
      <CommandPalette links={NAV_LINKS} />
    </div>
  );
}
