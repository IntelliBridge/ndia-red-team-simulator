"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";

import { NAV } from "@/lib/nav";

import { CommandPalette } from "./command-palette";
import { SidebarNav } from "./sidebar-nav";
import { TopBar } from "./top-bar";

const FOOTER_DISCLOSURE =
  "Proof of concept on open, unclassified public data. Results are evidence for human review, not a safety, readiness, or certification determination.";

/** The disclosure that sits under every page. */
export function AppFooter() {
  return (
    <footer className="border-t border-hairline bg-panel px-4 py-3">
      <p className="text-center text-[11px] leading-relaxed text-muted-foreground">
        {FOOTER_DISCLOSURE}
      </p>
    </footer>
  );
}

export interface AppShellProps {
  children: ReactNode;
}

/**
 * Chrome around every page.
 *
 * `/login` gets the bare frame: a sidebar and a sign-out control on the page
 * that signs you in would offer navigation the caller cannot use yet.
 */
export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname() ?? "";

  if (pathname === "/login") {
    return (
      <div className="flex min-h-screen flex-col">
        <main id="main-content" tabIndex={-1} className="flex-1">
          {children}
        </main>
        <AppFooter />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col">
      <div className="flex min-h-0 flex-1">
        <SidebarNav />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <main
            id="main-content"
            tabIndex={-1}
            className="flex-1 overflow-y-auto"
          >
            <div className="mx-auto w-full max-w-[1400px] p-6">{children}</div>
          </main>
          <AppFooter />
        </div>
      </div>
      <CommandPalette links={NAV.map((n) => ({ href: n.href, label: n.label }))} />
    </div>
  );
}
