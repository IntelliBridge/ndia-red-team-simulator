"use client";

// SidebarNav: the left column of the app shell from the md breakpoint up.
// The Agile Defense Labs mark in its head links home, and one link per NAV
// entry follows, the current section marked with aria-current="page".
// Below md the column is not rendered at all. The top bar carries the
// compact nav row there.

import { usePathname } from "next/navigation";

import { isCurrentRoute, NAV } from "@/lib/nav";

const LINK_BASE =
  "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors";
const LINK_CURRENT = "bg-muted text-foreground";
const LINK_REST = "text-muted-foreground hover:bg-muted hover:text-foreground";

export function SidebarNav() {
  const pathname = usePathname() ?? "";
  return (
    <aside className="hidden w-56 shrink-0 flex-col border-r border-border bg-card md:sticky md:top-0 md:flex md:h-screen">
      <div className="flex h-14 shrink-0 items-center border-b border-border px-4">
        <a
          href="/dashboard"
          className="flex h-[26px] items-center"
          data-testid="brand-link"
        >
          {/* The Agile Defense Labs mark, white on navy. Vendored from
              labs.agiledefense.com. */}
          <img
            src="/brand/agile-labs.svg"
            alt="Agile Defense Labs"
            width={56}
            height={26}
            className="h-[26px] w-auto"
          />
        </a>
      </div>
      <nav aria-label="Primary" className="flex-1 overflow-y-auto p-2">
        <ul className="flex flex-col gap-0.5">
          {NAV.map((item) => {
            const current = isCurrentRoute(pathname, item.href);
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <a
                  href={item.href}
                  aria-current={current ? "page" : undefined}
                  className={`${LINK_BASE} ${current ? LINK_CURRENT : LINK_REST}`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  {item.label}
                </a>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}
