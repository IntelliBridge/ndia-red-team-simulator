"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@redsim/design-system";

import { NAV } from "@/lib/nav";

/**
 * The primary sidebar.
 *
 * Hidden below the `md` breakpoint, where the command palette is the way
 * around. `aria-current="page"` rather than colour alone marks the active
 * entry, so the state survives without sight of the highlight.
 */
export function SidebarNav() {
  const pathname = usePathname() ?? "";
  return (
    <aside className="hidden w-56 shrink-0 flex-col border-r border-hairline bg-panel md:flex">
      <div className="flex h-14 items-center gap-2 border-b border-hairline px-4">
        <div className="flex h-6 w-6 items-center justify-center rounded bg-primary text-primary-fg">
          <span className="text-[11px] font-bold">rs</span>
        </div>
        <span className="text-sm font-semibold leading-tight text-foreground">
          redsim
        </span>
      </div>
      <nav aria-label="Primary" className="flex-1 overflow-y-auto p-2">
        <ul className="flex flex-col gap-0.5">
          {NAV.map((item) => {
            const active =
              pathname === item.href || pathname.startsWith(item.href + "/");
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                    active
                      ? "bg-panel-2 text-foreground"
                      : "text-muted-foreground hover:bg-panel-2 hover:text-foreground",
                  )}
                >
                  <Icon className="h-4 w-4" aria-hidden />
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}
