"use client";

// NavLinks — the header navigation, one mono uppercase link per top-level
// route in the Labs style. Marks the link whose route prefix matches the
// current pathname with aria-current="page", which the stylesheet paints red.
// Renders nothing on the login page: a signed-out visitor has nowhere to go.

import { usePathname } from "next/navigation";

import { isCurrentRoute } from "@/lib/nav";

export interface NavLink {
  href: string;
  label: string;
}

export function NavLinks({ links }: { links: NavLink[] }) {
  const pathname = usePathname() ?? "";
  if (pathname === "/login") return null;
  return (
    <>
      {links.map((link) => {
        const current = isCurrentRoute(pathname, link.href);
        return (
          <a
            key={link.href}
            className="redsim-nav-link"
            href={link.href}
            aria-current={current ? "page" : undefined}
          >
            {link.label}
          </a>
        );
      })}
    </>
  );
}
