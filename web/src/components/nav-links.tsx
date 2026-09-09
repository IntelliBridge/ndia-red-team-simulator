"use client";

// NavLinks — the header navigation, one mono uppercase link per top-level
// route in the Labs style. Marks the link whose route prefix matches the
// current pathname with aria-current="page", which the stylesheet paints red.

import { usePathname } from "next/navigation";

export interface NavLink {
  href: string;
  label: string;
}

export function NavLinks({ links }: { links: NavLink[] }) {
  const pathname = usePathname() ?? "";
  return (
    <>
      {links.map((link) => {
        const current =
          pathname === link.href || pathname.startsWith(`${link.href}/`);
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
