"use client";

// NavLinks — the header navigation, one mono uppercase link per top-level
// route in the Labs style. Marks the link whose route prefix matches the
// current pathname with aria-current="page", which the stylesheet paints red.

import { usePathname } from "next/navigation";

export interface NavLink {
  href: string;
  label: string;
}

/**
 * Routes that render without a credential. Every link in the header leads to
 * a gated page, so on these the nav is only a row of ways back to the login
 * form and the branded sign-in reads cleaner without it.
 */
const PUBLIC_PATHS = new Set(["/login"]);

export function NavLinks({ links }: { links: NavLink[] }) {
  const pathname = usePathname() ?? "";
  if (PUBLIC_PATHS.has(pathname)) return null;
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
